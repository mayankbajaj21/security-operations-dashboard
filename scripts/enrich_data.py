"""
Data Normalization and Threat Intelligence Enrichment Pipeline Script
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

This script reads cleaned datasets from data/processed/, executes Left Outer Joins
to enrich security events with asset metadata, CVE vulnerabilities, IoC threat intel,
MITRE ATT&CK mappings, and historical incidents, adhering strictly to the canonical
schema defined in documentation/data_dictionary.md.

Cleaned input datasets and raw files are left untouched.
Output is exported to data/processed/enriched_security_events.csv.
"""

from pathlib import Path
import sys
import pandas as pd


# Define project root directory
BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"

OUTPUT_FILE = PROCESSED_DIR / "enriched_security_events.csv"


def load_cleaned_datasets() -> dict[str, pd.DataFrame]:
    """
    Loads all six cleaned CSV datasets from data/processed/.
    Raises FileNotFoundError if any required file is missing.
    """
    filenames = [
        "cleaned_security_events.csv",
        "cleaned_threat_intelligence.csv",
        "cleaned_vulnerabilities.csv",
        "cleaned_mitre_attack_mapping.csv",
        "cleaned_incident_history.csv",
        "cleaned_assets.csv"
    ]
    
    datasets = {}
    for filename in filenames:
        filepath = PROCESSED_DIR / filename
        if not filepath.exists():
            raise FileNotFoundError(
                f"Missing required cleaned dataset: {filepath}. "
                "Please run scripts/clean_data.py first."
            )
        datasets[filename] = pd.read_csv(filepath)
        
    return datasets


def validate_reference_key_uniqueness(df: pd.DataFrame, key_col: str, dataset_name: str) -> None:
    """
    Validates that a reference dataset's join key is unique where uniqueness is expected.
    Raises ValueError if duplicate join keys are found.
    """
    if df[key_col].duplicated().any():
        dupes = df[df[key_col].duplicated()][key_col].unique().tolist()
        raise ValueError(
            f"Reference key uniqueness validation failed for '{dataset_name}'. "
            f"Column '{key_col}' contains duplicate keys: {dupes}"
        )


def enrich_security_events(datasets: dict[str, pd.DataFrame]) -> tuple[pd.DataFrame, dict]:
    """
    Executes relational enrichment joins on cleaned_security_events.csv:
    1. Reference Key Uniqueness Validation
    2. Asset Enrichment (Left Join on asset_name)
    3. Vulnerability Enrichment (Left Join security_events.vulnerability_id == vulnerabilities.cve_id)
    4. Threat Intelligence Enrichment (Scalable lookup matching source_ip / destination_ip)
    5. MITRE ATT&CK Enrichment (Left Join on event_type)
    6. Incident History Enrichment (Left Join on event_id)
    
    Returns (enriched_df, metrics_dict).
    """
    events_df = datasets["cleaned_security_events.csv"].copy()
    threat_df = datasets["cleaned_threat_intelligence.csv"].copy()
    vuln_df = datasets["cleaned_vulnerabilities.csv"].copy()
    mitre_df = datasets["cleaned_mitre_attack_mapping.csv"].copy()
    incident_df = datasets["cleaned_incident_history.csv"].copy()
    assets_df = datasets["cleaned_assets.csv"].copy()
    
    source_count = len(events_df)
    
    # 0. REFERENCE KEY UNIQUENESS VALIDATION
    validate_reference_key_uniqueness(assets_df, "asset_name", "cleaned_assets.csv")
    validate_reference_key_uniqueness(vuln_df, "cve_id", "cleaned_vulnerabilities.csv")
    validate_reference_key_uniqueness(mitre_df, "event_type", "cleaned_mitre_attack_mapping.csv")
    validate_reference_key_uniqueness(incident_df, "event_id", "cleaned_incident_history.csv")
    validate_reference_key_uniqueness(threat_df, "indicator_value", "cleaned_threat_intelligence.csv")

    # Rename ambiguous fields in base security_events dataframe
    events_df = events_df.rename(columns={
        "severity": "event_severity",
        "cvss_score": "raw_cvss_score"
    })
    
    # 1. ASSET ENRICHMENT
    # Join: security_events.asset_name -> assets.asset_name
    assets_subset = assets_df[[
        "asset_name", "asset_id", "asset_type", "owner", "department", "criticality", "operating_system"
    ]].rename(columns={
        "owner": "asset_owner",
        "department": "asset_department",
        "criticality": "asset_criticality",
        "operating_system": "asset_operating_system"
    })
    
    enriched = events_df.merge(assets_subset, on="asset_name", how="left")
    
    # Asset match metrics calculation
    asset_matched_events = int(enriched["asset_id"].notnull().sum())
    asset_unmatched_events = int(enriched["asset_id"].isnull().sum())
    
    unique_event_assets = int(events_df["asset_name"].nunique())
    unique_assets_enriched = int(enriched[enriched["asset_id"].notnull()]["asset_name"].nunique())
    unique_assets_unmatched = int(enriched[enriched["asset_id"].isnull()]["asset_name"].nunique())
    
    # 2. VULNERABILITY ENRICHMENT
    # Join: security_events.vulnerability_id -> vulnerabilities.cve_id
    vuln_subset = vuln_df[[
        "cve_id", "vulnerability_id", "vulnerability_name", "severity", "cvss_score",
        "patch_available", "status"
    ]].rename(columns={
        "vulnerability_id": "vulnerability_record_id",
        "severity": "vulnerability_severity",
        "cvss_score": "vulnerability_cvss_score",
        "status": "vulnerability_status"
    })
    
    enriched = enriched.merge(
        vuln_subset,
        left_on="vulnerability_id",
        right_on="cve_id",
        how="left",
        suffixes=("", "_vuln")
    )
    
    if "cve_id_vuln" in enriched.columns:
        enriched = enriched.drop(columns=["cve_id_vuln"])
        
    vuln_matches = int(enriched["vulnerability_record_id"].notnull().sum())
    events_without_vuln_id = int(events_df["vulnerability_id"].isnull().sum())

    # 3. THREAT INTELLIGENCE ENRICHMENT (Scalable Lookup Implementation)
    # Filter IP indicators and construct lookup table
    ip_threats = threat_df[threat_df["indicator_type"].str.lower() == "ip address"]
    ioc_lookup = ip_threats.set_index("indicator_value").to_dict(orient="index")
    
    def resolve_threat_intel(row):
        src = row.get("source_ip")
        dst = row.get("destination_ip")
        
        # Check source_ip first, then destination_ip
        match_ioc = ioc_lookup.get(src) or ioc_lookup.get(dst)
        if match_ioc:
            return pd.Series({
                "threat_intel_match": True,
                "threat_intel_indicator_id": match_ioc.get("indicator_id"),
                "threat_name": match_ioc.get("threat_name"),
                "threat_actor": match_ioc.get("threat_actor"),
                "threat_confidence": match_ioc.get("confidence"),
                "threat_intel_severity": match_ioc.get("severity")
            })
        else:
            return pd.Series({
                "threat_intel_match": False,
                "threat_intel_indicator_id": None,
                "threat_name": None,
                "threat_actor": None,
                "threat_confidence": None,
                "threat_intel_severity": None
            })
            
    threat_intel_fields = enriched.apply(resolve_threat_intel, axis=1)
    enriched = pd.concat([enriched, threat_intel_fields], axis=1)
    threat_matches = int(enriched["threat_intel_match"].sum())

    # 4. MITRE ATT&CK ENRICHMENT
    # Join: security_events.event_type -> mitre_attack_mapping.event_type
    mitre_subset = mitre_df[["event_type", "mitre_id", "technique_name", "tactic"]]
    enriched = enriched.merge(mitre_subset, on="event_type", how="left")
    
    enriched["mitre_mapping_status"] = enriched["mitre_id"].notnull().map({True: "Mapped", False: "Unmapped"})
    
    mitre_mapped_count = int((enriched["mitre_mapping_status"] == "Mapped").sum())
    mitre_unmapped_count = int((enriched["mitre_mapping_status"] == "Unmapped").sum())

    # 5. INCIDENT HISTORY ENRICHMENT
    # Join: security_events.event_id -> incident_history.event_id
    incident_subset = incident_df[[
        "event_id", "incident_id", "incident_type", "assigned_to", "status", "response_time", "response_time_minutes", "resolution"
    ]].rename(columns={
        "status": "incident_status"
    })
    
    enriched = enriched.merge(incident_subset, on="event_id", how="left")
    incident_matches = int(enriched["incident_id"].notnull().sum())

    # 6. TRACEABILITY & METADATA
    enriched["data_source"] = "security_events.csv"

    # DATA INTEGRITY CHECKS
    final_count = len(enriched)
    if final_count != source_count:
        raise ValueError(
            f"Data integrity failure: Enriched row count ({final_count}) "
            f"does not match source event count ({source_count}). "
            "Row multiplication occurred during enrichment joins."
        )
        
    if enriched["event_id"].nunique() != source_count:
        raise ValueError(
            "Data integrity failure: event_id is no longer unique after enrichment."
        )

    metrics = {
        "source_event_count": source_count,
        "final_enriched_count": final_count,
        "asset_matched_events": asset_matched_events,
        "asset_unmatched_events": asset_unmatched_events,
        "unique_event_assets": unique_event_assets,
        "unique_assets_enriched": unique_assets_enriched,
        "unique_assets_unmatched": unique_assets_unmatched,
        "vulnerability_matches": vuln_matches,
        "threat_intel_matches": threat_matches,
        "mitre_mapped_events": mitre_mapped_count,
        "mitre_unmapped_events": mitre_unmapped_count,
        "incident_matches": incident_matches,
        "events_without_vuln_ids": events_without_vuln_id
    }
    
    return enriched, metrics


def main():
    """Main execution entry point for data enrichment."""
    print("=" * 70)
    print("      DATA NORMALIZATION & ENRICHMENT PIPELINE (MILESTONE 1)")
    print("=" * 70)
    
    cleaned_datasets = load_cleaned_datasets()
    print("[+] Loaded 6 cleaned datasets from data/processed/")
    
    enriched_df, metrics = enrich_security_events(cleaned_datasets)
    print("[+] Completed relational joins & canonical schema mapping")
    
    enriched_df.to_csv(OUTPUT_FILE, index=False)
    print(f"[+] Saved enriched dataset to: {OUTPUT_FILE.relative_to(BASE_DIR)}")
    
    print("\n" + "=" * 70)
    print("                    ENRICHMENT REPORT SUMMARY")
    print("=" * 70)
    print(f"  - Source Event Count:            {metrics['source_event_count']}")
    print(f"  - Final Enriched Event Count:    {metrics['final_enriched_count']}")
    print("  --- ASSET METRICS ---")
    print(f"  - Asset Matched Events:          {metrics['asset_matched_events']}")
    print(f"  - Asset Unmatched Events:        {metrics['asset_unmatched_events']}")
    print(f"  - Unique Event Asset Names:      {metrics['unique_event_assets']}")
    print(f"  - Unique Assets Enriched:        {metrics['unique_assets_enriched']}")
    print(f"  - Unique Assets Unmatched:       {metrics['unique_assets_unmatched']}")
    print("  --- OTHER ENRICHMENT METRICS ---")
    print(f"  - Vulnerability Matches:         {metrics['vulnerability_matches']}")
    print(f"  - Events Without Vuln IDs:       {metrics['events_without_vuln_ids']}")
    print(f"  - Threat Intelligence Matches:   {metrics['threat_intel_matches']}")
    print(f"  - MITRE Mapped Events:           {metrics['mitre_mapped_events']}")
    print(f"  - MITRE Unmapped Events:         {metrics['mitre_unmapped_events']}")
    print(f"  - Incident History Matches:      {metrics['incident_matches']}")
    print("=" * 70)
    print("Enrichment completed successfully.")


if __name__ == "__main__":
    main()
