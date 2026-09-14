"""
Milestone 4 — Task 1: Backfill Priority Migration Script

Backfills deterministic priority (P1-P4) for existing incidents in the MongoDB
`incidents` collection where priority is currently None or missing.
Preserves existing non-empty priority values.
"""

from backend.app.core.database import get_database
from backend.app.schemas.incident import map_risk_level_to_priority

def run_migration():
    db = get_database()
    coll = db["incidents"]
    docs = list(coll.find({"priority": None}))
    print(f"Found {len(docs)} incidents with priority=None")
    
    updated = 0
    for d in docs:
        rl = d.get("risk_level")
        prio = map_risk_level_to_priority(rl)
        if prio:
            res = coll.update_one({"_id": d["_id"]}, {"$set": {"priority": prio}})
            updated += res.modified_count
            
    print(f"Successfully updated priority for {updated} incidents in MongoDB.")
    
    print("\nSample updated incidents:")
    for d in coll.find({}, {"_id": 0, "incident_id": 1, "risk_score": 1, "risk_level": 1, "priority": 1}).limit(6):
        print(f"  Incident {d['incident_id']}: Risk={d['risk_score']} ({d['risk_level']}) -> Priority={d['priority']}")

if __name__ == "__main__":
    run_migration()
