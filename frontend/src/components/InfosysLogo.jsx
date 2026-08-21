import React from 'react';
import infosysLogo from '../assets/infosys-logo.png';

/**
 * Authoritative Infosys Brand Logo Component
 * Renders the exact uploaded official Infosys logo image asset without modifications.
 */
const InfosysLogo = ({ height = 28, className = '', style = {} }) => {
  return (
    <img
      src={infosysLogo}
      alt="Infosys"
      className={className}
      style={{
        height: typeof height === 'number' ? `${height}px` : height,
        width: 'auto',
        display: 'inline-block',
        verticalAlign: 'middle',
        ...style
      }}
    />
  );
};

export default InfosysLogo;
