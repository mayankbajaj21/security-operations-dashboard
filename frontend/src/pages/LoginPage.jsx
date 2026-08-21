import React from 'react';
import LandingPage from './LandingPage';

/**
 * LoginPage Component Wrapper
 * Delegates directly to the single canonical LandingPage component in 'signin' mode
 * to eliminate duplicate sign-in screens and ensure a single authentication entry point.
 */
const LoginPage = ({ onLoginSuccess, onBackToLanding, theme, onToggleTheme }) => {
  return (
    <LandingPage
      initialMode="signin"
      onLoginSuccess={onLoginSuccess}
      onEnterSOC={onBackToLanding}
      theme={theme}
      onToggleTheme={onToggleTheme}
    />
  );
};

export default LoginPage;
