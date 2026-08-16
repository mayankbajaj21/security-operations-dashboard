import React, { useState, useMemo } from 'react';
import { 
  Shield, 
  Mail, 
  Lock, 
  Eye, 
  EyeOff, 
  User, 
  Check, 
  X, 
  AlertCircle, 
  Info 
} from 'lucide-react';

// Demo-only client-side authentication.
// Production authentication should use secure backend authentication,
// password hashing, sessions/JWT, and OAuth provider integration.

const DEMO_USERS_KEY = 'soc_demo_users';
const DEFAULT_DEMO_USER = {
  name: 'SOC Analyst',
  email: 'analyst@soc.internal',
  password: 'Password123!'
};

/**
 * Retrieve demo users database from localStorage
 */
const getDemoUsers = () => {
  try {
    const raw = localStorage.getItem(DEMO_USERS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch (e) {
    console.error('Failed to read demo users:', e);
  }
  // Initialize with default demo user
  const initial = [DEFAULT_DEMO_USER];
  try {
    localStorage.setItem(DEMO_USERS_KEY, JSON.stringify(initial));
  } catch (e) {}
  return initial;
};

/**
 * Google Icon SVG Component
 */
const GoogleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" style={{ marginRight: '0.5rem' }}>
    <path
      fill="#4285F4"
      d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
    />
    <path
      fill="#34A853"
      d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.27v3.15C3.25 21.3 7.31 24 12 24z"
    />
    <path
      fill="#FBBC05"
      d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.27C.46 8.2 0 10.04 0 12s.46 3.8 1.27 5.42l4.01-3.15z"
    />
    <path
      fill="#EA4335"
      d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.25 2.7 1.27 6.58l4.01 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
    />
  </svg>
);

const LoginPage = ({ onLoginSuccess }) => {
  const [isSignUp, setIsSignUp] = useState(false);

  // Form Fields
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);

  // Password Visibility
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // UI Notices & Validation
  const [errorMessage, setErrorMessage] = useState('');
  const [infoNotice, setInfoNotice] = useState('');

  // Password Strength Evaluation
  const passwordRequirements = useMemo(() => {
    return {
      minLength: password.length >= 8,
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecial: /[^A-Za-z0-9]/.test(password)
    };
  }, [password]);

  const strengthScore = useMemo(() => {
    return Object.values(passwordRequirements).filter(Boolean).length;
  }, [passwordRequirements]);

  const strengthLabel = useMemo(() => {
    if (!password) return '';
    if (strengthScore <= 1) return 'Weak';
    if (strengthScore <= 3) return 'Fair';
    if (strengthScore === 4) return 'Good';
    return 'Strong';
  }, [password, strengthScore]);

  const strengthColor = useMemo(() => {
    if (strengthScore <= 1) return 'var(--color-critical)';
    if (strengthScore <= 3) return 'var(--color-high)';
    if (strengthScore === 4) return 'var(--color-warning)';
    return 'var(--color-accent)';
  }, [strengthScore]);

  const toggleMode = () => {
    setIsSignUp(!isSignUp);
    setErrorMessage('');
    setInfoNotice('');
    setPassword('');
    setConfirmPassword('');
  };

  const handleGoogleClick = () => {
    setInfoNotice('Google sign-in will be available when OAuth is configured.');
    setErrorMessage('');
  };

  const handleForgotPassword = (e) => {
    e.preventDefault();
    setInfoNotice('Password reset is not configured in demo mode. Use the default password: Password123!');
    setErrorMessage('');
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setErrorMessage('');
    setInfoNotice('');

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (isSignUp) {
      // Sign-Up Validation
      if (!fullName.trim()) {
        setErrorMessage('Full Name is required.');
        return;
      }
      if (!email.trim() || !emailRegex.test(email.trim())) {
        setErrorMessage('Please enter a valid email address.');
        return;
      }
      if (strengthScore < 5) {
        setErrorMessage('Password must satisfy all 5 security requirements.');
        return;
      }
      if (password !== confirmPassword) {
        setErrorMessage('Passwords do not match.');
        return;
      }

      // Check if user exists
      const users = getDemoUsers();
      const existing = users.find((u) => u.email.toLowerCase() === email.trim().toLowerCase());
      if (existing) {
        setErrorMessage('An account with this email address already exists.');
        return;
      }

      // Save Demo User
      const newUser = {
        name: fullName.trim(),
        email: email.trim().toLowerCase(),
        password: password
      };

      try {
        const updatedUsers = [...users, newUser];
        localStorage.setItem(DEMO_USERS_KEY, JSON.stringify(updatedUsers));
      } catch (err) {
        console.error('Failed to save demo user:', err);
      }

      // Automatically log in newly registered user
      onLoginSuccess(newUser, rememberMe);
    } else {
      // Sign-In Validation
      if (!email.trim() || !emailRegex.test(email.trim())) {
        setErrorMessage('Please enter a valid email address.');
        return;
      }
      if (!password) {
        setErrorMessage('Password is required.');
        return;
      }

      const users = getDemoUsers();
      const matched = users.find(
        (u) => u.email.toLowerCase() === email.trim().toLowerCase() && u.password === password
      );

      if (!matched) {
        setErrorMessage('Invalid email or password.');
        return;
      }

      // Successful Sign-In
      onLoginSuccess(matched, rememberMe);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card} className="panel">
        {/* Header & Logo */}
        <div style={styles.brandHeader}>
          <div style={styles.logoBadge}>
            <Shield size={24} color="var(--color-accent)" />
          </div>
          <h2 style={styles.brandTitle}>
            {isSignUp ? 'Create your account' : 'Welcome back'}
          </h2>
          <p style={styles.brandSubtitle}>
            {isSignUp
              ? 'Set up your SOC analyst account.'
              : 'Sign in to access your security operations dashboard.'}
          </p>
        </div>

        {/* Dynamic Alerts */}
        {errorMessage && (
          <div style={styles.errorAlert}>
            <AlertCircle size={15} color="var(--color-critical)" />
            <span>{errorMessage}</span>
          </div>
        )}

        {infoNotice && (
          <div style={styles.infoAlert}>
            <Info size={15} color="var(--color-accent)" />
            <span>{infoNotice}</span>
          </div>
        )}

        {/* Auth Form */}
        <form onSubmit={handleSubmit} style={styles.form}>
          {/* Full Name (Sign Up only) */}
          {isSignUp && (
            <div style={styles.fieldGroup}>
              <label style={styles.fieldLabel}>Full Name</label>
              <div style={styles.inputWrapper}>
                <User size={15} color="var(--text-muted)" style={styles.leftIcon} />
                <input
                  type="text"
                  placeholder="Enter your full name"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  style={styles.input}
                />
              </div>
            </div>
          )}

          {/* Email Address */}
          <div style={styles.fieldGroup}>
            <label style={styles.fieldLabel}>Email Address</label>
            <div style={styles.inputWrapper}>
              <Mail size={15} color="var(--text-muted)" style={styles.leftIcon} />
              <input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={styles.input}
              />
            </div>
          </div>

          {/* Password */}
          <div style={styles.fieldGroup}>
            <label style={styles.fieldLabel}>
              {isSignUp ? 'Create Password' : 'Password'}
            </label>
            <div style={styles.inputWrapper}>
              <Lock size={15} color="var(--text-muted)" style={styles.leftIcon} />
              <input
                type={showPassword ? 'text' : 'password'}
                placeholder={isSignUp ? 'Create a password' : 'Enter your password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={styles.input}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={styles.eyeBtn}
                tabIndex="-1"
              >
                {showPassword ? (
                  <EyeOff size={15} color="var(--text-muted)" />
                ) : (
                  <Eye size={15} color="var(--text-muted)" />
                )}
              </button>
            </div>
          </div>

          {/* Password Strength Indicator (Sign Up only) */}
          {isSignUp && password.length > 0 && (
            <div style={styles.strengthBox}>
              <div style={styles.strengthHeader}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Password Strength</span>
                <span style={{ fontSize: '0.72rem', fontWeight: '700', color: strengthColor }}>
                  {strengthLabel}
                </span>
              </div>
              <div style={styles.progressBarTrack}>
                <div
                  style={{
                    ...styles.progressBarFill,
                    width: `${(strengthScore / 5) * 100}%`,
                    backgroundColor: strengthColor
                  }}
                />
              </div>
              <div style={styles.checklist}>
                <div style={styles.checkItem}>
                  {passwordRequirements.minLength ? (
                    <Check size={12} color="var(--color-accent)" />
                  ) : (
                    <X size={12} color="var(--text-muted)" />
                  )}
                  <span style={{ color: passwordRequirements.minLength ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    At least 8 characters
                  </span>
                </div>
                <div style={styles.checkItem}>
                  {passwordRequirements.hasUpper ? (
                    <Check size={12} color="var(--color-accent)" />
                  ) : (
                    <X size={12} color="var(--text-muted)" />
                  )}
                  <span style={{ color: passwordRequirements.hasUpper ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    Uppercase letter
                  </span>
                </div>
                <div style={styles.checkItem}>
                  {passwordRequirements.hasLower ? (
                    <Check size={12} color="var(--color-accent)" />
                  ) : (
                    <X size={12} color="var(--text-muted)" />
                  )}
                  <span style={{ color: passwordRequirements.hasLower ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    Lowercase letter
                  </span>
                </div>
                <div style={styles.checkItem}>
                  {passwordRequirements.hasNumber ? (
                    <Check size={12} color="var(--color-accent)" />
                  ) : (
                    <X size={12} color="var(--text-muted)" />
                  )}
                  <span style={{ color: passwordRequirements.hasNumber ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    Number
                  </span>
                </div>
                <div style={styles.checkItem}>
                  {passwordRequirements.hasSpecial ? (
                    <Check size={12} color="var(--color-accent)" />
                  ) : (
                    <X size={12} color="var(--text-muted)" />
                  )}
                  <span style={{ color: passwordRequirements.hasSpecial ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    Special character
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Confirm Password (Sign Up only) */}
          {isSignUp && (
            <div style={styles.fieldGroup}>
              <label style={styles.fieldLabel}>Confirm Password</label>
              <div style={styles.inputWrapper}>
                <Lock size={15} color="var(--text-muted)" style={styles.leftIcon} />
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  style={styles.input}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  style={styles.eyeBtn}
                  tabIndex="-1"
                >
                  {showConfirmPassword ? (
                    <EyeOff size={15} color="var(--text-muted)" />
                  ) : (
                    <Eye size={15} color="var(--text-muted)" />
                  )}
                </button>
              </div>
            </div>
          )}

          {/* Remember me & Forgot Password (Sign In only) */}
          {!isSignUp && (
            <div style={styles.rememberRow}>
              <label style={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  style={styles.checkbox}
                />
                <span>Remember me</span>
              </label>
              <a href="#forgot" onClick={handleForgotPassword} style={styles.forgotLink}>
                Forgot password?
              </a>
            </div>
          )}

          {/* Primary Submit Button */}
          <button type="submit" className="soc-button" style={styles.submitButton}>
            {isSignUp ? 'Create Account' : 'Sign In'}
          </button>
        </form>

        {/* OR Divider */}
        <div style={styles.dividerRow}>
          <div style={styles.dividerLine} />
          <span style={styles.dividerText}>OR</span>
          <div style={styles.dividerLine} />
        </div>

        {/* Google OAuth Button */}
        <button
          type="button"
          onClick={handleGoogleClick}
          style={styles.googleButton}
        >
          <GoogleIcon />
          <span>{isSignUp ? 'Sign up with Google' : 'Continue with Google'}</span>
        </button>

        {/* Toggle Mode Footer */}
        <div style={styles.toggleFooter}>
          <span style={{ color: 'var(--text-secondary)' }}>
            {isSignUp ? 'Already have an account?' : "Don't have an account?"}
          </span>
          <button type="button" onClick={toggleMode} style={styles.toggleBtn}>
            {isSignUp ? 'Sign In' : 'Sign Up'}
          </button>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '100vh',
    width: '100vw',
    backgroundColor: 'var(--bg-primary)',
    backgroundImage: 'radial-gradient(circle at 50% 25%, rgba(6, 182, 212, 0.04) 0%, transparent 65%)',
    padding: '1.25rem',
    boxSizing: 'border-box'
  },
  card: {
    width: '100%',
    maxWidth: '440px',
    padding: '2rem 2.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.35)'
  },
  brandHeader: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    textAlign: 'center'
  },
  logoBadge: {
    width: '48px',
    height: '48px',
    borderRadius: '10px',
    backgroundColor: 'rgba(6, 182, 212, 0.1)',
    border: '1px solid rgba(6, 182, 212, 0.2)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: '0.85rem'
  },
  brandTitle: {
    fontSize: '1.25rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0
  },
  brandSubtitle: {
    fontSize: '0.78rem',
    color: 'var(--text-secondary)',
    marginTop: '0.25rem'
  },
  errorAlert: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.6rem 0.8rem',
    backgroundColor: 'rgba(244, 63, 94, 0.08)',
    border: '1px solid var(--color-critical)',
    borderRadius: '4px',
    color: 'var(--color-critical)',
    fontSize: '0.76rem'
  },
  infoAlert: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.6rem 0.8rem',
    backgroundColor: 'rgba(6, 182, 212, 0.08)',
    border: '1px solid var(--color-accent)',
    borderRadius: '4px',
    color: 'var(--color-accent)',
    fontSize: '0.76rem'
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  fieldGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem'
  },
  fieldLabel: {
    fontSize: '0.74rem',
    fontWeight: '600',
    color: 'var(--text-secondary)'
  },
  inputWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  leftIcon: {
    position: 'absolute',
    left: '0.75rem',
    pointerEvents: 'none'
  },
  eyeBtn: {
    position: 'absolute',
    right: '0.65rem',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    padding: 0
  },
  input: {
    width: '100%',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    color: 'var(--text-primary)',
    padding: '0.6rem 2.25rem 0.6rem 2.35rem',
    fontSize: '0.82rem',
    outline: 'none',
    boxSizing: 'border-box'
  },
  strengthBox: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.4rem',
    padding: '0.6rem 0.75rem',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    marginTop: '-0.3rem'
  },
  strengthHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  progressBarTrack: {
    height: '4px',
    width: '100%',
    backgroundColor: 'rgba(255,255,255,0.08)',
    borderRadius: '2px',
    overflow: 'hidden'
  },
  progressBarFill: {
    height: '100%',
    transition: 'all 0.2s ease'
  },
  checklist: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '0.25rem 0.5rem',
    marginTop: '0.25rem'
  },
  checkItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.3rem',
    fontSize: '0.68rem'
  },
  rememberRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: '0.75rem'
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    color: 'var(--text-secondary)',
    cursor: 'pointer'
  },
  checkbox: {
    accentColor: 'var(--color-accent)',
    cursor: 'pointer'
  },
  forgotLink: {
    color: 'var(--color-accent)',
    textDecoration: 'none',
    fontWeight: '500'
  },
  submitButton: {
    width: '100%',
    padding: '0.7rem',
    fontSize: '0.85rem',
    fontWeight: '600',
    justifyContent: 'center',
    marginTop: '0.25rem'
  },
  dividerRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem'
  },
  dividerLine: {
    flex: 1,
    height: '1px',
    backgroundColor: 'var(--border-color)'
  },
  dividerText: {
    fontSize: '0.68rem',
    fontWeight: '600',
    color: 'var(--text-muted)'
  },
  googleButton: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '0.65rem',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    color: 'var(--text-primary)',
    fontSize: '0.82rem',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'all 0.15s ease'
  },
  toggleFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.4rem',
    fontSize: '0.78rem',
    borderTop: '1px solid var(--border-color)',
    paddingTop: '1rem',
    marginTop: '0.25rem'
  },
  toggleBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--color-accent)',
    fontWeight: '600',
    cursor: 'pointer',
    padding: 0,
    fontSize: '0.78rem'
  }
};

export default LoginPage;
