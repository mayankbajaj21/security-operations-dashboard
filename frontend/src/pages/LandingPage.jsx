import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  ArrowRight,
  Sun,
  Moon,
  Mail,
  Lock,
  Eye,
  EyeOff,
  User,
  Check,
  X,
  AlertCircle,
  Info,
  ArrowLeft,
  Shield,
  Activity,
  Cpu
} from 'lucide-react';
import InfosysLogo from '../components/InfosysLogo';

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
  const initial = [DEFAULT_DEMO_USER];
  try {
    localStorage.setItem(DEMO_USERS_KEY, JSON.stringify(initial));
  } catch (e) { }
  return initial;
};

/**
 * Dynamic Animated Cyber Particle Canvas Background
 */
const BackgroundParticles = ({ theme }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;

    const isDark = theme === 'dark';
    const particleColor = isDark ? 'rgba(6, 182, 212, 0.4)' : 'rgba(2, 132, 199, 0.35)';
    const lineColor = isDark ? 'rgba(6, 182, 212, 0.08)' : 'rgba(2, 132, 199, 0.06)';

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const particles = Array.from({ length: 45 }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6,
      radius: Math.random() * 2 + 1
    }));

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 130) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = lineColor;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = particleColor;
        ctx.fill();
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [theme]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0
      }}
    />
  );
};

/**
 * 3D Rotating Cyber Wireframe Digital Globe
 */
const DigitalGlobe = ({ theme }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;

    let rotation = 0;
    const isDark = theme === 'dark';

    const strokeColor = isDark ? 'rgba(6, 182, 212, 0.45)' : 'rgba(2, 132, 199, 0.45)';
    const nodeColor = isDark ? '#06b6d4' : '#0284c7';
    const pulseColor = isDark ? 'rgba(6, 182, 212, 0.12)' : 'rgba(2, 132, 199, 0.12)';

    const render = () => {
      const w = (canvas.width = 440);
      const h = (canvas.height = 440);
      const cx = w / 2;
      const cy = h / 2;
      const radius = 170;

      ctx.clearRect(0, 0, w, h);

      // Outer Glowing Ring
      ctx.beginPath();
      ctx.arc(cx, cy, radius + 18, 0, Math.PI * 2);
      ctx.fillStyle = pulseColor;
      ctx.fill();

      // Main Outer Circle
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Latitude Ellipses
      for (let i = -60; i <= 60; i += 20) {
        const rad = (i * Math.PI) / 180;
        const y = cy + Math.sin(rad) * radius;
        const rLat = Math.cos(rad) * radius;

        ctx.beginPath();
        ctx.ellipse(cx, y, rLat, rLat * 0.35, 0, 0, Math.PI * 2);
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      // Longitude Lines with Dynamic Rotation
      rotation += 0.008;
      for (let i = 0; i < 360; i += 30) {
        const rad = ((i + rotation * 50) * Math.PI) / 180;
        const xOffset = Math.sin(rad) * radius;
        const vis = Math.cos(rad);

        if (vis > -0.2) {
          ctx.beginPath();
          ctx.ellipse(cx + xOffset * 0.3, cy, Math.abs(xOffset), radius, 0, 0, Math.PI * 2);
          ctx.strokeStyle = strokeColor;
          ctx.lineWidth = vis > 0.4 ? 1.2 : 0.6;
          ctx.stroke();
        }
      }

      // Threat Telemetry Pulse Nodes
      for (let n = 0; n < 12; n++) {
        const angle = (n * 30 + rotation * 60) * (Math.PI / 180);
        const nx = cx + Math.cos(angle) * (radius * 0.72);
        const ny = cy + Math.sin(angle * 1.5) * (radius * 0.62);

        ctx.beginPath();
        ctx.arc(nx, ny, 4, 0, Math.PI * 2);
        ctx.fillStyle = nodeColor;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(nx, ny, 8, 0, Math.PI * 2);
        ctx.strokeStyle = nodeColor;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animationFrameId);
  }, [theme]);

  return (
    <canvas
      ref={canvasRef}
      width={440}
      height={440}
      style={{
        width: '100%',
        maxWidth: '440px',
        height: 'auto',
        aspectRatio: '1 / 1'
      }}
    />
  );
};

/**
 * Floating Circular Glass Security Icons
 */
const FloatingSecurityIcons = () => {
  return (
    <>
      <div className="floating-security-icon-glass icon-pos-1">
        <Shield size={20} className="floating-icon" />
      </div>
      <div className="floating-security-icon-glass icon-pos-2">
        <Lock size={20} className="floating-icon" />
      </div>
      <div className="floating-security-icon-glass icon-pos-3">
        <Activity size={20} className="floating-icon" />
      </div>
      <div className="floating-security-icon-glass icon-pos-4">
        <Cpu size={20} className="floating-icon" />
      </div>
    </>
  );
};

/**
 * Google Icon SVG Component
 */
const GoogleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" style={{ marginRight: '0.5rem', flexShrink: 0 }}>
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

/**
 * Enterprise SOC Unified Landing & Sign-In Page
 * Single canonical authentication & landing component.
 * Smoothly transitions live digital globe from Right -> Left when user clicks GET STARTED,
 * rendering the SOC authentication console on the Right side.
 */
const LandingPage = ({
  onEnterSOC,
  theme,
  onToggleTheme,
  currentUser,
  onLoginSuccess,
  initialMode = 'landing'
}) => {
  const isDark = theme === 'dark';
  const [viewMode, setViewMode] = useState(initialMode); // 'landing' | 'signin'
  const [isSignUp, setIsSignUp] = useState(false);

  // Form Fields State
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);

  // Password Visibility
  const [showPassword, setShowPassword] = useState(false);

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

  // Handle CTA Click ("GET STARTED →")
  const handleGetStarted = () => {
    if (currentUser && onEnterSOC) {
      onEnterSOC();
    } else {
      setViewMode('signin');
    }
  };

  // Toggle between Sign In and Sign Up mode
  const toggleAuthMode = () => {
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
    setInfoNotice('Password reset is not configured in demo mode. Use default password: Password123!');
    setErrorMessage('');
  };

  // Handle Auth Form Submission
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

      if (onLoginSuccess) {
        onLoginSuccess(newUser, rememberMe);
      } else if (onEnterSOC) {
        onEnterSOC();
      }
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

      // Successful Sign-In -> directly calls onLoginSuccess to switch view to dashboard
      if (onLoginSuccess) {
        onLoginSuccess(matched, rememberMe);
      } else if (onEnterSOC) {
        onEnterSOC();
      }
    }
  };

  const isSignIn = viewMode === 'signin';

  return (
    <div className="soc-landing-wrapper">
      {/* Dynamic Animated Cyber Particle Canvas Background */}
      <BackgroundParticles theme={theme} />

      {/* Full-screen Centered Hero Card Container */}
      <main className="soc-hero-container">
        <div className="soc-hero-card">
          {/* Top Header / Branding & Controls */}
          <div className="soc-hero-card-header">
            <div className="soc-brand-group">
              <InfosysLogo height={32} className="soc-infosys-logo" />
              <span className="soc-brand-title">SECURITY OPERATIONS CENTER</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {isSignIn && (
                <button
                  className="soc-theme-toggle-btn"
                  onClick={() => setViewMode('landing')}
                  title="Back to Landing Page"
                  aria-label="Back to landing"
                  id="back-to-landing-btn"
                  style={{ width: 'auto', padding: '0 0.85rem', gap: '0.4rem', fontSize: '0.8rem', fontWeight: 600 }}
                >
                  <ArrowLeft size={16} />
                  <span>Back</span>
                </button>
              )}

              {onToggleTheme && (
                <button
                  className="soc-theme-toggle-btn"
                  onClick={onToggleTheme}
                  title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
                  aria-label="Toggle theme"
                  id="theme-toggle-btn"
                >
                  {isDark ? <Sun size={18} /> : <Moon size={18} />}
                </button>
              )}
            </div>
          </div>

          {/* Dynamic 2-Column Hero Content Grid */}
          <div className={`soc-hero-grid ${isSignIn ? 'mode-signin' : 'mode-landing'}`}>
            {/* Left Slot: Hero Copy in Landing mode OR Live Globe in Sign-In mode */}
            <div className="soc-hero-col soc-col-left">
              {!isSignIn ? (
                <div className="soc-hero-left-content animate-fade-in">
                  <h1 className="soc-main-heading">
                    Threat<br />
                    Detection<br />
                    Dashboard
                  </h1>

                  <div className="soc-action-block">
                    <button 
                      className="soc-hero-btn" 
                      onClick={handleGetStarted}
                      id="get-started-btn"
                    >
                      <span>GET STARTED</span>
                      <ArrowRight size={18} className="soc-btn-arrow" />
                    </button>
                  </div>
                </div>
              ) : (
                <div className="soc-globe-col-content animate-fade-in">
                  <div className="soc-globe-wrapper">
                    <div className="soc-live-world-pill">
                      <span className="soc-live-dot" />
                      <span className="soc-live-text">LIVE WORLD</span>
                    </div>
                    <DigitalGlobe theme={theme} />
                    <FloatingSecurityIcons theme={theme} />
                  </div>
                </div>
              )}
            </div>

            {/* Right Slot: Live Globe in Landing mode OR Sign-In Console in Sign-In mode */}
            <div className="soc-hero-col soc-col-right">
              {!isSignIn ? (
                <div className="soc-globe-col-content animate-fade-in">
                  <div className="soc-globe-wrapper">
                    <div className="soc-live-world-pill">
                      <span className="soc-live-dot" />
                      <span className="soc-live-text">LIVE WORLD</span>
                    </div>
                    <DigitalGlobe theme={theme} />
                    <FloatingSecurityIcons theme={theme} />
                  </div>
                </div>
              ) : (
                <div className="soc-auth-console animate-fade-in">
                  <div className="soc-auth-header">
                    <h2 className="soc-auth-title">
                      {isSignUp ? 'Create Analyst Account' : 'Sign In'}
                    </h2>
                    <p className="soc-auth-subtitle">
                      {isSignUp
                        ? 'Set up credentials to access the Security Operations Center.'
                        : 'Verify credentials to access the Security Operations Center.'}
                    </p>
                  </div>

                  {/* Dynamic Alert Messages */}
                  {errorMessage && (
                    <div className="soc-auth-alert error">
                      <AlertCircle size={15} color="var(--color-critical)" />
                      <span>{errorMessage}</span>
                    </div>
                  )}

                  {infoNotice && (
                    <div className="soc-auth-alert info">
                      <Info size={15} color="var(--soc-brand-color)" />
                      <span>{infoNotice}</span>
                    </div>
                  )}

                  {/* Auth Form */}
                  <form onSubmit={handleSubmit} className="soc-auth-form">
                    {isSignUp && (
                      <div className="soc-form-group">
                        <label className="soc-form-label">Full Name</label>
                        <div className="soc-input-wrapper">
                          <User size={15} className="soc-input-icon" />
                          <input
                            type="text"
                            placeholder="Enter your full name"
                            value={fullName}
                            onChange={(e) => setFullName(e.target.value)}
                            className="soc-auth-input"
                          />
                        </div>
                      </div>
                    )}

                    <div className="soc-form-group">
                      <label className="soc-form-label">Email Address</label>
                      <div className="soc-input-wrapper">
                        <Mail size={15} className="soc-input-icon" />
                        <input
                          type="email"
                          placeholder="Enter your email"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          className="soc-auth-input"
                          id="email-input"
                        />
                      </div>
                    </div>

                    <div className="soc-form-group">
                      <label className="soc-form-label">
                        {isSignUp ? 'Create Password' : 'Password'}
                      </label>
                      <div className="soc-input-wrapper">
                        <Lock size={15} className="soc-input-icon" />
                        <input
                          type={showPassword ? 'text' : 'password'}
                          placeholder={isSignUp ? 'Create a password' : 'Enter your password'}
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          className="soc-auth-input"
                          id="password-input"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="soc-eye-toggle"
                          tabIndex="-1"
                        >
                          {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                      </div>
                    </div>

                    {/* Password Strength Meter (Sign Up Only) */}
                    {isSignUp && password.length > 0 && (
                      <div className="soc-strength-box">
                        <div className="soc-strength-header">
                          <span>Password Strength</span>
                          <span style={{ fontWeight: '700', color: strengthColor }}>
                            {strengthLabel}
                          </span>
                        </div>
                        <div className="soc-progress-track">
                          <div
                            className="soc-progress-fill"
                            style={{
                              width: `${(strengthScore / 5) * 100}%`,
                              backgroundColor: strengthColor
                            }}
                          />
                        </div>
                        <div className="soc-checklist">
                          <div className="soc-check-item">
                            {passwordRequirements.minLength ? <Check size={12} color="#10b981" /> : <X size={12} color="#64748b" />}
                            <span style={{ color: passwordRequirements.minLength ? 'var(--soc-heading-color)' : '#64748b' }}>At least 8 chars</span>
                          </div>
                          <div className="soc-check-item">
                            {passwordRequirements.hasUpper ? <Check size={12} color="#10b981" /> : <X size={12} color="#64748b" />}
                            <span style={{ color: passwordRequirements.hasUpper ? 'var(--soc-heading-color)' : '#64748b' }}>Uppercase letter</span>
                          </div>
                          <div className="soc-check-item">
                            {passwordRequirements.hasLower ? <Check size={12} color="#10b981" /> : <X size={12} color="#64748b" />}
                            <span style={{ color: passwordRequirements.hasLower ? 'var(--soc-heading-color)' : '#64748b' }}>Lowercase letter</span>
                          </div>
                          <div className="soc-check-item">
                            {passwordRequirements.hasNumber ? <Check size={12} color="#10b981" /> : <X size={12} color="#64748b" />}
                            <span style={{ color: passwordRequirements.hasNumber ? 'var(--soc-heading-color)' : '#64748b' }}>Number</span>
                          </div>
                          <div className="soc-check-item">
                            {passwordRequirements.hasSpecial ? <Check size={12} color="#10b981" /> : <X size={12} color="#64748b" />}
                            <span style={{ color: passwordRequirements.hasSpecial ? 'var(--soc-heading-color)' : '#64748b' }}>Special char</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Remember Me & Forgot Password */}
                    {!isSignUp && (
                      <div className="soc-remember-row">
                        <label className="soc-checkbox-label">
                          <input
                            type="checkbox"
                            checked={rememberMe}
                            onChange={(e) => setRememberMe(e.target.checked)}
                            className="soc-checkbox"
                          />
                          <span>Remember me</span>
                        </label>
                        <a href="#forgot" onClick={handleForgotPassword} className="soc-forgot-link">
                          Forgot password?
                        </a>
                      </div>
                    )}

                    <button type="submit" className="soc-hero-btn soc-auth-submit" id="sign-in-submit-btn">
                      <span>{isSignUp ? 'Create Account' : 'Sign In'}</span>
                      <ArrowRight size={18} className="soc-btn-arrow" />
                    </button>
                  </form>

                  {/* OR Divider */}
                  <div className="soc-auth-divider">
                    <span className="soc-divider-line" />
                    <span className="soc-divider-text">OR</span>
                    <span className="soc-divider-line" />
                  </div>

                  {/* Google OAuth Button */}
                  <button
                    type="button"
                    onClick={handleGoogleClick}
                    className="soc-google-btn"
                  >
                    <GoogleIcon />
                    <span>{isSignUp ? 'Sign up with Google' : 'Continue with Google'}</span>
                  </button>

                  {/* Mode Toggle Footer */}
                  <div className="soc-toggle-footer">
                    <span>
                      {isSignUp ? 'Already have an account?' : "Don't have an account?"}
                    </span>
                    <button type="button" onClick={toggleAuthMode} className="soc-toggle-mode-btn">
                      {isSignUp ? 'Sign In' : 'Sign Up'}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default LandingPage;
