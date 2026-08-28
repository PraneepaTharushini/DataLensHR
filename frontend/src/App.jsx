import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import './App.css';

const API_BASE = 'http://localhost:5000/api';

function App() {
  // Session States
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user')) || null);
  
  // Theme State (Defaulting to light mode for brighter view)
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  
  // Navigation & Data States
  const [showSecOps, setShowSecOps] = useState(false);
  const [activeTab, setActiveTab] = useState('employees'); // employees, leaves
  const [employees, setEmployees] = useState([]);
  const [leaves, setLeaves] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  
  // Rule Management States
  const [rules, setRules] = useState([]);
  const [secOpsTab, setSecOpsTab] = useState('alerts'); // alerts, rules, analytics
  const [editingRule, setEditingRule] = useState(null);
  const [editWeight, setEditWeight] = useState(0);
  const [editIsEnabled, setEditIsEnabled] = useState(true);
  const [editParams, setEditParams] = useState({});
  
  // Department Analytics States
  const [deptAnalytics, setDeptAnalytics] = useState([]);
  const [isLoadingAnalytics, setIsLoadingAnalytics] = useState(false);
  
  // Proactive Recommendations States
  const [recommendations, setRecommendations] = useState([]);
  
  // Custom Simulator / Context Headers
  const [simLocation, setSimLocation] = useState('Colombo, Sri Lanka');
  const [isScraping, setIsScraping] = useState(false);

  // Forms
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // Leave request form states
  const [leaveType, setLeaveType] = useState('Annual Leave');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [reason, setReason] = useState('');
  // Add employee form states
  const [showAddEmployeeForm, setShowAddEmployeeForm] = useState(false);
  const [newEmpFirstName, setNewEmpFirstName] = useState('');
  const [newEmpLastName, setNewEmpLastName] = useState('');
  const [newEmpEmail, setNewEmpEmail] = useState('');
  const [newEmpDepartment, setNewEmpDepartment] = useState('IT');
  const [newEmpPosition, setNewEmpPosition] = useState('');
  const [newEmpSalary, setNewEmpSalary] = useState('');
  const [newEmpHireDate, setNewEmpHireDate] = useState('');
  
  // Salary state tracking
  const [salaryMap, setSalaryMap] = useState({}); 

  // Establish WebSockets Connection for security updates
  useEffect(() => {
    const socket = io('http://localhost:5000');

    socket.on('connect', () => {
      console.log('[WEBSOCKET] Connected to real-time incident stream.');
    });

    socket.on('NEW_INCIDENT', (newIncident) => {
      console.log('[ALERT] New suspicious activity detected:', newIncident);
      fetchIncidents();
    });

    socket.on('INCIDENT_RESOLVED', () => {
      fetchIncidents();
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // Fetch HRIS data when token changes
  useEffect(() => {
    if (token) {
      fetchEmployees();
      fetchLeaves();
      fetchIncidents();
      fetchRules();
      fetchDeptAnalytics();
      fetchRecommendations();
    }
  }, [token]);

  // Headers helper
  const getHeaders = () => {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'x-simulate-location': simLocation,
      'x-simulate-impossible-travel': 'false'
    };
  };

  // API Call: Fetch Employees
  const fetchEmployees = async () => {
    try {
      const response = await fetch(`${API_BASE}/employees`, {
        headers: getHeaders()
      });
      if (response.status === 403) {
        handleSessionExpiration('Session suspended. High security threat detected.');
        return;
      }
      if (!response.ok) throw new Error('Failed to load directory');
      const data = await response.json();
      setEmployees(data);
    } catch (err) {
      setErrorMessage(err.message);
    }
  };

  // API Call: Fetch Leaves
  const fetchLeaves = async () => {
    try {
      const response = await fetch(`${API_BASE}/leaves`, {
        headers: getHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setLeaves(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // API Call: Fetch Security Incidents
  const fetchIncidents = async () => {
    try {
      const response = await fetch(`${API_BASE}/incidents`, {
        headers: getHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setIncidents(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // API Call: Fetch Privacy Detection Rules
  const fetchRules = async () => {
    try {
      const response = await fetch(`${API_BASE}/rules`, {
        headers: getHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setRules(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // API Call: Fetch Department Privacy Analytics
  const fetchDeptAnalytics = async () => {
    setIsLoadingAnalytics(true);
    try {
      const response = await fetch(`${API_BASE}/analytics/departments`, {
        headers: getHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setDeptAnalytics(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingAnalytics(false);
    }
  };

  // API Call: Fetch Proactive Policy Recommendations
  const fetchRecommendations = async () => {
    try {
      const response = await fetch(`${API_BASE}/analytics/recommendations`, {
        headers: getHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setRecommendations(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // API Call: Enforce Dynamic Recommendation Action
  const handleApplyRecommendation = async (rec) => {
    try {
      const response = await fetch(`${API_BASE}/recommendations/apply`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          type: rec.type,
          target_user_id: rec.target_user_id,
          target_email: rec.target_email,
          target_rule_id: rec.target_rule_id,
          target_limit: rec.target_limit,
          incident_id: rec.incident_id
        })
      });
      if (response.ok) {
        const resData = await response.json();
        alert(resData.message || 'Recommendation policy applied successfully!');
        fetchRecommendations();
        fetchIncidents();
        fetchRules();
        fetchDeptAnalytics();
      } else {
        const errData = await response.json();
        alert(errData.message || 'Failed to apply recommendation policy.');
      }
    } catch (err) {
      console.error(err);
      alert('Error applying policy recommendation.');
    }
  };

  // API Call: Save Privacy Rule modifications
  const handleSaveRule = async (e, ruleId) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_BASE}/rules/${ruleId}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify({
          weight: editWeight,
          is_enabled: editIsEnabled,
          parameters: editParams
        })
      });
      if (response.ok) {
        alert('Rule configuration updated successfully!');
        setEditingRule(null);
        fetchRules();
        fetchIncidents();
      } else {
        const err = await response.json();
        alert(err.message || 'Failed to update rule.');
      }
    } catch (err) {
      console.error(err);
      alert('Error saving rule configuration.');
    }
  };

  // API Call: Request Sensitive Salary Details (Explicit read check)
  const fetchSensitiveSalary = async (employeeId) => {
    if (salaryMap[employeeId]) {
      setSalaryMap(prev => {
        const next = { ...prev };
        delete next[employeeId];
        return next;
      });
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/employees/${employeeId}/salary`, {
        headers: getHeaders()
      });
      if (response.status === 401) {
        handleSessionExpiration('Session expired. Please log in again.');
        return;
      }
      if (response.status === 403) {
        const data = await response.json();
        if (data.message && data.message.includes('suspended')) {
          handleSessionExpiration('Session suspended. High security threat detected.');
        } else {
          alert('ACCESS DENIED: Insufficient Role-Based permission levels. Threat logged.');
          fetchIncidents();
        }
        return;
      }
      const data = await response.json();
      setSalaryMap(prev => ({ ...prev, [employeeId]: data.salary }));
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  // Calculate Rule Trigger Frequencies
  const getRuleFrequencies = () => {
    const counts = {
      VOLUMETRIC_SCRAPE: 0,
      IMPOSSIBLE_TRAVEL: 0,
      UNAUTHORIZED_SALARY_READ: 0,
      CANARY_ACCESS: 0
    };
    incidents.forEach(inc => {
      const rules = Array.isArray(inc.triggered_rules) ? inc.triggered_rules : JSON.parse(inc.triggered_rules || '[]');
      rules.forEach(rule => {
        if (rule in counts) {
          counts[rule]++;
        } else {
          counts[rule] = (counts[rule] || 0) + 1;
        }
      });
    });
    return counts;
  };

  // Calculate Top Risk Accounts
  const getTopRiskAccounts = () => {
    const accounts = {};
    incidents.forEach(inc => {
      const email = inc.user_email || 'Anonymous';
      if (!accounts[email]) {
        accounts[email] = {
          email,
          role: inc.user_role || 'Guest',
          peakScore: 0,
          incidentCount: 0
        };
      }
      accounts[email].peakScore = Math.max(accounts[email].peakScore, inc.risk_score);
      accounts[email].incidentCount++;
    });
    return Object.values(accounts)
      .sort((a, b) => b.peakScore - a.peakScore)
      .slice(0, 3);
  };

  // Helper: Get highest average risk department
  const getTopRiskDept = () => {
    if (deptAnalytics.length === 0) return 'None';
    const sorted = [...deptAnalytics].sort((a, b) => b.avg_risk_score - a.avg_risk_score);
    return sorted[0].avg_risk_score > 0 ? `${sorted[0].department} (${Math.round(sorted[0].avg_risk_score)} Avg Risk)` : 'None';
  };

  // Helper: Get highest records accessed department
  const getTopHarvesterDept = () => {
    if (deptAnalytics.length === 0) return 'None';
    const sorted = [...deptAnalytics].sort((a, b) => b.total_records_accessed - a.total_records_accessed);
    return sorted[0].total_records_accessed > 0 ? `${sorted[0].department} (${sorted[0].total_records_accessed} reads)` : 'None';
  };

  // API Call: Resolve / Mitigate Incident
  const executeMitigation = async (incidentId, action, userId) => {
    try {
      const response = await fetch(`${API_BASE}/incidents/${incidentId}/mitigate`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ action, userId })
      });
      if (response.ok) {
        alert(`Mitigation executed: ${action}`);
        fetchIncidents();
      } else {
        const errData = await response.json();
        alert(errData.message || 'Mitigation failed');
      }
    } catch (err) {
      console.error(err);
    }
  };

  // API Call: Login
  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage('');
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-simulate-location': simLocation,
          'x-simulate-impossible-travel': 'false'
        },
        body: JSON.stringify({ email: loginEmail, password: loginPassword })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.message || 'Invalid credentials');
      }

      const data = await response.json();
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
      
      // Auto-route to SecOps if admin/manager
      if (data.user.role === 'System Administrator' || data.user.role === 'HR Manager') {
        setShowSecOps(true);
      } else {
        setShowSecOps(false);
      }
    } catch (err) {
      setErrorMessage(err.message);
    }
  };

  // Autofill Helper
  const handleAutofill = (email) => {
    setLoginEmail(email);
    setLoginPassword('admin123');
  };

  // Toggle Theme
  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    localStorage.setItem('theme', nextTheme);
  };

  // API Call: Add new employee (HR Manager/Admin)
  const handleAddEmployee = async (e) => {
    e.preventDefault();
    if (!newEmpFirstName || !newEmpLastName || !newEmpEmail || !newEmpSalary || !newEmpHireDate) {
      alert('Please fill out all required fields.');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/employees`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          first_name: newEmpFirstName,
          last_name: newEmpLastName,
          email: newEmpEmail,
          department: newEmpDepartment,
          position: newEmpPosition,
          salary: newEmpSalary,
          hire_date: newEmpHireDate
        })
      });

      if (response.ok) {
        alert('Employee added successfully!');
        setNewEmpFirstName('');
        setNewEmpLastName('');
        setNewEmpEmail('');
        setNewEmpPosition('');
        setNewEmpSalary('');
        setNewEmpHireDate('');
        setShowAddEmployeeForm(false);
        fetchEmployees();
      } else {
        const data = await response.json();
        alert(data.message || 'Failed to add employee.');
      }
    } catch (err) {
      console.error(err);
      alert('Error adding employee.');
    }
  };

  // API Call: Remove employee (HR Manager/Admin)
  const handleRemoveEmployee = async (employeeId, name) => {
    if (!window.confirm(`Are you sure you want to remove employee ${name}? This action is permanent.`)) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/employees/${employeeId}`, {
        method: 'DELETE',
        headers: getHeaders()
      });

      if (response.ok) {
        alert('Employee removed successfully!');
        fetchEmployees();
      } else {
        const data = await response.json();
        alert(data.message || 'Failed to remove employee.');
      }
    } catch (err) {
      console.error(err);
      alert('Error removing employee.');
    }
  };

  // API Call: Approve/Reject Leave Request
  const handleLeaveDecision = async (leaveId, decision) => {
    try {
      const response = await fetch(`${API_BASE}/leaves/${leaveId}/status`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify({ status: decision })
      });
      if (response.ok) {
        fetchLeaves();
      } else {
        const err = await response.json();
        alert(err.message || 'Action denied');
      }
    } catch (err) {
      console.error(err);
    }
  };
  const handleRequestLeave = async (e) => {
    e.preventDefault();
    if (!startDate || !endDate || !reason) {
      alert('Please fill out all fields.');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/leaves`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          leave_type: leaveType,
          start_date: startDate,
          end_date: endDate,
          reason
        })
      });

      if (response.ok) {
        alert('Leave request submitted successfully!');
        setStartDate('');
        setEndDate('');
        setReason('');
        fetchLeaves();
      } else {
        const err = await response.json();
        alert(err.message || 'Failed to submit leave request');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken('');
    setUser(null);
    setShowSecOps(false);
    setSalaryMap({});
    setRules([]);
    setDeptAnalytics([]);
  };

  const handleSessionExpiration = (message) => {
    alert(message);
    handleLogout();
  };

  // ------------------ THREAT SIMULATORS ------------------
  
  // Simulate Volumetric profile scraping (making 12 quick requests in 1 second)
  const simulateScraping = async () => {
    if (!token) return;
    setIsScraping(true);
    console.log('[SIMULATOR] Starting rapid employee profile scrape...');
    
    try {
      for (let i = 0; i < 12; i++) {
        await fetch(`${API_BASE}/employees`, {
          headers: getHeaders()
        });
      }
      await fetchEmployees();
      await fetchIncidents();
      
      if (user.role === 'System Administrator' || user.role === 'HR Manager') {
        setShowSecOps(true);
      }
      alert('Simulation completed! Redirecting you to the SecOps Panel to view the active Volumetric Scrape alert.');
    } catch (e) {
      console.error(e);
    } finally {
      setIsScraping(false);
    }
  };

  // Run the new server-side impossible travel simulator
  const simulateImpossibleTravel = async () => {
    if (!token) return;
    try {
      const response = await fetch(`${API_BASE}/simulate/threat`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ threatType: 'IMPOSSIBLE_TRAVEL' })
      });
      if (response.ok) {
        await fetchIncidents();
        if (user.role === 'System Administrator' || user.role === 'HR Manager') {
          setShowSecOps(true);
        }
        alert('Impossible travel threat simulated! Redirecting you to the SecOps Panel to view the active alert.');
      } else {
        const data = await response.json();
        alert(data.message || 'Simulation failed');
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className={`app-layout ${theme === 'dark' ? 'dark-theme' : 'light-theme'}`}>
      {/* Navbar header */}
      <header className="navbar">
        <div className="nav-brand">
          <div className="nav-logo">
            <img src="/logo.png" alt="DataLens Logo" className="nav-logo-img" />
          </div>
          <div className="nav-title">
            <h1 style={{ color: 'var(--text-primary)' }}>DataLens HR</h1>
            <p>Privacy Analytics Suite</p>
          </div>
        </div>

        <div className="nav-controls">
          {/* Universal Theme Toggle Button */}
          <button 
            onClick={toggleTheme}
            className="btn-signout"
            style={{ marginRight: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
          </button>

          {token && (
            <>
              {/* Switching tabs */}
              <div className="switch-group">
                <button 
                  onClick={() => setShowSecOps(false)}
                  className={`switch-btn ${!showSecOps ? 'active' : ''}`}
                >
                  HR Workspace
                </button>
                {(user.role === 'System Administrator' || user.role === 'HR Manager') && (
                  <button 
                    onClick={() => setShowSecOps(true)}
                    className={`switch-btn ${showSecOps ? 'active' : ''}`}
                  >
                    SecOps Panel
                  </button>
                )}
              </div>

              {/* Profile Info */}
              <div className="user-badge">
                <div className="user-badge-info">
                  <p className="user-badge-email" style={{ color: 'var(--text-primary)' }}>{user.email}</p>
                  <p className="user-badge-role">{user.role}</p>
                </div>
                <button onClick={handleLogout} className="btn-signout">
                  Sign Out
                </button>
              </div>
            </>
          )}
        </div>
      </header>

      {/* Main Container */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {!token ? (
          /* ================= LOGIN PORTAL ================= */
          <div className="login-view animate-fade-in">
            <div className="login-hero">
              <h2 style={{ color: 'var(--text-primary)' }}>
                Redefining HRIS with <br />
                <span>Privacy Monitoring Analytics</span>
              </h2>
              <p>
                An intelligent Privacy Auditing and Incident Response System designed to continuously monitor database request rates, unauthorized wage probing, decoy honeypots, and location velocity anomalies.
              </p>
              
              <div className="demo-accounts-card">
                <h4>Interactive Role Quick-Select (Autofill)</h4>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>Click any pill button below to automatically load credentials:</p>
                <div className="demo-pills-container">
                  <div className="demo-pill" onClick={() => handleAutofill('admin@datalenshr.com')}>
                    <span className="demo-pill-title" style={{ color: 'var(--text-primary)' }}>System Administrator (Full Access)</span>
                    <span className="demo-pill-email">admin@datalenshr.com</span>
                  </div>
                  <div className="demo-pill" onClick={() => handleAutofill('manager@datalenshr.com')}>
                    <span className="demo-pill-title" style={{ color: 'var(--text-primary)' }}>HR Manager (Privileged HR)</span>
                    <span className="demo-pill-email">manager@datalenshr.com</span>
                  </div>
                  <div className="demo-pill" onClick={() => handleAutofill('staff@datalenshr.com')}>
                    <span className="demo-pill-title" style={{ color: 'var(--text-primary)' }}>HR Staff (General Access)</span>
                    <span className="demo-pill-email">staff@datalenshr.com</span>
                  </div>
                  <div className="demo-pill" onClick={() => handleAutofill('employee@datalenshr.com')}>
                    <span className="demo-pill-title" style={{ color: 'var(--text-primary)' }}>Employee (Profile Owner Only)</span>
                    <span className="demo-pill-email">employee@datalenshr.com</span>
                  </div>
                </div>
              </div>

              {/* Simulation Environment Config */}
              <div className="sim-controller-card">
                <h4>⚙️ Client Simulation Environment</h4>
                <div className="input-select-container">
                  <label>Simulated Geolocation (IP-City Mapping):</label>
                  <select 
                    value={simLocation} 
                    onChange={(e) => setSimLocation(e.target.value)}
                    className="select-dropdown"
                  >
                    <option value="Colombo, Sri Lanka">Colombo, Sri Lanka (HQ Network)</option>
                    <option value="Tokyo, Japan">Tokyo, Japan (Remote Anomaly)</option>
                    <option value="London, United Kingdom">London, United Kingdom (Remote Anomaly)</option>
                  </select>
                </div>
                <div className="checkbox-row">
                  <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    💡 <em>Impossible travel velocities and lockout triggers can now be simulated safely using the simulator console inside the dashboard.</em>
                  </p>
                </div>
              </div>
            </div>

            {/* Login Box */}
            <div className="login-form-box">
              <h3 style={{ color: 'var(--text-primary)' }}>Secure Sign In</h3>
              <p className="login-subtitle">Authenticate credentials to initiate secure workspace audit log tracking.</p>
              
              {errorMessage && (
                <div className="error-banner" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '8px', padding: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>⚠️</span> 
                    <span style={{ textAlign: 'left' }}>{errorMessage}</span>
                  </div>
                  {(errorMessage.includes('locked') || errorMessage.includes('suspended')) && (
                    <button
                      type="button"
                      onClick={async () => {
                        try {
                          const res = await fetch(`${API_BASE}/auth/bypass-lockout`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: loginEmail })
                          });
                          if (res.ok) {
                            alert('Account unlocked successfully! You can now sign in.');
                            setErrorMessage('');
                          }
                        } catch (e) {
                          console.error(e);
                        }
                      }}
                      className="btn-mitigation-unlock"
                      style={{ padding: '6px 12px', fontSize: '11px', marginTop: '4px', width: 'auto', alignSelf: 'stretch', textAlign: 'center' }}
                    >
                      Instant Unlock Account (Demo Helper)
                    </button>
                  )}
                </div>
              )}
              
              <form onSubmit={handleLogin}>
                <div className="input-field-group">
                  <label>Email Address</label>
                  <input 
                    type="email" 
                    required 
                    placeholder="name@datalenshr.com"
                    value={loginEmail}
                    onChange={(e) => setLoginEmail(e.target.value)}
                    className="text-input-field"
                  />
                </div>
                
                <div className="input-field-group">
                  <label>Password</label>
                  <div style={{ position: 'relative' }}>
                    <input 
                      type={showPassword ? 'text' : 'password'} 
                      required 
                      placeholder="••••••••"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      className="text-input-field"
                      style={{ width: '100%', paddingRight: '45px' }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      style={{
                        position: 'absolute',
                        right: '12px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: '14px',
                        color: 'var(--text-secondary)',
                        outline: 'none',
                        userSelect: 'none',
                        padding: '4px'
                      }}
                    >
                      {showPassword ? '👁️' : '🔒'}
                    </button>
                  </div>
                </div>

                <button type="submit" className="btn-login-submit">
                  Sign In
                </button>
              </form>
            </div>
          </div>
        ) : showSecOps ? (
          /* ================= SECOPS DASHBOARD ================= */
          <div className="secops-view animate-fade-in">
            <div className="secops-widgets-aside">
              {/* Composite Gauge Card */}
              <div className="gauge-panel">
                <h3>Composite System Risk</h3>
                
                {(() => {
                  const maxRisk = incidents.filter(i => i.status === 'Open').length > 0 
                    ? Math.max(...incidents.filter(i => i.status === 'Open').map(i => i.risk_score)) 
                    : 0;
                  const isHigh = maxRisk >= 70;
                  const isMed = maxRisk >= 40 && maxRisk < 70;
                  const strokeDash = 2 * Math.PI * 62; // ~389.5
                  const strokeOffset = strokeDash * (1 - maxRisk / 100);

                  return (
                    <div className={`gauge-ring-outer ${isHigh ? 'high-risk' : isMed ? 'med-risk' : ''}`} style={{ border: 'none' }}>
                      <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)', position: 'absolute', top: '0', left: '0' }}>
                        <circle
                          cx="70"
                          cy="70"
                          r="62"
                          fill="transparent"
                          stroke="var(--border-glow)"
                          strokeWidth="8"
                        />
                        {/* Spinning high-tech dash accent ring */}
                        <circle
                          cx="70"
                          cy="70"
                          r="54"
                          fill="transparent"
                          stroke={isHigh ? 'rgba(239, 68, 68, 0.15)' : isMed ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.1)'}
                          strokeWidth="2"
                          strokeDasharray="6, 8"
                          style={{
                            transformOrigin: '70px 70px',
                            animation: 'spinDial 25s linear infinite'
                          }}
                        />
                        <circle
                          cx="70"
                          cy="70"
                          r="62"
                          fill="transparent"
                          stroke={isHigh ? 'var(--danger)' : isMed ? 'var(--warning)' : 'var(--success)'}
                          strokeWidth="8"
                          strokeDasharray={strokeDash}
                          strokeDashoffset={strokeOffset}
                          strokeLinecap="round"
                          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.34, 1.56, 0.64, 1)' }}
                        />
                      </svg>
                      <div style={{ position: 'relative', zIndex: 2 }}>
                        <span className="gauge-value-number" style={{ color: 'var(--text-primary)' }}>
                          {maxRisk}
                        </span>
                        <span className="gauge-value-lbl">
                          {maxRisk === 0 ? 'Clean' : maxRisk >= 70 ? 'Critical' : 'Warning'}
                        </span>
                      </div>
                    </div>
                  );
                })()}

                <div className="status-stats-grid">
                  <div className="status-stats-row">
                    <label>Total Incidents Logged:</label>
                    <span style={{ color: 'var(--text-primary)' }}>{incidents.length}</span>
                  </div>
                  <div className="status-stats-row">
                    <label>Active Unresolved Alerts:</label>
                    <span style={{ color: '#ef4444' }}>{incidents.filter(i => i.status === 'Open').length}</span>
                  </div>
                </div>
              </div>

              {/* Threat Matrix Rules Overview */}
              <div className="policies-panel">
                <h3>Threat Detection Policies</h3>
                <div className="policy-grid-rows">
                  {rules.map((r) => {
                    const params = typeof r.parameters === 'object' ? r.parameters : JSON.parse(r.parameters || '{}');
                    let displayDesc = 'Enabled';
                    if (!r.is_enabled) {
                      displayDesc = 'Disabled';
                    } else if (r.id === 'R-02') {
                      displayDesc = `${params.start_hour ?? 23}:00 - ${params.end_hour ?? 5}:00`;
                    } else if (r.id === 'R-03') {
                      displayDesc = 'Geo Anomaly';
                    } else if (r.id === 'R-04') {
                      displayDesc = 'Salary Read';
                    } else if (r.id === 'R-05') {
                      displayDesc = `>${params.limit ?? 10} reads/${(params.window_ms ?? 10000)/1000}s`;
                    } else if (r.id === 'R-06') {
                      displayDesc = 'Canary Trigger';
                    }
                    return (
                      <div key={r.id} className="policy-grid-row" style={!r.is_enabled ? { opacity: 0.5 } : {}}>
                        <span className="policy-label-code">{r.id}: {r.name.replace(/_/g, ' ')}</span>
                        <span className="policy-label-desc" style={{ color: !r.is_enabled ? 'var(--text-muted)' : 'var(--text-primary)' }}>{displayDesc}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="secops-main-content">
              {/* SecOps Sub-Navigation Tabs */}
              <div className="secops-sub-nav">
                <button 
                  onClick={() => setSecOpsTab('alerts')} 
                  className={`sub-nav-btn ${secOpsTab === 'alerts' ? 'active' : ''}`}
                >
                  ⚠️ Telemetry & Incident Alerts
                </button>
                {user && user.role === 'System Administrator' && (
                  <button 
                    onClick={() => setSecOpsTab('rules')} 
                    className={`sub-nav-btn ${secOpsTab === 'rules' ? 'active' : ''}`}
                  >
                    ⚙️ Privacy Detection Rules
                  </button>
                )}
                {(user && (user.role === 'System Administrator' || user.role === 'HR Manager')) && (
                  <button 
                    onClick={() => { setSecOpsTab('analytics'); fetchDeptAnalytics(); }} 
                    className={`sub-nav-btn ${secOpsTab === 'analytics' ? 'active' : ''}`}
                  >
                    📊 Department Analytics
                  </button>
                )}
                {(user && (user.role === 'System Administrator' || user.role === 'HR Manager')) && (
                  <button 
                    onClick={() => { setSecOpsTab('recommendations'); fetchRecommendations(); }} 
                    className={`sub-nav-btn ${secOpsTab === 'recommendations' ? 'active' : ''}`}
                  >
                    💡 Policy Recommendations
                  </button>
                )}
              </div>

              {secOpsTab === 'alerts' ? (
                <>
                  {/* Top Analytics Panel (Top Risk & Rule Frequency) */}
                  <div className="secops-analytics-grid">
                    
                    {/* Top Risk Accounts */}
                    <div className="analytics-card">
                      <h3>🚨 Top Risk Accounts</h3>
                      <div className="analytics-card-content">
                        {getTopRiskAccounts().length === 0 ? (
                          <div style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>No active accounts flagged.</div>
                        ) : (
                          <div className="risk-accounts-list">
                            {getTopRiskAccounts().map((acc, idx) => (
                              <div key={idx} className="risk-account-row">
                                <div className="risk-account-details">
                                  <span className="risk-account-email" style={{ color: 'var(--text-primary)' }}>{acc.email}</span>
                                  <span className="risk-account-role">{acc.role}</span>
                                </div>
                                <div className="risk-account-badge">
                                  <span className="risk-score-pill" style={{
                                    backgroundColor: acc.peakScore >= 70 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                                    color: acc.peakScore >= 70 ? '#fca5a5' : '#fcd34d'
                                  }}>
                                    Peak Risk: {acc.peakScore}
                                  </span>
                                  <span className="risk-incident-count">({acc.incidentCount} alerts)</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Rule Trigger Frequency */}
                    <div className="analytics-card">
                      <h3>📊 Rule Trigger Frequency</h3>
                      <div className="analytics-card-content">
                        {Object.entries(getRuleFrequencies()).map(([rule, count], idx) => {
                          const frequencies = getRuleFrequencies();
                          const maxCount = Math.max(...Object.values(frequencies), 1);
                          const percentage = (count / maxCount) * 100;
                          return (
                            <div key={idx} className="rule-frequency-row">
                              <div className="rule-frequency-labels">
                                <span className="rule-name-lbl" style={{ color: 'var(--text-primary)' }}>{rule.replace(/_/g, ' ')}</span>
                                <span className="rule-count-lbl">{count} times</span>
                              </div>
                              <div className="rule-frequency-bar-bg">
                                <div 
                                  className="rule-frequency-bar-fill" 
                                  style={{ 
                                    width: `${percentage}%`,
                                    backgroundColor: rule === 'CANARY_ACCESS' || rule === 'IMPOSSIBLE_TRAVEL' ? 'var(--danger)' : 'var(--warning)'
                                  }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                  </div>

                  {/* Main alerts listing log */}
                  <div className="incidents-card-log">
                    <div className="incidents-log-header">
                      <div>
                        <h3 style={{ color: 'var(--text-primary)' }}>Suspicious Activity Auditing Feed</h3>
                        <p>Real-time telemetry reports containing detailed user access records, IP geolocations, and dynamic mitigation advice.</p>
                      </div>
                      <button onClick={fetchIncidents} className="btn-actions-refresh">
                        Refresh Alerts Feed
                      </button>
                    </div>

                    <div className="incident-scroller-view">
                      {incidents.length === 0 ? (
                        <div className="no-incidents-placeholder">
                          <div className="no-incidents-placeholder-icon">🛡️</div>
                          <p style={{ fontWeight: 'bold', fontSize: '15px', color: 'var(--text-primary)' }}>System Shield Active</p>
                          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                            No malicious activities flagged yet. Switch to "HR Workspace" and trigger simulator buttons to test rule calculations.
                          </p>
                        </div>
                      ) : (
                        incidents.map((inc) => {
                          const triggeredRules = Array.isArray(inc.triggered_rules) ? inc.triggered_rules : JSON.parse(inc.triggered_rules || '[]');
                          const evidence = typeof inc.raw_evidence === 'object' ? inc.raw_evidence : JSON.parse(inc.raw_evidence || '{}');
                          const actions = Array.isArray(inc.recommended_actions) ? inc.recommended_actions : JSON.parse(inc.recommended_actions || '[]');
                          
                          return (
                            <div 
                              key={inc.id}
                              className={`incident-ticket ${
                                inc.status === 'Open' 
                                  ? inc.risk_level === 'High' 
                                    ? 'risk-high' 
                                    : inc.risk_level === 'Medium' 
                                      ? 'risk-medium' 
                                      : 'risk-low'
                                  : 'resolved'
                              }`}
                            >
                              <div className="ticket-header">
                                <div>
                                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                    <span className={`risk-level-badge ${inc.risk_level.toLowerCase()}`}>
                                      {inc.risk_level} Risk Level
                                    </span>
                                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>ID: {inc.id.substring(0, 8)}</span>
                                  </div>
                                  <h4 className="ticket-title" style={{ color: 'var(--text-primary)' }}>
                                    Triggered: <span className="rule-code-ref">{triggeredRules.join(', ')}</span>
                                  </h4>
                                </div>

                                <div className="ticket-score-box">
                                  <span className="ticket-score-number" style={{ color: 'var(--text-primary)' }}>{inc.risk_score}</span>
                                  <span className="ticket-score-lbl block">Calculated Risk</span>
                                </div>
                              </div>

                              {/* Evidence Table */}
                              <div className="evidence-grid">
                                <div className="evidence-cell">
                                  <label>Audit Target Account:</label>
                                  <span style={{ color: 'var(--text-primary)' }}>{inc.user_email || 'Anonymous'}</span>
                                </div>
                                <div className="evidence-cell">
                                  <label>Role Assignment:</label>
                                  <span style={{ color: '#818cf8' }}>{inc.user_role || 'Guest'}</span>
                                </div>
                                <div className="evidence-cell">
                                  <label>Browser/Device Agent:</label>
                                  <span style={{ color: 'var(--text-primary)' }}>{evidence.metadata ? evidence.metadata.device : 'Unknown Browser'}</span>
                                </div>
                                <div className="evidence-cell">
                                  <label>Geo Location Network:</label>
                                  <span style={{ color: 'var(--text-primary)' }}>
                                    📍 {evidence.metadata ? `${evidence.metadata.city}, ${evidence.metadata.country}` : 'Unknown'} ({evidence.metadata ? evidence.metadata.ip : '127.0.0.1'})
                                  </span>
                                </div>
                              </div>

                              {/* Mitigation protocols */}
                              <div className="incident-protocol-section">
                                <span className="incident-protocol-title">Mitigation Advice Response Plan:</span>
                                <ul className="incident-protocol-list" style={{ color: 'var(--text-secondary)' }}>
                                  {actions.map((act, i) => (
                                    <li key={i}>{act}</li>
                                  ))}
                                </ul>
                              </div>

                              {inc.status === 'Open' && (
                                <div className="ticket-actions-bar">
                                  <button
                                    onClick={() => executeMitigation(inc.id, 'DISMISS', null)}
                                    className="btn-mitigation-dismiss"
                                    style={{ color: 'var(--text-primary)', border: '1px solid var(--border-glow)' }}
                                  >
                                    Dismiss False Positive
                                  </button>
                                  {inc.risk_level === 'High' && (
                                    <button
                                      onClick={() => executeMitigation(inc.id, 'LOCK_USER', inc.user_id)}
                                      className="btn-mitigation-lock"
                                    >
                                      Trigger Lock User Account
                                    </button>
                                  )}
                                </div>
                              )}
                              {inc.status === 'Resolved' && (
                                <div className="ticket-actions-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                                  <span className="ticket-resolved-badge">
                                    ✓ Mitigated & Resolved
                                  </span>
                                  <div style={{ display: 'flex', gap: '8px' }}>
                                    {inc.risk_level === 'High' && (
                                      <button
                                        onClick={() => executeMitigation(inc.id, 'UNLOCK_USER', inc.user_id)}
                                        className="btn-mitigation-unlock"
                                      >
                                        Unlock Account
                                      </button>
                                    )}
                                    <button
                                      onClick={() => executeMitigation(inc.id, 'REOPEN', null)}
                                      className="btn-mitigation-dismiss"
                                      style={{ color: 'var(--text-primary)', border: '1px solid var(--border-glow)', padding: '8px 16px' }}
                                    >
                                      Reopen Incident
                                    </button>
                                  </div>
                                </div>
                              )}
                              {inc.status === 'False Positive' && (
                                <div className="ticket-actions-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                                  <span className="ticket-resolved-badge" style={{ color: 'var(--text-muted)' }}>
                                    ✓ Dismissed (False Positive)
                                  </span>
                                  <button
                                    onClick={() => executeMitigation(inc.id, 'REOPEN', null)}
                                    className="btn-mitigation-unlock"
                                    style={{ background: 'var(--primary)', padding: '8px 16px' }}
                                  >
                                    Reopen Incident
                                  </button>
                                </div>
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                </>
              ) : secOpsTab === 'rules' ? (
                /* ================= RULES CONFIGURATION VIEW ================= */
                <div className="rules-config-panel animate-fade-in">
                  <div className="rules-config-header">
                    <h3 style={{ color: 'var(--text-primary)' }}>Privacy Policy Detection Rules</h3>
                    <p>Dynamically modify threat limits, active sliding windows, risk weights, and toggle rules on/off to adjust security sensitivity levels.</p>
                  </div>

                  <div className="rules-grid">
                    {rules.map((rule) => {
                      const params = typeof rule.parameters === 'object' ? rule.parameters : JSON.parse(rule.parameters || '{}');
                      const isEditing = editingRule && editingRule.id === rule.id;

                      return (
                        <div key={rule.id} className={`rule-config-card ${rule.is_enabled ? 'enabled' : 'disabled'}`}>
                          <div className="rule-card-header">
                            <div>
                              <span className="rule-card-id">{rule.id}</span>
                              <h4 style={{ color: 'var(--text-primary)', marginTop: '4px' }}>{rule.name.replace(/_/g, ' ')}</h4>
                            </div>
                            <span className={`status-badge-indicator ${rule.is_enabled ? 'active' : 'inactive'}`}>
                              {rule.is_enabled ? 'Active Policy' : 'Disabled'}
                            </span>
                          </div>
                          
                          <p className="rule-card-desc" style={{ color: 'var(--text-secondary)' }}>{rule.description}</p>

                          {isEditing ? (
                            <form onSubmit={(e) => handleSaveRule(e, rule.id)} className="rule-edit-form">
                              <div className="edit-form-field">
                                <label style={{ display: 'block', color: 'var(--text-primary)', marginBottom: '6px', fontSize: '12px' }}>Risk Score Weight (1 - 100):</label>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                  <input 
                                    type="range" 
                                    min="1" 
                                    max="100" 
                                    value={editWeight} 
                                    onChange={(e) => setEditWeight(parseInt(e.target.value))}
                                    style={{ flex: 1 }}
                                  />
                                  <span style={{ fontWeight: 'bold', width: '30px', textAlign: 'right', color: 'var(--text-primary)' }}>{editWeight}</span>
                                </div>
                              </div>

                              <div className="edit-form-field checkbox-field" style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '14px 0' }}>
                                <input 
                                  type="checkbox" 
                                  id={`enabled-chk-${rule.id}`}
                                  checked={editIsEnabled} 
                                  onChange={(e) => setEditIsEnabled(e.target.checked)}
                                  style={{ cursor: 'pointer', width: '16px', height: '16px' }}
                                />
                                <label htmlFor={`enabled-chk-${rule.id}`} style={{ cursor: 'pointer', fontSize: '13px', color: 'var(--text-primary)' }}>
                                  Enable threat detection check
                                </label>
                              </div>

                              {/* Custom Parameter Fields */}
                              {rule.id === 'R-02' && (
                                <div className="edit-form-field inline-fields" style={{ display: 'flex', gap: '12px', margin: '14px 0' }}>
                                  <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>Start Hour (11 PM = 23):</label>
                                    <input 
                                      type="number" 
                                      min="0" 
                                      max="23" 
                                      value={editParams.start_hour ?? 23} 
                                      onChange={(e) => setEditParams(prev => ({ ...prev, start_hour: parseInt(e.target.value) }))}
                                      className="text-input-field"
                                      style={{ width: '100%', padding: '6px' }}
                                    />
                                  </div>
                                  <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>End Hour (5 AM = 5):</label>
                                    <input 
                                      type="number" 
                                      min="0" 
                                      max="23" 
                                      value={editParams.end_hour ?? 5} 
                                      onChange={(e) => setEditParams(prev => ({ ...prev, end_hour: parseInt(e.target.value) }))}
                                      className="text-input-field"
                                      style={{ width: '100%', padding: '6px' }}
                                    />
                                  </div>
                                </div>
                              )}

                              {rule.id === 'R-05' && (
                                <div className="edit-form-field inline-fields" style={{ display: 'flex', gap: '12px', margin: '14px 0' }}>
                                  <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>Profile Reads Threshold:</label>
                                    <input 
                                      type="number" 
                                      min="1" 
                                      value={editParams.limit ?? 10} 
                                      onChange={(e) => setEditParams(prev => ({ ...prev, limit: parseInt(e.target.value) }))}
                                      className="text-input-field"
                                      style={{ width: '100%', padding: '6px' }}
                                    />
                                  </div>
                                  <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>Sliding Window (ms):</label>
                                    <input 
                                      type="number" 
                                      min="1000" 
                                      step="1000"
                                      value={editParams.window_ms ?? 10000} 
                                      onChange={(e) => setEditParams(prev => ({ ...prev, window_ms: parseInt(e.target.value) }))}
                                      className="text-input-field"
                                      style={{ width: '100%', padding: '6px' }}
                                    />
                                  </div>
                                </div>
                              )}

                              <div className="edit-form-actions" style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                                <button type="submit" className="btn-primary-action" style={{ padding: '6px 12px', fontSize: '12px' }}>Save Changes</button>
                                <button type="button" onClick={() => setEditingRule(null)} className="btn-mitigation-dismiss" style={{ padding: '6px 12px', fontSize: '12px', border: '1px solid var(--border-glow)' }}>Cancel</button>
                              </div>
                            </form>
                          ) : (
                            <div className="rule-card-metrics" style={{ marginTop: '14px' }}>
                              <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Risk Weight:</span>
                                <span style={{ color: 'var(--text-primary)', fontWeight: 'bold', fontSize: '12px' }}>{rule.weight}</span>
                              </div>
                              
                              {rule.id === 'R-02' && (
                                <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                  <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Restricted Timeframe:</span>
                                  <span style={{ color: 'var(--text-primary)', fontSize: '12px', fontWeight: '500' }}>
                                    {params.start_hour ?? 23}:00 to {params.end_hour ?? 5}:00
                                  </span>
                                </div>
                              )}

                              {rule.id === 'R-05' && (
                                <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                  <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Alert Limit Threshold:</span>
                                  <span style={{ color: 'var(--text-primary)', fontSize: '12px', fontWeight: '500' }}>
                                    &gt; {params.limit ?? 10} reads / {(params.window_ms ?? 10000) / 1000}s
                                  </span>
                                </div>
                              )}

                              <button 
                                onClick={() => {
                                  setEditingRule(rule);
                                  setEditWeight(rule.weight);
                                  setEditIsEnabled(rule.is_enabled);
                                  setEditParams(params);
                                }} 
                                className="btn-actions-refresh"
                                style={{ width: '100%', marginTop: '14px', padding: '8px', fontSize: '12px', border: '1px solid var(--border-glow)', textAlign: 'center' }}
                              >
                                Edit Policy Configurations
                              </button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : secOpsTab === 'analytics' ? (
                /* ================= DEPARTMENT ANALYTICS VIEW ================= */
                <div className="dept-analytics-panel animate-fade-in">
                  <div className="rules-config-header">
                    <h3 style={{ color: 'var(--text-primary)' }}>Department Privacy Analytics</h3>
                    <p>Aggregated telemetry audit of data accesses, record leaks, and incident risk summaries grouped by department.</p>
                  </div>

                  {/* Summary ribbon */}
                  <div className="analytics-ribbon" style={{ display: 'flex', gap: '16px', marginBottom: '24px', flexWrap: 'wrap' }}>
                    <div className="ribbon-card" style={{ flex: 1, minWidth: '220px', background: 'var(--bg-card)', border: '1px solid var(--border-glow)', padding: '16px', borderRadius: '12px' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Monitored Depts</span>
                      <h3 style={{ fontSize: '24px', fontWeight: '800', marginTop: '8px', color: 'var(--text-primary)' }}>{deptAnalytics.length}</h3>
                    </div>
                    <div className="ribbon-card" style={{ flex: 1, minWidth: '220px', background: 'var(--bg-card)', border: '1px solid var(--border-glow)', padding: '16px', borderRadius: '12px' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Top Vulnerability Dept</span>
                      <h3 style={{ fontSize: '15px', fontWeight: '700', marginTop: '12px', color: 'var(--danger)' }}>{getTopRiskDept()}</h3>
                    </div>
                    <div className="ribbon-card" style={{ flex: 1, minWidth: '220px', background: 'var(--bg-card)', border: '1px solid var(--border-glow)', padding: '16px', borderRadius: '12px' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Highest Data Harvest</span>
                      <h3 style={{ fontSize: '15px', fontWeight: '700', marginTop: '12px', color: 'var(--warning)' }}>{getTopHarvesterDept()}</h3>
                    </div>
                  </div>

                  {/* Grid of Department Cards */}
                  <div className="rules-grid" style={{ marginBottom: '24px' }}>
                    {deptAnalytics.map((dept) => {
                      const avgRisk = parseFloat(dept.avg_risk_score || 0);
                      const maxRisk = parseInt(dept.max_risk_score || 0);
                      const isHighRisk = avgRisk >= 60 || maxRisk >= 75;
                      const isMedRisk = (avgRisk >= 30 && avgRisk < 60) || (maxRisk >= 40 && maxRisk < 75);
                      
                      return (
                        <div 
                          key={dept.department} 
                          className="rule-config-card" 
                          style={{
                            borderColor: isHighRisk 
                              ? 'rgba(239, 68, 68, 0.4)' 
                              : isMedRisk 
                                ? 'rgba(245, 158, 11, 0.4)' 
                                : 'var(--border-glow)'
                          }}
                        >
                          <div className="rule-card-header" style={{ marginBottom: '8px' }}>
                            <div>
                              <span className="rule-card-id" style={{ background: 'var(--primary-glow)', color: 'var(--text-primary)' }}>
                                {dept.employee_count} Employees
                              </span>
                              <h4 style={{ color: 'var(--text-primary)', marginTop: '8px', fontSize: '16px' }}>{dept.department || 'General'}</h4>
                            </div>
                            <span className="status-badge-indicator" style={{
                              backgroundColor: isHighRisk 
                                ? 'rgba(239, 68, 68, 0.15)' 
                                : isMedRisk 
                                  ? 'rgba(245, 158, 11, 0.15)' 
                                  : 'rgba(16, 185, 129, 0.15)',
                              color: isHighRisk ? 'var(--danger)' : isMedRisk ? 'var(--warning)' : 'var(--success)'
                            }}>
                              {isHighRisk ? 'Critical Risk' : isMedRisk ? 'Elevated' : 'Secured'}
                            </span>
                          </div>

                          <div className="rule-card-metrics" style={{ marginTop: '12px' }}>
                            {/* Horizontal Risk Bar */}
                            <div style={{ marginBottom: '14px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Avg Risk Score:</span>
                                <span style={{ fontWeight: 'bold', color: 'var(--text-primary)' }}>{Math.round(avgRisk)}/100</span>
                              </div>
                              <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                                <div style={{
                                  height: '100%',
                                  width: `${Math.max(avgRisk, 3)}%`,
                                  backgroundColor: isHighRisk ? 'var(--danger)' : isMedRisk ? 'var(--warning)' : 'var(--success)'
                                }} />
                              </div>
                            </div>

                            <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>Triggered Incidents:</span>
                              <span style={{ 
                                color: dept.incident_count > 0 ? 'var(--danger)' : 'var(--text-primary)', 
                                fontWeight: dept.incident_count > 0 ? 'bold' : 'normal' 
                              }}>
                                {dept.incident_count}
                              </span>
                            </div>

                            <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>Max Incident Risk:</span>
                              <span style={{ color: 'var(--text-primary)' }}>{maxRisk}</span>
                            </div>

                            <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>Sensitive Records Read:</span>
                              <span style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>{dept.total_records_accessed}</span>
                            </div>

                            <div className="metric-row" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', fontSize: '12px' }}>
                              <span style={{ color: 'var(--text-secondary)' }}>Total Audit Activities:</span>
                              <span style={{ color: 'var(--text-primary)' }}>{dept.total_actions}</span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Analytics Detail Data Table */}
                  <div className="incidents-card-log">
                    <div className="incidents-log-header">
                      <div>
                        <h3 style={{ color: 'var(--text-primary)' }}>Department Audit Log Matrix</h3>
                        <p>Detailed breakdown of access rates, data leak risks, and compliance levels by department.</p>
                      </div>
                      <button onClick={fetchDeptAnalytics} className="btn-actions-refresh">
                        Refresh Reporting
                      </button>
                    </div>

                    <div className="table-wrapper">
                      <table>
                        <thead>
                          <tr>
                            <th>Department</th>
                            <th>Active Members</th>
                            <th>Incident Violations</th>
                            <th>Average Risk Score</th>
                            <th>Peak Risk Score</th>
                            <th>Sensitive Records Read</th>
                            <th>Audit Transactions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {deptAnalytics.map((dept, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{dept.department || 'General'}</td>
                              <td style={{ color: 'var(--text-primary)' }}>{dept.employee_count}</td>
                              <td style={{ color: dept.incident_count > 0 ? 'var(--danger)' : 'var(--text-primary)', fontWeight: dept.incident_count > 0 ? 'bold' : 'normal' }}>
                                {dept.incident_count}
                              </td>
                              <td style={{ color: 'var(--text-primary)' }}>
                                <span className={`risk-score-pill`} style={{
                                  backgroundColor: parseFloat(dept.avg_risk_score) >= 60 ? 'rgba(239, 68, 68, 0.15)' : parseFloat(dept.avg_risk_score) >= 30 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                  color: parseFloat(dept.avg_risk_score) >= 60 ? '#fca5a5' : parseFloat(dept.avg_risk_score) >= 30 ? '#fcd34d' : '#a7f3d0'
                                }}>
                                  {Math.round(dept.avg_risk_score)}
                                </span>
                              </td>
                              <td style={{ color: 'var(--text-primary)' }}>{dept.max_risk_score}</td>
                              <td style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>{dept.total_records_accessed}</td>
                              <td style={{ color: 'var(--text-primary)' }}>{dept.total_actions}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              ) : (
                /* ================= POLICY RECOMMENDATIONS VIEW ================= */
                <div className="dept-analytics-panel animate-fade-in">
                  <div className="rules-config-header">
                    <h3 style={{ color: 'var(--text-primary)' }}>💡 Proactive Policy Recommendations</h3>
                    <p>AI-driven security enforcement policies automatically generated based on telemetry patterns, anomalous logins, and system configuration rules.</p>
                  </div>

                  <div className="rules-grid">
                    {recommendations.length === 0 ? (
                      <div className="no-incidents-placeholder" style={{ gridColumn: '1 / -1', padding: '40px 20px' }}>
                        <div className="no-incidents-placeholder-icon">💡</div>
                        <p style={{ fontWeight: 'bold', fontSize: '15px', color: 'var(--text-primary)' }}>System Fully Optimized</p>
                        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                          No active policy vulnerability recommendations generated. All configurations are aligned with current telemetry.
                        </p>
                      </div>
                    ) : (
                      recommendations.map((rec) => {
                        const isHigh = rec.severity === 'High' || rec.severity === 'Critical';
                        return (
                          <div 
                            key={rec.id} 
                            className="rule-config-card"
                            style={{
                              borderColor: isHigh ? 'rgba(239, 68, 68, 0.4)' : 'var(--border-glow)',
                              display: 'flex',
                              flexDirection: 'column',
                              justifyContent: 'space-between'
                            }}
                          >
                            <div>
                              <div className="rule-card-header" style={{ marginBottom: '12px' }}>
                                <div>
                                  <span className="rule-card-id" style={{ background: 'var(--primary-glow)', color: 'var(--text-primary)' }}>{rec.id}</span>
                                  <h4 style={{ color: 'var(--text-primary)', marginTop: '8px', fontSize: '15px' }}>{rec.title}</h4>
                                </div>
                                <span className="status-badge-indicator" style={{
                                  backgroundColor: rec.severity === 'Critical' 
                                    ? 'rgba(239, 68, 68, 0.2)' 
                                    : rec.severity === 'High' 
                                      ? 'rgba(239, 68, 68, 0.15)' 
                                      : 'rgba(245, 158, 11, 0.15)',
                                  color: isHigh ? 'var(--danger)' : 'var(--warning)'
                                }}>
                                  {rec.severity} Priority
                                </span>
                              </div>

                              <p className="rule-card-desc" style={{ color: 'var(--text-secondary)', fontSize: '12px', marginBottom: '16px' }}>
                                {rec.description}
                              </p>
                            </div>

                            <div style={{ marginTop: 'auto' }}>
                              {user.role === 'System Administrator' ? (
                                <button
                                  onClick={() => handleApplyRecommendation(rec)}
                                  className="btn-primary-action"
                                  style={{ width: '100%', padding: '10px', fontSize: '12px', borderRadius: '8px' }}
                                >
                                  ⚡ Apply Policy Recommendation
                                </button>
                              ) : (
                                <div style={{ 
                                  textAlign: 'center', 
                                  fontSize: '11px', 
                                  color: 'var(--text-muted)', 
                                  padding: '8px', 
                                  background: 'rgba(255,255,255,0.02)',
                                  borderRadius: '6px',
                                  border: '1px dashed var(--border-glow)' 
                                }}>
                                  Requires Admin permissions to apply
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          /* ================= HR DEMO APPLICATION WORKSPACE ================= */
          <div className="workspace-container animate-fade-in">
            <aside className="nav-sidebar">
              <div className="nav-menu">
                <span className="menu-header">HR Modules</span>
                <button 
                  onClick={() => setActiveTab('employees')}
                  className={`menu-item-btn ${activeTab === 'employees' ? 'active' : ''}`}
                >
                  👥 Employee Directory
                </button>
                <button 
                  onClick={() => setActiveTab('leaves')}
                  className={`menu-item-btn ${activeTab === 'leaves' ? 'active' : ''}`}
                >
                  📝 Leave Requests
                </button>
              </div>

              {/* Simulator trigger controls box */}
              <div className="simulator-widget">
                <span className="menu-header" style={{ color: '#f87171' }}>🚨 Threat Simulator Console</span>
                
                <button
                  onClick={simulateScraping}
                  disabled={isScraping}
                  className="btn-simulate-threat"
                >
                  {isScraping ? 'Scraping...' : 'Simulate Volumetric Scrape'}
                </button>
                
                <button
                  onClick={simulateImpossibleTravel}
                  className="btn-simulate-threat"
                >
                  Simulate Impossible Travel
                </button>

                <div className="client-status-card">
                  <span>Simulated Context:</span>
                  <div>📍 Location: <strong style={{ color: 'var(--text-primary)' }}>{simLocation}</strong></div>
                  <div>📡 Proxy: <strong style={{ color: 'var(--text-primary)' }}>Inactive</strong></div>
                </div>
              </div>
            </aside>

            {/* Workspace screen contents */}
            <section className="view-frame">
              {activeTab === 'employees' && (
                <div>
                  <div className="view-title-block" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                    <div>
                      <h3 style={{ color: 'var(--text-primary)' }}>Employee Directory</h3>
                      <p>View basic employee directories. Sensitive salary column fields are dynamically masked under dynamic privacy shielding.</p>
                    </div>
                    {(user.role === 'HR Manager' || user.role === 'System Administrator') && (
                      <button 
                        onClick={() => setShowAddEmployeeForm(true)}
                        className="btn-primary-action"
                        style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                      >
                        <span>➕</span> Add Employee
                      </button>
                    )}
                  </div>



                  <div className="table-wrapper">
                    <table>
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Department</th>
                          <th>Position</th>
                          <th>Hire Date</th>
                          <th>Sensitive Salary</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {employees.map((emp) => (
                          <tr key={emp.id} style={emp.is_canary ? { backgroundColor: 'rgba(239, 68, 68, 0.03)' } : {}}>
                            <td style={{ fontWeight: '700', color: 'var(--text-primary)' }}>
                              {emp.first_name} {emp.last_name}
                              {emp.is_canary && (
                                <span className="honeypot-badge">
                                  Honeypot Decoy
                                </span>
                              )}
                            </td>
                            <td style={{ color: 'var(--text-secondary)' }}>{emp.department}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{emp.position}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{new Date(emp.hire_date).toLocaleDateString()}</td>
                            <td className="salary-val-sensitive">
                              {salaryMap[emp.id] ? (
                                <span className="visible">${parseFloat(salaryMap[emp.id]).toLocaleString()}</span>
                              ) : (
                                <span style={{ color: 'var(--text-secondary)' }}>{emp.salary}</span>
                              )}
                            </td>
                            <td>
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <button 
                                  onClick={() => fetchSensitiveSalary(emp.id)}
                                  className="btn-salary-unlock"
                                  style={{ color: 'var(--text-primary)' }}
                                >
                                  {salaryMap[emp.id] ? 'Hide Salary' : 'Query Salary'}
                                </button>
                                {(user.role === 'HR Manager' || user.role === 'System Administrator') && !emp.is_canary && (
                                  <button 
                                    onClick={() => handleRemoveEmployee(emp.id, `${emp.first_name} ${emp.last_name}`)}
                                    className="btn-action-danger"
                                    style={{ padding: '6px 12px', fontSize: '11px', borderRadius: '6px', cursor: 'pointer' }}
                                  >
                                    Remove
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'leaves' && (
                <div>
                  <div className="view-title-block">
                    <h3 style={{ color: 'var(--text-primary)' }}>
                      {user.role === 'HR Manager' || user.role === 'System Administrator' 
                        ? 'Leave Request Management' 
                        : 'My Leave Requests'}
                    </h3>
                    <p>
                      {user.role === 'HR Manager' || user.role === 'System Administrator'
                        ? 'Approve or reject leave requests submitted by staff members.'
                        : 'Submit a new leave request and track its approval status.'}
                    </p>
                  </div>

                  {/* If Employee, show Request Leave Form */}
                  {!(user.role === 'HR Manager' || user.role === 'System Administrator') && (
                    <div className="leave-form-card" style={{ marginBottom: '24px', padding: '24px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-glow)', borderRadius: '16px' }}>
                      <h4 style={{ color: 'var(--text-primary)', marginBottom: '16px', fontSize: '14px', fontWeight: '800' }}>Request New Leave</h4>
                      <form onSubmit={handleRequestLeave} style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'flex-end' }}>
                        <div style={{ flex: '1 1 200px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>Leave Type</label>
                          <select 
                            value={leaveType} 
                            onChange={(e) => setLeaveType(e.target.value)}
                            style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-glow)', backgroundColor: 'var(--bg-input)', color: 'var(--text-primary)', outline: 'none' }}
                          >
                            <option value="Annual Leave">Annual Leave</option>
                            <option value="Sick Leave">Sick Leave</option>
                            <option value="Casual Leave">Casual Leave</option>
                            <option value="Maternity Leave">Maternity Leave</option>
                          </select>
                        </div>
                        <div style={{ flex: '1 1 150px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>Start Date</label>
                          <input 
                            type="date" 
                            value={startDate} 
                            onChange={(e) => setStartDate(e.target.value)}
                            required
                            style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-glow)', backgroundColor: 'var(--bg-input)', color: 'var(--text-primary)', outline: 'none' }}
                          />
                        </div>
                        <div style={{ flex: '1 1 150px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>End Date</label>
                          <input 
                            type="date" 
                            value={endDate} 
                            onChange={(e) => setEndDate(e.target.value)}
                            required
                            style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-glow)', backgroundColor: 'var(--bg-input)', color: 'var(--text-primary)', outline: 'none' }}
                          />
                        </div>
                        <div style={{ flex: '1 1 100%', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>Reason</label>
                          <textarea 
                            value={reason} 
                            onChange={(e) => setReason(e.target.value)}
                            required
                            placeholder="Enter description/reason for leave..."
                            style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-glow)', backgroundColor: 'var(--bg-input)', color: 'var(--text-primary)', minHeight: '80px', resize: 'vertical', outline: 'none' }}
                          />
                        </div>
                        <button 
                          type="submit" 
                          className="btn-mitigation-unlock"
                          style={{ background: 'var(--primary)', color: 'white', padding: '12px 24px', fontSize: '12px', border: 'none', borderRadius: '8px', cursor: 'pointer', fontWeight: '700' }}
                        >
                          Submit Leave Request
                        </button>
                      </form>
                    </div>
                  )}

                  <div className="table-wrapper">
                    <table>
                      <thead>
                        <tr>
                          <th>Employee</th>
                          <th>Leave Type</th>
                          <th>Start Date</th>
                          <th>End Date</th>
                          <th>Reason</th>
                          <th>Status</th>
                          {(user.role === 'HR Manager' || user.role === 'System Administrator') && <th>Actions</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {leaves.map((l) => (
                          <tr key={l.id}>
                            <td style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{l.employee_name}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{l.leave_type}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{new Date(l.start_date).toLocaleDateString()}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{new Date(l.end_date).toLocaleDateString()}</td>
                            <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{l.reason}</td>
                            <td>
                              <span className={`status-indicator ${l.status.toLowerCase()}`}>
                                {l.status}
                              </span>
                            </td>
                            {(user.role === 'HR Manager' || user.role === 'System Administrator') && (
                              <td>
                                {l.status === 'Pending' && (
                                  <div style={{ display: 'flex', gap: '8px' }}>
                                    <button 
                                      onClick={() => handleLeaveDecision(l.id, 'Approved')}
                                      className="btn-action-success"
                                    >
                                      Approve
                                    </button>
                                    <button 
                                      onClick={() => handleLeaveDecision(l.id, 'Rejected')}
                                      className="btn-action-danger"
                                    >
                                      Reject
                                    </button>
                                  </div>
                                )}
                              </td>
                            )}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="footer">
        <span>© 2026 DataLens HR.</span>
        {token && <span>Secure Session Audit Active (RBAC Level {user ? user.role : 'Guest'})</span>}
      </footer>

      {/* Add Employee Modal Overlay (Rendered at root to avoid stacking context issues with main container) */}
      {showAddEmployeeForm && (user.role === 'HR Manager' || user.role === 'System Administrator') && (
        <div 
          className="modal-backdrop" 
          onClick={(e) => {
            if (e.target.className === 'modal-backdrop') {
              setShowAddEmployeeForm(false);
            }
          }}
        >
          <div className="modal-card animate-scale-up">
            <div className="modal-header">
              <h3>Add New Employee</h3>
              <button 
                onClick={() => setShowAddEmployeeForm(false)} 
                className="btn-close"
                aria-label="Close modal"
              >
                &times;
              </button>
            </div>
            <form onSubmit={handleAddEmployee} className="modal-form">
              <div className="form-group">
                <label>First Name</label>
                <input 
                  type="text" 
                  placeholder="e.g. Emma"
                  value={newEmpFirstName} 
                  onChange={(e) => setNewEmpFirstName(e.target.value)} 
                  className="form-input-field" 
                  required 
                />
              </div>
              <div className="form-group">
                <label>Last Name</label>
                <input 
                  type="text" 
                  placeholder="e.g. Watson"
                  value={newEmpLastName} 
                  onChange={(e) => setNewEmpLastName(e.target.value)} 
                  className="form-input-field" 
                  required 
                />
              </div>
              <div className="form-group full-width">
                <label>Email Address</label>
                <input 
                  type="email" 
                  placeholder="emma.watson@datalenshr.com"
                  value={newEmpEmail} 
                  onChange={(e) => setNewEmpEmail(e.target.value)} 
                  className="form-input-field" 
                  required 
                />
              </div>
              <div className="form-group">
                <label>Department</label>
                <select 
                  value={newEmpDepartment} 
                  onChange={(e) => setNewEmpDepartment(e.target.value)} 
                  className="form-input-field"
                  style={{ paddingRight: '32px' }}
                >
                  <option value="IT">IT</option>
                  <option value="HR">HR</option>
                  <option value="Sales">Sales</option>
                  <option value="Operations">Operations</option>
                  <option value="Executive">Executive</option>
                </select>
              </div>
              <div className="form-group">
                <label>Position Title</label>
                <input 
                  type="text" 
                  placeholder="e.g. HR Director"
                  value={newEmpPosition} 
                  onChange={(e) => setNewEmpPosition(e.target.value)} 
                  className="form-input-field" 
                  required 
                />
              </div>
              <div className="form-group">
                <label>Sensitive Annual Salary ($)</label>
                <input 
                  type="number" 
                  placeholder="e.g. 185000"
                  value={newEmpSalary} 
                  onChange={(e) => setNewEmpSalary(e.target.value)} 
                  className="form-input-field" 
                  required 
                />
              </div>
              <div className="form-group">
                <label>Hire Date</label>
                <input 
                  type="date" 
                  value={newEmpHireDate} 
                  onChange={(e) => setNewEmpHireDate(e.target.value)} 
                  className="form-input-field" 
                  required 
                />
              </div>
              <div className="modal-actions">
                <button 
                  type="button" 
                  onClick={() => setShowAddEmployeeForm(false)} 
                  className="btn-mitigation-dismiss"
                  style={{ color: 'var(--text-primary)', border: '1px solid var(--border-glow)' }}
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn-primary-action"
                >
                  Add Employee
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
