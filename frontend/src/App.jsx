import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import {
  Shield,
  ShieldCheck,
  BarChart3,
  Sliders,
  Lightbulb,
  Users,
  Calendar,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Lock,
  Unlock,
  RefreshCw,
  Search,
  MapPin,
  Plus,
  X,
  Eye,
  EyeOff,
  Sun,
  Moon,
  LogOut,
  Activity,
  FileText,
  ChevronDown,
  ChevronUp,
  Zap,
  Building2,
  UserCheck,
  User,
  Radio,
  Clock,
  RotateCcw,
  Check,
  Info
} from 'lucide-react';
import './App.css';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

// ================= REUSABLE EMPTY & LOADING COMPONENTS =================

// Reusable Loading State Component
function LoadingState({ message = 'Loading employee analytics...', subtitle, compact = false }) {
  return (
    <div className={`loading-state-container ${compact ? 'compact' : ''}`}>
      <div className="loading-spinner-box">
        <div className="loading-spinner" />
        <div className="loading-spinner-glow" />
      </div>
      <p className="loading-state-title">{message}</p>
      {subtitle && <p className="loading-state-subtext">{subtitle}</p>}
    </div>
  );
}

// Reusable Empty State Component
function EmptyState({ icon, title = 'No data available yet', description = 'No employee activity has been recorded for this period.', actionText, onAction }) {
  return (
    <div className="empty-state-wrapper">
      <div className="empty-icon-circle">
        {icon || <BarChart3 size={32} color="var(--primary)" />}
      </div>
      <h4 className="empty-state-title">{title}</h4>
      <p className="empty-state-desc">{description}</p>
      {actionText && onAction && (
        <button onClick={onAction} className="btn-empty-action">
          {actionText}
        </button>
      )}
    </div>
  );
}

// Reusable Search / Filter Zero Results State Component with Dynamic Query Feedback
function NoResultsState({ 
  title = 'No results found', 
  query = '', 
  entity = 'records',
  description, 
  onClear 
}) {
  const displayDesc = description || (
    query 
      ? `No ${entity} match "${query}". Try adjusting your search or filters.`
      : `No ${entity} match the selected filter criteria. Try adjusting your filters.`
  );

  return (
    <div className="no-results-container">
      <div className="no-results-badge">
        <Search size={22} color="var(--primary)" />
      </div>
      <h4 className="no-results-title">{title}</h4>
      <p className="no-results-desc">{displayDesc}</p>
      {onClear && (
        <button onClick={onClear} className="btn-clear-filters" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
          <RotateCcw size={13} /> Clear Filters
        </button>
      )}
    </div>
  );
}

// Skeleton Table Loader Rows
function SkeletonTableRows({ columns = 6, rows = 4 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, rIdx) => (
        <tr key={rIdx} className="skeleton-row">
          {Array.from({ length: columns }).map((_, cIdx) => (
            <td key={cIdx}>
              <div 
                className="skeleton-bar" 
                style={{ 
                  width: cIdx === 0 ? '70%' : cIdx === columns - 1 ? '40%' : `${50 + (cIdx * 13) % 40}%` 
                }} 
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

// Skeleton Card Component
function SkeletonCard({ height = '120px' }) {
  return (
    <div className="skeleton-card" style={{ minHeight: height }}>
      <div className="skeleton-card-header">
        <div className="skeleton-bar" style={{ width: '45%', height: '14px' }} />
        <div className="skeleton-bar" style={{ width: '24px', height: '24px', borderRadius: '50%' }} />
      </div>
      <div className="skeleton-card-body">
        <div className="skeleton-bar" style={{ width: '65%', height: '26px' }} />
        <div className="skeleton-bar" style={{ width: '80%', height: '12px' }} />
      </div>
    </div>
  );
}

// Skeleton Chart Component with Progress Columns
function SkeletonChart({ message = 'Loading security analytics...', subtitle }) {
  return (
    <div className="skeleton-chart-container">
      <div className="skeleton-chart-header">
        <div className="loading-spinner-box" style={{ width: '28px', height: '28px', minWidth: '28px' }}>
          <div className="loading-spinner" style={{ width: '22px', height: '22px', borderWidth: '2.5px' }} />
          <div className="loading-spinner-glow" />
        </div>
        <div>
          <p className="loading-state-title" style={{ margin: 0, fontSize: '13.5px', fontWeight: '700', textAlign: 'left' }}>{message}</p>
          {subtitle && <p className="loading-state-subtext" style={{ margin: '2px 0 0 0', fontSize: '11px', textAlign: 'left' }}>{subtitle}</p>}
        </div>
      </div>
      
      <div className="skeleton-chart-bars">
        {[80, 50, 65, 90, 35].map((val, idx) => (
          <div key={idx} className="skeleton-chart-bar-item">
            <div className="skeleton-chart-bar-header">
              <div className="skeleton-bar" style={{ width: `${30 + idx * 9}%`, height: '11px' }} />
              <div className="skeleton-bar" style={{ width: '18%', height: '11px' }} />
            </div>
            <div className="skeleton-bar" style={{ width: `${val}%`, height: '8px' }} />
          </div>
        ))}
      </div>
    </div>
  );
}

// Heuristic Detection Rule Explanatory Metadata for Tooltips and Visualizations
const RULE_METADATA = {
  CANARY_ACCESS: {
    label: 'Canary Decoy Access',
    shortName: 'Canary Decoy Access',
    code: 'R-01',
    description: 'High-severity detection triggered when an unauthorized user queries masked honeypot employee accounts.'
  },
  IMPOSSIBLE_TRAVEL: {
    label: 'Impossible Travel Velocity',
    shortName: 'Impossible Travel',
    code: 'R-03',
    description: 'Flags login sessions originating from geographically distant regions faster than supersonic transport velocities.'
  },
  AFTER_HOURS_ACCESS: {
    label: 'After-Hours Access',
    shortName: 'After-Hours Access',
    code: 'R-02',
    description: 'Monitors database queries and employee unmasking executed during restricted overnight timeframes (11 PM - 5 AM).'
  },
  MASS_PROFILE_READS: {
    label: 'Volumetric Profile Scrape',
    shortName: 'Volumetric Scrape',
    code: 'R-05',
    description: 'Alerts when rapid bulk employee directory scraping exceeds the configured threshold (> 10 records / 10s).'
  },
  ANOMALOUS_SALARY_VIEW: {
    label: 'Unauthorized Salary Read',
    shortName: 'Unauthorized Salary Read',
    code: 'R-04',
    description: 'Detects unauthorized attempts by non-privileged accounts to unmask confidential executive compensation.'
  }
};

function App() {
  // Session States
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user')) || null);
  
  // Theme State (Defaulting to light mode for brighter view)
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  
  // Unified Navigation & Data States: 'dashboard', 'analytics', 'rules', 'recommendations', 'employees', 'leaves'
  const [activeTab, setActiveTab] = useState(() => {
    const savedUser = JSON.parse(localStorage.getItem('user')) || null;
    if (savedUser && (savedUser.role === 'System Administrator' || savedUser.role === 'HR Manager')) {
      return 'dashboard';
    }
    return 'employees';
  });
  const [employees, setEmployees] = useState([]);
  const [leaves, setLeaves] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  
  // Loading States for All Modules
  const [isLoadingEmployees, setIsLoadingEmployees] = useState(false);
  const [isLoadingLeaves, setIsLoadingLeaves] = useState(false);
  const [isLoadingIncidents, setIsLoadingIncidents] = useState(false);
  const [isLoadingRules, setIsLoadingRules] = useState(false);
  const [isLoadingAnalytics, setIsLoadingAnalytics] = useState(false);
  const [isLoadingRecommendations, setIsLoadingRecommendations] = useState(false);
  
  // Rule Management States
  const [rules, setRules] = useState([]);
  const [editingRule, setEditingRule] = useState(null);
  const [editWeight, setEditWeight] = useState(0);
  const [editIsEnabled, setEditIsEnabled] = useState(true);
  const [editParams, setEditParams] = useState({});
  
  // Department Analytics States
  const [deptAnalytics, setDeptAnalytics] = useState([]);
  
  // Proactive Recommendations States
  const [recommendations, setRecommendations] = useState([]);
  
  // Custom Simulator / Context Headers
  const [simLocation, setSimLocation] = useState('Colombo, Sri Lanka');
  const [isScraping, setIsScraping] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isSimulatorCollapsed, setIsSimulatorCollapsed] = useState(window.innerWidth < 768);

  // Dashboard Interactive Filter & Search States
  const [alertFilter, setAlertFilter] = useState('all'); // 'all', 'open', 'high', 'resolved'
  const [alertSearch, setAlertSearch] = useState('');
  const [expandedIncidents, setExpandedIncidents] = useState({});

  // Employee Directory Filter & Search States
  const [empSearch, setEmpSearch] = useState('');
  const [empDeptFilter, setEmpDeptFilter] = useState('all');

  // Leave Management Filter & Search States
  const [leaveSearch, setLeaveSearch] = useState('');
  const [leaveStatusFilter, setLeaveStatusFilter] = useState('all');

  const toggleIncidentExpand = (id) => {
    setExpandedIncidents(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Forms State & Touched Tracking for Real-Time Inline Validation
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loginTouched, setLoginTouched] = useState({ email: false, password: false });
  
  // Leave request form states
  const [leaveType, setLeaveType] = useState('Annual Leave');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [reason, setReason] = useState('');
  const [leaveTouched, setLeaveTouched] = useState({});
  
  // Add employee form states
  const [showAddEmployeeForm, setShowAddEmployeeForm] = useState(false);
  const [newEmpFirstName, setNewEmpFirstName] = useState('');
  const [newEmpLastName, setNewEmpLastName] = useState('');
  const [newEmpEmail, setNewEmpEmail] = useState('');
  const [newEmpDepartment, setNewEmpDepartment] = useState('IT');
  const [newEmpPosition, setNewEmpPosition] = useState('');
  const [newEmpSalary, setNewEmpSalary] = useState('');
  const [newEmpHireDate, setNewEmpHireDate] = useState('');
  const [empFormTouched, setEmpFormTouched] = useState({});
  
  // Rule edit form touched
  const [ruleTouched, setRuleTouched] = useState({});
  
  // Salary state tracking
  const [salaryMap, setSalaryMap] = useState({}); 

  // ================= FORM VALIDATION HELPERS =================
  const getLoginErrors = () => {
    const errors = {};
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!loginEmail.trim()) {
      errors.email = 'Email address is required.';
    } else if (!emailRegex.test(loginEmail.trim())) {
      errors.email = 'Please enter a valid email address (e.g. name@datalenshr.com).';
    }
    if (!loginPassword) {
      errors.password = 'Password is required.';
    } else if (loginPassword.length < 6) {
      errors.password = 'Password must be at least 6 characters.';
    }
    return errors;
  };

  const getEmpFormErrors = () => {
    const errors = {};
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!newEmpFirstName.trim()) {
      errors.first_name = 'First name is required.';
    } else if (newEmpFirstName.trim().length < 2) {
      errors.first_name = 'First name must be at least 2 characters.';
    }
    if (!newEmpLastName.trim()) {
      errors.last_name = 'Last name is required.';
    } else if (newEmpLastName.trim().length < 2) {
      errors.last_name = 'Last name must be at least 2 characters.';
    }
    if (!newEmpEmail.trim()) {
      errors.email = 'Email address is required.';
    } else if (!emailRegex.test(newEmpEmail.trim())) {
      errors.email = 'Please enter a valid email address (e.g. user@datalenshr.com).';
    }
    if (!newEmpPosition.trim()) {
      errors.position = 'Position title is required.';
    } else if (newEmpPosition.trim().length < 2) {
      errors.position = 'Position title must be at least 2 characters.';
    }
    if (!newEmpSalary) {
      errors.salary = 'Annual salary is required.';
    } else if (isNaN(newEmpSalary) || Number(newEmpSalary) <= 0) {
      errors.salary = 'Please enter a valid salary greater than $0.';
    }
    if (!newEmpHireDate) {
      errors.hire_date = 'Hire date is required.';
    }
    return errors;
  };

  const getLeaveFormErrors = () => {
    const errors = {};
    if (!startDate) {
      errors.startDate = 'Start date is required.';
    }
    if (!endDate) {
      errors.endDate = 'End date is required.';
    } else if (startDate && endDate && new Date(endDate) < new Date(startDate)) {
      errors.endDate = 'End date cannot be earlier than start date.';
    }
    if (!reason.trim()) {
      errors.reason = 'Reason for leave is required.';
    } else if (reason.trim().length < 5) {
      errors.reason = 'Please provide a descriptive reason of at least 5 characters.';
    }
    return errors;
  };

  const getRuleErrors = () => {
    const errors = {};
    if (editWeight < 1 || editWeight > 100) {
      errors.weight = 'Weight must be between 1 and 100 points.';
    }
    if (editParams.start_hour !== undefined && (isNaN(editParams.start_hour) || editParams.start_hour < 0 || editParams.start_hour > 23)) {
      errors.start_hour = 'Start hour must be between 0 and 23.';
    }
    if (editParams.end_hour !== undefined && (isNaN(editParams.end_hour) || editParams.end_hour < 0 || editParams.end_hour > 23)) {
      errors.end_hour = 'End hour must be between 0 and 23.';
    }
    if (editParams.limit !== undefined && (isNaN(editParams.limit) || editParams.limit < 1)) {
      errors.limit = 'Profile reads threshold must be at least 1 record.';
    }
    if (editParams.window_ms !== undefined && (isNaN(editParams.window_ms) || editParams.window_ms < 1000)) {
      errors.window_ms = 'Window must be at least 1000ms (1 second).';
    }
    return errors;
  };

  // Keyboard Escape Handler for Modals, Drawers, and Overlays
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (showAddEmployeeForm) setShowAddEmployeeForm(false);
        if (editingRule) setEditingRule(null);
        if (isMobileMenuOpen) setIsMobileMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showAddEmployeeForm, editingRule, isMobileMenuOpen]);

  // Establish WebSockets Connection for security updates
  useEffect(() => {
    const backendUrl = import.meta.env.VITE_API_URL ? import.meta.env.VITE_API_URL.replace('/api', '') : 'http://localhost:5000';
    const socket = io(backendUrl);

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
    setIsLoadingEmployees(true);
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
    } finally {
      setIsLoadingEmployees(false);
    }
  };

  // API Call: Fetch Leaves
  const fetchLeaves = async () => {
    setIsLoadingLeaves(true);
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
    } finally {
      setIsLoadingLeaves(false);
    }
  };

  // API Call: Fetch Security Incidents
  const fetchIncidents = async () => {
    setIsLoadingIncidents(true);
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
    } finally {
      setIsLoadingIncidents(false);
    }
  };

  // API Call: Fetch Privacy Detection Rules
  const fetchRules = async () => {
    setIsLoadingRules(true);
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
    } finally {
      setIsLoadingRules(false);
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
    setIsLoadingRecommendations(true);
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
    } finally {
      setIsLoadingRecommendations(false);
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

  // Helper: Filter Incidents by Status and Search Query
  const getFilteredIncidents = () => {
    return incidents.filter(inc => {
      // Status filter
      if (alertFilter === 'open' && inc.status !== 'Open') return false;
      if (alertFilter === 'high' && (inc.risk_level !== 'High' || inc.status !== 'Open')) return false;
      if (alertFilter === 'resolved' && inc.status === 'Open') return false;

      // Search query
      if (alertSearch.trim()) {
        const query = alertSearch.toLowerCase();
        const emailMatch = (inc.user_email || '').toLowerCase().includes(query);
        const roleMatch = (inc.user_role || '').toLowerCase().includes(query);
        const rules = Array.isArray(inc.triggered_rules) ? inc.triggered_rules : JSON.parse(inc.triggered_rules || '[]');
        const ruleMatch = rules.some(r => r.toLowerCase().includes(query));
        const evidence = typeof inc.raw_evidence === 'object' ? inc.raw_evidence : JSON.parse(inc.raw_evidence || '{}');
        const cityMatch = (evidence.metadata?.city || '').toLowerCase().includes(query);
        const ipMatch = (evidence.metadata?.ip || '').toLowerCase().includes(query);
        return emailMatch || roleMatch || ruleMatch || cityMatch || ipMatch;
      }
      return true;
    });
  };

  // Helper: Filter Employees by Department and Search Query
  const getFilteredEmployees = () => {
    return employees.filter(emp => {
      if (empDeptFilter !== 'all' && emp.department !== empDeptFilter) return false;
      if (empSearch.trim()) {
        const query = empSearch.toLowerCase();
        const fullName = `${emp.first_name || ''} ${emp.last_name || ''}`.toLowerCase();
        const emailMatch = (emp.email || '').toLowerCase().includes(query);
        const deptMatch = (emp.department || '').toLowerCase().includes(query);
        const posMatch = (emp.position || '').toLowerCase().includes(query);
        return fullName.includes(query) || emailMatch || deptMatch || posMatch;
      }
      return true;
    });
  };

  // Helper: Filter Leaves by Status and Search Query
  const getFilteredLeaves = () => {
    return leaves.filter(l => {
      if (leaveStatusFilter !== 'all' && l.status !== leaveStatusFilter) return false;
      if (leaveSearch.trim()) {
        const query = leaveSearch.toLowerCase();
        const empMatch = (l.employee_name || '').toLowerCase().includes(query);
        const typeMatch = (l.leave_type || '').toLowerCase().includes(query);
        const reasonMatch = (l.reason || '').toLowerCase().includes(query);
        return empMatch || typeMatch || reasonMatch;
      }
      return true;
    });
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
    setLoginTouched({ email: true, password: true });
    const errors = getLoginErrors();
    if (Object.keys(errors).length > 0) {
      return;
    }
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
      
      // Auto-route to Security Dashboard if admin/manager, else employee directory
      if (data.user.role === 'System Administrator' || data.user.role === 'HR Manager') {
        setActiveTab('dashboard');
      } else {
        setActiveTab('employees');
      }
    } catch (err) {
      setErrorMessage(err.message);
    }
  };

  // Autofill Helper
  const handleAutofill = (email) => {
    setLoginEmail(email);
    setLoginPassword('admin123');
    setLoginTouched({ email: true, password: true });
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
    setEmpFormTouched({
      first_name: true,
      last_name: true,
      email: true,
      position: true,
      salary: true,
      hire_date: true
    });
    const errors = getEmpFormErrors();
    if (Object.keys(errors).length > 0) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/employees`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          first_name: newEmpFirstName.trim(),
          last_name: newEmpLastName.trim(),
          email: newEmpEmail.trim(),
          department: newEmpDepartment,
          position: newEmpPosition.trim(),
          salary: Number(newEmpSalary),
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
        setEmpFormTouched({});
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
    setLeaveTouched({
      startDate: true,
      endDate: true,
      reason: true
    });
    const errors = getLeaveFormErrors();
    if (Object.keys(errors).length > 0) {
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
          reason: reason.trim()
        })
      });

      if (response.ok) {
        alert('Leave request submitted successfully!');
        setStartDate('');
        setEndDate('');
        setReason('');
        setLeaveTouched({});
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
    setActiveTab('employees');
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
        setActiveTab('dashboard');
      }
      alert('Simulation completed! Redirecting you to the Security Dashboard to view the active Volumetric Scrape alert.');
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
          setActiveTab('dashboard');
        }
        alert('Impossible travel threat simulated! Redirecting you to the Security Dashboard to view the active alert.');
      } else {
        const data = await response.json();
        alert(data.message || 'Simulation failed');
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Breadcrumbs & View Meta Helper
  const getPageBreadcrumb = () => {
    switch (activeTab) {
      case 'dashboard':
        return { category: 'Security Intelligence', title: 'Security Dashboard', icon: <Shield size={16} /> };
      case 'analytics':
        return { category: 'Security Intelligence', title: 'Department Privacy Analytics', icon: <BarChart3 size={16} /> };
      case 'rules':
        return { category: 'Security Intelligence', title: 'Privacy Detection Rules', icon: <Sliders size={16} /> };
      case 'recommendations':
        return { category: 'Security Intelligence', title: 'Proactive Policy Advisor', icon: <Lightbulb size={16} /> };
      case 'employees':
        return { category: 'HR Operations', title: 'Employee Directory', icon: <Users size={16} /> };
      case 'leaves':
        return { category: 'HR Operations', title: (user?.role === 'HR Manager' || user?.role === 'System Administrator') ? 'Leave Management' : 'My Leave Requests', icon: <Calendar size={16} /> };
      default:
        return { category: 'Overview', title: 'Security Dashboard', icon: <Shield size={16} /> };
    }
  };

  return (
    <div className={`app-layout ${theme === 'dark' ? 'dark-theme' : 'light-theme'}`}>
      {!token ? (
        <>
          {/* Unauthenticated Navbar header */}
          <header className="navbar login-navbar">
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
              <button 
                onClick={toggleTheme}
                className="btn-signout"
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                {theme === 'dark' ? <><Sun size={14} /> Light Mode</> : <><Moon size={14} /> Dark Mode</>}
              </button>
            </div>
          </header>

          {/* Login Portal View */}
          <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
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
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>Click or navigate with Tab/Enter to automatically load credentials:</p>
                  <div className="demo-pills-container">
                    <div 
                      className="demo-pill" 
                      tabIndex={0}
                      role="button"
                      aria-label="Autofill System Administrator credentials"
                      onClick={() => handleAutofill('admin@datalenshr.com')}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleAutofill('admin@datalenshr.com'); } }}
                    >
                      <span className="demo-pill-title" style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <UserCheck size={13} color="var(--primary)" /> System Administrator (Full Access)
                      </span>
                      <span className="demo-pill-email">admin@datalenshr.com</span>
                    </div>
                    <div 
                      className="demo-pill" 
                      tabIndex={0}
                      role="button"
                      aria-label="Autofill HR Manager credentials"
                      onClick={() => handleAutofill('manager@datalenshr.com')}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleAutofill('manager@datalenshr.com'); } }}
                    >
                      <span className="demo-pill-title" style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <UserCheck size={13} color="var(--primary)" /> HR Manager (Privileged HR)
                      </span>
                      <span className="demo-pill-email">manager@datalenshr.com</span>
                    </div>
                    <div 
                      className="demo-pill" 
                      tabIndex={0}
                      role="button"
                      aria-label="Autofill HR Staff credentials"
                      onClick={() => handleAutofill('staff@datalenshr.com')}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleAutofill('staff@datalenshr.com'); } }}
                    >
                      <span className="demo-pill-title" style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <UserCheck size={13} color="var(--primary)" /> HR Staff (General Access)
                      </span>
                      <span className="demo-pill-email">staff@datalenshr.com</span>
                    </div>
                    <div 
                      className="demo-pill" 
                      tabIndex={0}
                      role="button"
                      aria-label="Autofill Employee credentials"
                      onClick={() => handleAutofill('employee@datalenshr.com')}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleAutofill('employee@datalenshr.com'); } }}
                    >
                      <span className="demo-pill-title" style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <UserCheck size={13} color="var(--primary)" /> Employee (Profile Owner Only)
                      </span>
                      <span className="demo-pill-email">employee@datalenshr.com</span>
                    </div>
                  </div>
                </div>

                {/* Simulation Environment Config */}
                <div className="sim-controller-card">
                  <h4 style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Sliders size={14} color="var(--primary)" /> Client Simulation Environment
                  </h4>
                  <div className="input-select-container">
                    <label htmlFor="sim-geo-select">Simulated Geolocation (IP-City Mapping):</label>
                    <select 
                      id="sim-geo-select"
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
                      <em>Impossible travel velocities and lockout triggers can now be simulated safely using the simulator console inside the dashboard.</em>
                    </p>
                  </div>
                </div>
              </div>

              {/* Login Box */}
              <div className="login-form-box">
                <h3 style={{ color: 'var(--text-primary)' }}>Secure Sign In</h3>
                <p className="login-subtitle">Authenticate credentials to initiate secure workspace audit log tracking.</p>
                
                {errorMessage && (
                  <div className="error-banner" role="alert" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '8px', padding: '14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <AlertTriangle size={16} color="var(--danger)" style={{ flexShrink: 0 }} />
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
                
                {(() => {
                  const loginErrors = getLoginErrors();
                  return (
                    <form onSubmit={handleLogin} noValidate>
                      <div className="input-field-group">
                        <label htmlFor="login-email-input" style={{ color: 'var(--text-primary)' }}>Email Address</label>
                        <input 
                          id="login-email-input"
                          type="email" 
                          required 
                          placeholder="name@datalenshr.com"
                          value={loginEmail}
                          aria-invalid={loginTouched.email && !!loginErrors.email}
                          aria-describedby={loginTouched.email && loginErrors.email ? "login-email-error" : undefined}
                          onBlur={() => setLoginTouched(prev => ({ ...prev, email: true }))}
                          onChange={(e) => {
                            setLoginEmail(e.target.value);
                            setLoginTouched(prev => ({ ...prev, email: true }));
                          }}
                          className={`text-input-field ${loginTouched.email && loginErrors.email ? 'input-error' : loginTouched.email && !loginErrors.email ? 'input-valid' : ''}`}
                        />
                        {loginTouched.email && loginErrors.email && (
                          <div className="field-error-msg" id="login-email-error" role="alert">
                            <span className="field-error-icon"><AlertTriangle size={12} /></span> {loginErrors.email}
                          </div>
                        )}
                      </div>
                      
                      <div className="input-field-group" style={{ marginTop: '12px' }}>
                        <label htmlFor="login-password-input" style={{ color: 'var(--text-primary)' }}>Password</label>
                        <div style={{ position: 'relative' }}>
                          <input 
                            id="login-password-input"
                            type={showPassword ? 'text' : 'password'} 
                            required 
                            placeholder="••••••••"
                            value={loginPassword}
                            aria-invalid={loginTouched.password && !!loginErrors.password}
                            aria-describedby={loginTouched.password && loginErrors.password ? "login-password-error" : undefined}
                            onBlur={() => setLoginTouched(prev => ({ ...prev, password: true }))}
                            onChange={(e) => {
                              setLoginPassword(e.target.value);
                              setLoginTouched(prev => ({ ...prev, password: true }));
                            }}
                            className={`text-input-field ${loginTouched.password && loginErrors.password ? 'input-error' : loginTouched.password && !loginErrors.password ? 'input-valid' : ''}`}
                            style={{ width: '100%', paddingRight: '45px' }}
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            aria-label={showPassword ? "Hide password text" : "Show password text"}
                            style={{
                              position: 'absolute',
                              right: '12px',
                              top: '50%',
                              transform: 'translateY(-50%)',
                              background: 'none',
                              border: 'none',
                              cursor: 'pointer',
                              color: 'var(--text-secondary)',
                              userSelect: 'none',
                              padding: '4px',
                              display: 'flex',
                              alignItems: 'center'
                            }}
                          >
                            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                          </button>
                        </div>
                        {loginTouched.password && loginErrors.password && (
                          <div className="field-error-msg" id="login-password-error" role="alert">
                            <span className="field-error-icon"><AlertTriangle size={12} /></span> {loginErrors.password}
                          </div>
                        )}
                      </div>

                      <button 
                        type="submit" 
                        className="btn-login-submit"
                        style={{ marginTop: '18px' }}
                      >
                        Sign In
                      </button>
                    </form>
                  );
                })()}
              </div>
            </div>
          </main>
        </>
      ) : (
        /* ================= AUTHENTICATED PERSISTENT WORKSPACE ================= */
        <div className="workspace-container animate-fade-in">
          {/* Mobile Overlay Backdrop */}
          {isMobileMenuOpen && (
            <div 
              className="sidebar-mobile-backdrop" 
              onClick={() => setIsMobileMenuOpen(false)}
            />
          )}

          {/* PERSISTENT SIDEBAR */}
          <aside className={`nav-sidebar ${isMobileMenuOpen ? 'mobile-open' : ''}`}>
            {/* Sidebar Brand Header */}
            <div 
              className="sidebar-brand" 
              onClick={() => {
                if (user.role === 'System Administrator' || user.role === 'HR Manager') {
                  setActiveTab('dashboard');
                } else {
                  setActiveTab('employees');
                }
                setIsMobileMenuOpen(false);
              }}
              style={{ cursor: 'pointer' }}
            >
              <div className="sidebar-logo">
                <img src="/logo.png" alt="DataLens Logo" className="nav-logo-img" />
              </div>
              <div className="sidebar-brand-text">
                <h2>DataLens HR</h2>
                <p>Privacy Analytics Suite</p>
              </div>
            </div>

            {/* Navigation Groups */}
            <div className="nav-menu-scroll">
              {/* Security Intelligence Category (Admins / Managers) */}
              {(user.role === 'System Administrator' || user.role === 'HR Manager') && (
                <div className="nav-menu-group">
                  <div className="menu-group-header">
                    <span className="menu-group-icon"><ShieldCheck size={14} /></span>
                    <span className="menu-header">Security Intelligence</span>
                  </div>
                  
                  <button 
                    onClick={() => { setActiveTab('dashboard'); setIsMobileMenuOpen(false); }}
                    className={`menu-item-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
                    id="nav-btn-dashboard"
                  >
                    <span className="menu-icon-box"><Shield size={16} /></span>
                    <div className="menu-text-wrap">
                      <span className="menu-label">Security Dashboard</span>
                      <span className="menu-sublabel">Threat Telemetry & SecOps</span>
                    </div>
                    {incidents.filter(i => i.status === 'Open').length > 0 && (
                      <span className="badge-alert-count">
                        {incidents.filter(i => i.status === 'Open').length}
                      </span>
                    )}
                  </button>

                  <button 
                    onClick={() => { setActiveTab('analytics'); setIsMobileMenuOpen(false); }}
                    className={`menu-item-btn ${activeTab === 'analytics' ? 'active' : ''}`}
                    id="nav-btn-analytics"
                  >
                    <span className="menu-icon-box"><BarChart3 size={16} /></span>
                    <div className="menu-text-wrap">
                      <span className="menu-label">Department Analytics</span>
                      <span className="menu-sublabel">Organizational Risk Matrix</span>
                    </div>
                  </button>

                  <button 
                    onClick={() => { setActiveTab('rules'); setIsMobileMenuOpen(false); }}
                    className={`menu-item-btn ${activeTab === 'rules' ? 'active' : ''}`}
                    id="nav-btn-rules"
                  >
                    <span className="menu-icon-box"><Sliders size={16} /></span>
                    <div className="menu-text-wrap">
                      <span className="menu-label">Detection Rules</span>
                      <span className="menu-sublabel">Thresholds & Heuristics</span>
                    </div>
                  </button>

                  <button 
                    onClick={() => { setActiveTab('recommendations'); setIsMobileMenuOpen(false); }}
                    className={`menu-item-btn ${activeTab === 'recommendations' ? 'active' : ''}`}
                    id="nav-btn-recommendations"
                  >
                    <span className="menu-icon-box"><Lightbulb size={16} /></span>
                    <div className="menu-text-wrap">
                      <span className="menu-label">Policy Advisor</span>
                      <span className="menu-sublabel">AI Hardening Advice</span>
                    </div>
                    {recommendations.length > 0 && (
                      <span className="badge-rec-count">{recommendations.length}</span>
                    )}
                  </button>
                </div>
              )}

              {/* HR Operations Category (All Authorized Roles) */}
              <div className="nav-menu-group">
                <div className="menu-group-header">
                  <span className="menu-group-icon"><Building2 size={14} /></span>
                  <span className="menu-header">HR Operations</span>
                </div>

                <button 
                  onClick={() => { setActiveTab('employees'); setIsMobileMenuOpen(false); }}
                  className={`menu-item-btn ${activeTab === 'employees' ? 'active' : ''}`}
                  id="nav-btn-employees"
                >
                  <span className="menu-icon-box"><Users size={16} /></span>
                  <div className="menu-text-wrap">
                    <span className="menu-label">Employee Directory</span>
                    <span className="menu-sublabel">Masked Staff Profiles</span>
                  </div>
                </button>

                <button 
                  onClick={() => { setActiveTab('leaves'); setIsMobileMenuOpen(false); }}
                  className={`menu-item-btn ${activeTab === 'leaves' ? 'active' : ''}`}
                  id="nav-btn-leaves"
                >
                  <span className="menu-icon-box"><Calendar size={16} /></span>
                  <div className="menu-text-wrap">
                    <span className="menu-label">
                      {user.role === 'HR Manager' || user.role === 'System Administrator' ? 'Leave Management' : 'My Leave Requests'}
                    </span>
                    <span className="menu-sublabel">
                      {user.role === 'HR Manager' || user.role === 'System Administrator' ? 'Approvals & Records' : 'Submit & Track Requests'}
                    </span>
                  </div>
                  {leaves.filter(l => l.status === 'Pending').length > 0 && (user.role === 'HR Manager' || user.role === 'System Administrator') && (
                    <span className="badge-pending-count">
                      {leaves.filter(l => l.status === 'Pending').length}
                    </span>
                  )}
                </button>
              </div>

              {/* Threat Simulator Widget (Collapsible) */}
              <div className={`simulator-widget ${isSimulatorCollapsed ? 'collapsed' : ''}`}>
                <div 
                  className="simulator-widget-header" 
                  tabIndex={0}
                  role="button"
                  aria-expanded={!isSimulatorCollapsed}
                  aria-label={isSimulatorCollapsed ? "Expand threat simulator console" : "Collapse threat simulator console"}
                  onClick={() => setIsSimulatorCollapsed(!isSimulatorCollapsed)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setIsSimulatorCollapsed(!isSimulatorCollapsed); } }}
                  style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                >
                  <span className="menu-header" style={{ color: 'var(--danger)', margin: 0, display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                    <AlertTriangle size={14} /> Threat Simulator
                  </span>
                  <span className="simulator-toggle-indicator" style={{ color: 'var(--danger)', fontSize: '11px', fontWeight: 'bold' }}>
                    {isSimulatorCollapsed ? '＋ Expand' : '－ Collapse'}
                  </span>
                </div>
                
                {!isSimulatorCollapsed && (
                  <div className="simulator-widget-body animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '14px' }}>
                    <button
                      onClick={simulateScraping}
                      disabled={isScraping}
                      className="btn-simulate-threat"
                      style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                    >
                      <Zap size={13} /> {isScraping ? 'Scraping...' : 'Simulate Volumetric Scrape'}
                    </button>
                    
                    <button
                      onClick={simulateImpossibleTravel}
                      className="btn-simulate-threat"
                      style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                    >
                      <MapPin size={13} /> Simulate Impossible Travel
                    </button>

                    <div className="client-status-card">
                      <span>Simulated Context:</span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <MapPin size={12} color="var(--text-muted)" /> Location: <strong style={{ color: 'var(--text-primary)' }}>{simLocation}</strong>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <Radio size={12} color="var(--text-muted)" /> Proxy: <strong style={{ color: 'var(--text-primary)' }}>Inactive</strong>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Sidebar User Footer Profile & Actions */}
            <div className="sidebar-footer">
              <div className="user-profile-summary">
                <div className="user-avatar-circle">
                  {user.email ? user.email.charAt(0).toUpperCase() : 'U'}
                </div>
                <div className="user-info-text">
                  <span className="user-email-text" title={user.email}>{user.email}</span>
                  <span className="user-role-badge">{user.role}</span>
                </div>
              </div>
              <div className="sidebar-footer-actions">
                <button 
                  onClick={toggleTheme} 
                  className="btn-sidebar-icon" 
                  title={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
                  aria-label={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
                >
                  {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
                </button>
                <button 
                  onClick={handleLogout} 
                  className="btn-sidebar-signout" 
                  title="Sign Out"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                >
                  <LogOut size={14} /> Sign Out
                </button>
              </div>
            </div>
          </aside>

          {/* MAIN CONTENT FRAME */}
          <div className="main-content-frame">
            {/* Top Contextual Header Bar */}
            <header className="workspace-top-bar">
              <div className="top-bar-left">
                <button 
                  className={`hamburger-menu-btn ${isMobileMenuOpen ? 'open' : ''}`}
                  onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                  aria-label="Toggle navigation menu"
                >
                  <span></span>
                  <span></span>
                  <span></span>
                </button>
                <div className="breadcrumb-box">
                  <span className="breadcrumb-icon">{getPageBreadcrumb().icon}</span>
                  <span className="breadcrumb-cat">{getPageBreadcrumb().category}</span>
                  <span className="breadcrumb-separator">/</span>
                  <span className="breadcrumb-page">{getPageBreadcrumb().title}</span>
                </div>
              </div>

              <div className="top-bar-right">
                <div className="live-status-pill">
                  <span className="pulse-dot"></span>
                  <span>Real-Time Shield Active</span>
                </div>
                <div className="sim-location-pill" title="Simulated Client Geolocation" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                  <MapPin size={12} /> <span>{simLocation}</span>
                </div>
              </div>
            </header>

            {/* UNIFIED VIEW FRAME */}
            <section className="view-frame">
              {/* ================= VIEW 1: SECURITY DASHBOARD ================= */}
              {activeTab === 'dashboard' && (
                <div className="dashboard-view-panel animate-fade-in">
                  {/* Dashboard Executive Header Block */}
                  <div className="view-title-block dashboard-header-block">
                    <div>
                      <div className="dashboard-suite-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: '800', color: 'var(--primary)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: '6px', background: 'var(--primary-glow)', padding: '4px 10px', borderRadius: '6px' }}>
                        <Shield size={12} /> Privacy Analytics Suite
                      </div>
                      <h3 style={{ color: 'var(--text-primary)', margin: '2px 0 6px 0' }}>Security Operations Dashboard</h3>
                      <p style={{ maxWidth: '850px', fontSize: '13.5px', lineHeight: '1.5', color: 'var(--text-secondary)' }}>
                        Monitor employee data access, identify suspicious activity, and manage privacy and security risks across your organization.
                      </p>
                    </div>
                  </div>

                  {(() => {
                    const openIncidents = incidents.filter(i => i.status === 'Open');
                    const maxRisk = openIncidents.length > 0 ? Math.max(...openIncidents.map(i => i.risk_score)) : 0;
                    const isHigh = maxRisk >= 70;
                    const isMed = maxRisk >= 40 && maxRisk < 70;
                    const openAlertsCount = openIncidents.length;
                    const highRiskCount = openIncidents.filter(i => i.risk_score >= 70).length;
                    const activeRulesCount = rules.filter(r => r.is_enabled).length;
                    const filteredIncidents = getFilteredIncidents();
                    const frequencies = getRuleFrequencies();
                    const maxCount = Math.max(...Object.values(frequencies), 1);
                    const strokeDash = 2 * Math.PI * 44; // ~276.46
                    const strokeOffset = strokeDash * (1 - maxRisk / 100);

                    return (
                      <>
                        {/* 1. TOP EXECUTIVE KPI METRIC STRIP (4 Cards with Tooltips & Units) */}
                        <div className="dashboard-kpi-grid">
                          {/* KPI 1: System Threat Index */}
                          <div className={`app-card kpi-metric-card ${isHigh ? 'critical-state' : ''} has-tooltip`}>
                            <div className="kpi-card-header">
                              <span className="kpi-title" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                                System Threat Index <Info size={13} style={{ color: 'var(--text-muted)', cursor: 'help' }} />
                              </span>
                              <span className={`kpi-status-badge ${isHigh ? 'critical' : isMed ? 'warning' : 'clean'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                {maxRisk === 0 ? <><Check size={12} /> Secured</> : isHigh ? <><AlertTriangle size={12} /> Critical</> : <><Zap size={12} /> Warning</>}
                              </span>
                            </div>
                            <div className="kpi-value-row">
                              <span className="kpi-big-number" style={{ color: isHigh ? 'var(--danger)' : isMed ? 'var(--warning)' : 'var(--success)' }}>
                                {maxRisk}
                              </span>
                              <span className="kpi-scale" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                / 100 Risk Score <Info size={11} style={{ color: 'var(--text-muted)' }} />
                              </span>
                            </div>
                            <div className="kpi-footer-text">
                              {maxRisk === 0 ? 'Normal traffic baselines (0/100)' : isHigh ? 'Active security anomaly detected' : 'Elevated velocity patterns'}
                            </div>
                            <div className="tooltip-bubble" style={{ minWidth: '240px' }}>
                              <strong className="tooltip-title">Risk Score (0 - 100)</strong>
                              <p style={{ margin: '4px 0 6px 0', fontSize: '11px', lineHeight: '1.4' }}>
                                A composite score representing the current level of detected security and privacy risks. Higher scores indicate greater risk.
                              </p>
                              <div style={{ borderTop: '1px solid var(--border-glow)', paddingTop: '6px', fontSize: '10px', color: 'var(--text-muted)' }}>
                                <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '3px' }}>Calculation Factors:</strong>
                                <ul style={{ margin: '0 0 0 14px', padding: 0, lineHeight: '1.4' }}>
                                  <li>Canary Honeypot Decoy Hit (+40 pts)</li>
                                  <li>Impossible Travel Velocity (+35 pts)</li>
                                  <li>Volumetric Scrape Probing (+25 pts)</li>
                                  <li>After-Hours / Salary Unmask (+20 pts)</li>
                                </ul>
                              </div>
                            </div>
                          </div>

                          {/* KPI 2: Active Unresolved Alerts */}
                          <div className="app-card kpi-metric-card has-tooltip">
                            <div className="kpi-card-header">
                              <span className="kpi-title">Active Alerts</span>
                              <span className="kpi-icon"><AlertTriangle size={18} color="var(--warning)" /></span>
                            </div>
                            <div className="kpi-value-row">
                              <span className="kpi-big-number" style={{ color: openAlertsCount > 0 ? 'var(--danger)' : 'var(--text-primary)' }}>
                                {openAlertsCount}
                              </span>
                              <span className="kpi-scale">Unresolved Tickets</span>
                            </div>
                            <div className="kpi-footer-text">
                              {openAlertsCount > 0 ? `${openAlertsCount} incident(s) require action` : 'All telemetry alerts cleared'}
                            </div>
                            <div className="tooltip-bubble">
                              <strong className="tooltip-title">Active Security Alerts</strong>
                              <span>Total open incidents and policy violations currently awaiting dismissal, review, or administrative lockout.</span>
                            </div>
                          </div>

                          {/* KPI 3: High Risk Outliers */}
                          <div className="app-card kpi-metric-card has-tooltip">
                            <div className="kpi-card-header">
                              <span className="kpi-title">Critical Anomalies</span>
                              <span className="kpi-icon"><AlertCircle size={18} color="var(--danger)" /></span>
                            </div>
                            <div className="kpi-value-row">
                              <span className="kpi-big-number" style={{ color: highRiskCount > 0 ? 'var(--danger)' : 'var(--text-primary)' }}>
                                {highRiskCount}
                              </span>
                              <span className="kpi-scale">High-Risk Events</span>
                            </div>
                            <div className="kpi-footer-text">
                              {highRiskCount > 0 ? 'Lockout triggers available below' : 'Zero severe policy breaches'}
                            </div>
                            <div className="tooltip-bubble">
                              <strong className="tooltip-title">Critical Security Anomalies</strong>
                              <span>High-risk events scoring ≥ 70/100 risk that qualify for immediate user account lockout response.</span>
                            </div>
                          </div>

                          {/* KPI 4: Monitored Policies */}
                          <div className="app-card kpi-metric-card has-tooltip">
                            <div className="kpi-card-header">
                              <span className="kpi-title">Monitored Policies</span>
                              <span className="kpi-icon"><Sliders size={18} color="var(--primary)" /></span>
                            </div>
                            <div className="kpi-value-row">
                              <span className="kpi-big-number" style={{ color: 'var(--text-primary)' }}>
                                {activeRulesCount}
                              </span>
                              <span className="kpi-scale">Active Rules</span>
                            </div>
                            <div className="kpi-footer-text">
                              {incidents.length} total events audited
                            </div>
                            <div className="tooltip-bubble">
                              <strong className="tooltip-title">Active Detection Rules</strong>
                              <span>Number of heuristic privacy and security evaluation rules actively inspecting access logs.</span>
                            </div>
                          </div>
                        </div>

                        {/* 2. CONSOLIDATED ANALYTICS ROW (2 Balanced Cards with Axis & Tooltips) */}
                        <div className="dashboard-analytics-row">
                          {/* Left Column: Threat Distribution & Risk Dial */}
                          <div className="app-card unified-threat-card">
                            <div className="analytics-card-header">
                              <div>
                                <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <Activity size={18} color="var(--primary)" /> Threat Velocity & Distribution
                                </h3>
                                <p className="card-subtitle">Live rule trigger frequency mapped against current composite risk index.</p>
                              </div>
                            </div>
                            
                            {isLoadingIncidents ? (
                              <SkeletonChart 
                                message="Loading security analytics..." 
                                subtitle="Processing real-time access logs and rule trigger frequencies" 
                              />
                            ) : incidents.length === 0 ? (
                              <EmptyState 
                                icon={<BarChart3 size={32} color="var(--primary)" />} 
                                title="No data available yet" 
                                description="No employee activity has been recorded for this period." 
                                actionText="Trigger Threat Simulation"
                                onAction={simulateScraping}
                              />
                            ) : (
                              <div className="threat-dial-and-bars">
                                {/* Mini Circular Gauge Dial with Tooltip */}
                                <div className="gauge-panel-compact has-tooltip">
                                  <div className={`gauge-ring-outer gauge-ring-compact ${isHigh ? 'high-risk' : isMed ? 'med-risk' : ''}`}>
                                    <svg width="110" height="110" viewBox="0 0 110 110" style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
                                      <circle cx="55" cy="55" r="44" fill="transparent" stroke="var(--border-glow)" strokeWidth="6" />
                                      <circle
                                        cx="55"
                                        cy="55"
                                        r="44"
                                        fill="transparent"
                                        stroke={isHigh ? 'var(--danger)' : isMed ? 'var(--warning)' : 'var(--success)'}
                                        strokeWidth="6"
                                        strokeDasharray={strokeDash}
                                        strokeDashoffset={strokeOffset}
                                        strokeLinecap="round"
                                        style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.34, 1.56, 0.64, 1)' }}
                                      />
                                    </svg>
                                    <div style={{ position: 'relative', zIndex: 2, textAlign: 'center' }}>
                                      <span className="gauge-value-number" style={{ fontSize: '26px', color: 'var(--text-primary)' }}>{maxRisk}</span>
                                      <span className="gauge-value-lbl" style={{ fontSize: '9px' }}>/ 100 Risk</span>
                                    </div>
                                  </div>
                                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.4px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    {maxRisk === 0 ? <><Check size={11} color="var(--success)" /> Baseline Clean</> : isHigh ? <><AlertTriangle size={11} color="var(--danger)" /> Critical State</> : <><Zap size={11} color="var(--warning)" /> Warning State</>}
                                  </span>
                                  <div className="tooltip-bubble">
                                    <strong className="tooltip-title">Composite Privacy Threat Index</strong>
                                    <span>Threat Score: <strong>{maxRisk}/100</strong>. Measures the overall level of privacy risk based on employee access velocity, anomalous locations, and security activity.</span>
                                  </div>
                                </div>

                                {/* Trigger Frequency Progress Bars with Axis & Tooltips */}
                                <div className="rule-frequencies-compact">
                                  <div className="chart-axis-header">
                                    <span>Detection Rule Heuristic</span>
                                    <span>Rule Trigger Frequency (Events)</span>
                                  </div>
                                  {Object.entries(frequencies).map(([rule, count], idx) => {
                                    const percentage = (count / maxCount) * 100;
                                    const meta = RULE_METADATA[rule] || { label: rule.replace(/_/g, ' '), shortName: rule.replace(/_/g, ' '), code: 'RULE', description: 'Monitors specific access telemetry patterns.' };
                                    
                                    // Locate the most recent incident for this rule to show "Last detected"
                                    const matchingIncident = incidents.find(inc => {
                                      const tr = Array.isArray(inc.triggered_rules) 
                                        ? inc.triggered_rules 
                                        : JSON.parse(inc.triggered_rules || '[]');
                                      return tr.includes(rule);
                                    });
                                    const lastDetected = matchingIncident?.created_at 
                                      ? new Date(matchingIncident.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
                                      : 'None recorded';
                                    const riskLevel = (rule === 'CANARY_ACCESS' || rule === 'IMPOSSIBLE_TRAVEL') 
                                      ? 'Critical' 
                                      : count > 10 
                                        ? 'High' 
                                        : count > 0 
                                          ? 'Medium' 
                                          : 'Low';

                                    return (
                                      <div key={idx} className="rule-frequency-row has-tooltip" style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                                        <div className="rule-frequency-labels" style={{ width: '100%', display: 'flex', justifyContent: 'space-between' }}>
                                          <span className="rule-name-lbl" style={{ color: 'var(--text-primary)', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <span className="rule-card-id" style={{ fontSize: '9px', padding: '1px 5px' }}>{meta.code}</span>
                                            {meta.shortName || meta.label}
                                          </span>
                                          <span className="rule-count-lbl" style={{ fontSize: '11px', fontWeight: '700', color: count > 0 ? (rule === 'CANARY_ACCESS' || rule === 'IMPOSSIBLE_TRAVEL' ? 'var(--danger)' : 'var(--warning)') : 'var(--text-muted)' }}>
                                            {count} {count === 1 ? 'trigger event' : 'trigger events'} ({Math.round(percentage)}%)
                                          </span>
                                        </div>
                                        <div className="rule-frequency-bar-bg" style={{ height: '7px', background: 'var(--bg-input)', borderRadius: '4px', overflow: 'hidden', border: '1px solid var(--border-glow)' }}>
                                          <div 
                                            className="rule-frequency-bar-fill" 
                                            style={{ 
                                              width: `${Math.max(percentage, count > 0 ? 8 : 0)}%`,
                                              backgroundColor: rule === 'CANARY_ACCESS' || rule === 'IMPOSSIBLE_TRAVEL' ? 'var(--danger)' : 'var(--warning)',
                                              height: '100%',
                                              borderRadius: '4px',
                                              transition: 'width 0.4s ease'
                                            }}
                                          />
                                        </div>
                                        <div className="tooltip-bubble" style={{ minWidth: '220px' }}>
                                          <strong className="tooltip-title">{meta.shortName || meta.label}</strong>
                                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', margin: '6px 0', fontSize: '11px' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <span style={{ color: 'var(--text-muted)' }}>Triggered:</span>
                                              <strong style={{ color: 'var(--text-primary)' }}>{count} {count === 1 ? 'time' : 'times'}</strong>
                                            </div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <span style={{ color: 'var(--text-muted)' }}>Risk Level:</span>
                                              <strong style={{ color: riskLevel === 'Critical' ? 'var(--danger)' : riskLevel === 'High' ? 'var(--warning)' : 'var(--success)' }}>
                                                {riskLevel}
                                              </strong>
                                            </div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <span style={{ color: 'var(--text-muted)' }}>Last detected:</span>
                                              <strong style={{ color: 'var(--text-secondary)' }}>{lastDetected}</strong>
                                            </div>
                                          </div>
                                          <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', borderTop: '1px solid var(--border-glow)', paddingTop: '4px', display: 'block', lineHeight: '1.3' }}>
                                            {meta.description}
                                          </span>
                                        </div>
                                      </div>
                                    );
                                  })}
                                  
                                  {/* Graphical Scale & Axis Ticks with Units */}
                                  <div className="chart-axis-container" style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px dashed var(--border-glow)' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: '600' }}>
                                      <span>0</span>
                                      <span>{Math.max(1, Math.round(maxCount * 0.25))}</span>
                                      <span>{Math.max(2, Math.round(maxCount * 0.5))}</span>
                                      <span>{Math.max(3, Math.round(maxCount * 0.75))}</span>
                                      <span>{maxCount} Events (Peak)</span>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: '6px', margin: '2px 0 4px 0', borderBottom: '1px solid var(--border-glow)' }}>
                                      <span style={{ width: '1px', height: '6px', background: 'var(--text-muted)' }} />
                                      <span style={{ width: '1px', height: '4px', background: 'var(--border-glow)' }} />
                                      <span style={{ width: '1px', height: '4px', background: 'var(--border-glow)' }} />
                                      <span style={{ width: '1px', height: '4px', background: 'var(--border-glow)' }} />
                                      <span style={{ width: '1px', height: '6px', background: 'var(--text-muted)' }} />
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)' }}>
                                      <span>Scale: Trigger Count (0 to Peak)</span>
                                      <span>Unit: Recorded Security Events</span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Right Column: Flagged Accounts Leaderboard */}
                          <div className="app-card flagged-accounts-card">
                            <div className="analytics-card-header">
                              <div>
                                <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  <AlertTriangle size={18} color="var(--danger)" /> Flagged Accounts Leaderboard
                                </h3>
                                <p className="card-subtitle">User accounts exceeding safety limits with highest telemetry violations.</p>
                              </div>
                            </div>

                            <div className="analytics-card-content">
                              {isLoadingIncidents ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                  {[1, 2, 3].map((n) => (
                                    <div key={n} className="skeleton-card" style={{ padding: '12px 14px', minHeight: 'auto', gap: '8px' }}>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                        <div className="skeleton-bar" style={{ width: '32px', height: '32px', borderRadius: '50%' }} />
                                        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                          <div className="skeleton-bar" style={{ width: '60%', height: '12px' }} />
                                          <div className="skeleton-bar" style={{ width: '35%', height: '10px' }} />
                                        </div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              ) : getTopRiskAccounts().length === 0 ? (
                                <EmptyState 
                                  icon={<ShieldCheck size={32} color="var(--success)" />} 
                                  title="No flagged accounts" 
                                  description="No employee accounts currently exceed the configured risk threshold." 
                                />
                              ) : (
                                <div className="risk-accounts-list">
                                  {getTopRiskAccounts().map((acc, idx) => (
                                    <div key={idx} className="risk-account-row has-tooltip">
                                      <div className="user-avatar-circle" style={{ width: '34px', height: '34px', minWidth: '34px', fontSize: '13px' }}>
                                        {acc.email.charAt(0).toUpperCase()}
                                      </div>
                                      <div className="risk-account-details">
                                        <span className="risk-account-email" style={{ color: 'var(--text-primary)' }}>{acc.email}</span>
                                        <span className="risk-account-role">{acc.role}</span>
                                      </div>
                                      <div className="risk-account-badge">
                                        <span className="risk-score-pill" style={{
                                          backgroundColor: acc.peakScore >= 70 ? 'rgba(220, 38, 38, 0.15)' : 'rgba(217, 119, 6, 0.15)',
                                          color: acc.peakScore >= 70 ? '#fca5a5' : '#fcd34d'
                                        }}>
                                          Peak Risk: {acc.peakScore} / 100
                                        </span>
                                        <span className="risk-incident-count">{acc.incidentCount} incident(s)</span>
                                      </div>
                                      <div className="tooltip-bubble">
                                        <strong className="tooltip-title">Account Risk Profile: {acc.email}</strong>
                                        <span>Peak Risk: <strong>{acc.peakScore}/100</strong> across <strong>{acc.incidentCount} triggered violation(s)</strong>.</span>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* 3. STREAMLINED INCIDENT TELEMETRY FEED */}
                        <div className="incidents-card-log">
                          {/* Header & Filter Toolbar */}
                          <div className="incident-toolbar-container">
                            <div className="toolbar-header-text">
                              <h3 style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <FileText size={18} color="var(--primary)" /> Incident Telemetry & Audit Stream
                              </h3>
                              <p>Real-time security logs with instant automated mitigation tools.</p>
                            </div>

                            <div className="incident-filter-bar">
                              {/* Search Input */}
                              <div className="search-box-wrapper">
                                <span className="search-icon"><Search size={14} /></span>
                                <input 
                                  type="text" 
                                  placeholder="Filter by email, rule, city, or IP..." 
                                  value={alertSearch}
                                  onChange={(e) => setAlertSearch(e.target.value)}
                                  className="search-input-field"
                                />
                                {alertSearch && (
                                  <button onClick={() => setAlertSearch('')} className="btn-clear-search" title="Clear Search">×</button>
                                )}
                              </div>

                              {/* Status Filter Buttons */}
                              <div className="filter-pill-group">
                                <button 
                                  onClick={() => setAlertFilter('all')} 
                                  className={`filter-pill-btn ${alertFilter === 'all' ? 'active' : ''}`}
                                >
                                  All ({incidents.length})
                                </button>
                                <button 
                                  onClick={() => setAlertFilter('open')} 
                                  className={`filter-pill-btn ${alertFilter === 'open' ? 'active' : ''}`}
                                >
                                  Open ({openAlertsCount})
                                </button>
                                <button 
                                  onClick={() => setAlertFilter('high')} 
                                  className={`filter-pill-btn ${alertFilter === 'high' ? 'active' : ''}`}
                                >
                                  Critical ({highRiskCount})
                                </button>
                                <button 
                                  onClick={() => setAlertFilter('resolved')} 
                                  className={`filter-pill-btn ${alertFilter === 'resolved' ? 'active' : ''}`}
                                >
                                  Resolved ({incidents.filter(i => i.status !== 'Open').length})
                                </button>
                              </div>

                              <button onClick={fetchIncidents} className="btn-actions-refresh" title="Refresh Live Stream" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                                <RefreshCw size={12} /> Refresh
                              </button>
                            </div>
                          </div>

                          {/* Streamlined Incident List */}
                          <div className="incident-stream-list">
                            {isLoadingIncidents ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                {[1, 2, 3, 4].map((n) => (
                                  <div key={n} className="skeleton-ticket-card">
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                      <div style={{ display: 'flex', gap: '8px', width: '50%' }}>
                                        <div className="skeleton-bar" style={{ width: '80px', height: '20px', borderRadius: '12px' }} />
                                        <div className="skeleton-bar" style={{ width: '140px', height: '20px', borderRadius: '12px' }} />
                                      </div>
                                      <div className="skeleton-bar" style={{ width: '90px', height: '28px', borderRadius: '8px' }} />
                                    </div>
                                    <div className="skeleton-bar" style={{ width: '80%', height: '12px' }} />
                                  </div>
                                ))}
                              </div>
                            ) : incidents.length === 0 ? (
                              <EmptyState 
                                icon={<BarChart3 size={32} color="var(--primary)" />} 
                                title="No data available yet" 
                                description="No employee activity has been recorded for this period." 
                                actionText="Trigger Threat Simulation"
                                onAction={simulateScraping}
                              />
                            ) : filteredIncidents.length === 0 ? (
                              <NoResultsState 
                                title="No results found" 
                                query={alertSearch}
                                entity="security alerts"
                                onClear={() => { setAlertSearch(''); setAlertFilter('all'); }} 
                              />
                            ) : (
                              filteredIncidents.map((inc) => {
                                const triggeredRules = Array.isArray(inc.triggered_rules) ? inc.triggered_rules : JSON.parse(inc.triggered_rules || '[]');
                                const evidence = typeof inc.raw_evidence === 'object' ? inc.raw_evidence : JSON.parse(inc.raw_evidence || '{}');
                                const actions = Array.isArray(inc.recommended_actions) ? inc.recommended_actions : JSON.parse(inc.recommended_actions || '[]');
                                const isExpanded = !!expandedIncidents[inc.id];
                                const isResolved = inc.status !== 'Open';

                                return (
                                  <div 
                                    key={inc.id} 
                                    className={`incident-ticket-stream ${!isResolved ? (inc.risk_level === 'High' ? 'risk-high' : 'risk-medium') : 'resolved'}`}
                                  >
                                    <div className="ticket-summary-row">
                                      <div className="ticket-summary-left">
                                        <span className={`risk-level-badge ${inc.risk_level.toLowerCase()}`}>
                                          {inc.risk_level} ({inc.risk_score})
                                        </span>
                                        <span className="ticket-user-pill" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                          <User size={12} /> <strong>{inc.user_email || 'Anonymous'}</strong> ({inc.user_role || 'Guest'})
                                        </span>
                                        <span className="ticket-rule-tag">
                                          {triggeredRules.join(', ')}
                                        </span>
                                        {evidence.metadata && (
                                          <span className="ticket-geo-pill" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                            <MapPin size={12} /> {evidence.metadata.city || 'Unknown'}, {evidence.metadata.country || ''}
                                          </span>
                                        )}
                                      </div>

                                      <div className="ticket-summary-right">
                                        <button 
                                          onClick={() => toggleIncidentExpand(inc.id)}
                                          className="btn-toggle-evidence"
                                          aria-expanded={isExpanded}
                                          aria-label={isExpanded ? `Hide audit evidence details for incident ${inc.id}` : `View audit evidence details for incident ${inc.id}`}
                                          style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                                        >
                                          {isExpanded ? <>Hide Audit Details <ChevronUp size={13} /></> : <>View Audit Details <ChevronDown size={13} /></>}
                                        </button>

                                        {!isResolved ? (
                                          <div className="ticket-action-btns">
                                            <button
                                              onClick={() => executeMitigation(inc.id, 'DISMISS', null)}
                                              className="btn-mitigation-dismiss-sm"
                                            >
                                              Dismiss
                                            </button>
                                            {inc.risk_level === 'High' && (
                                              <button
                                                onClick={() => executeMitigation(inc.id, 'LOCK_USER', inc.user_id)}
                                                className="btn-mitigation-lock-sm"
                                              >
                                                Lock Account
                                              </button>
                                            )}
                                          </div>
                                        ) : (
                                          <div className="ticket-action-btns">
                                            <span className="ticket-resolved-pill" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                              <Check size={12} /> {inc.status === 'Resolved' ? 'Mitigated' : 'Dismissed'}
                                            </span>
                                            {inc.risk_level === 'High' && inc.status === 'Resolved' && (
                                              <button
                                                onClick={() => executeMitigation(inc.id, 'UNLOCK_USER', inc.user_id)}
                                                className="btn-mitigation-unlock-sm"
                                              >
                                                Unlock
                                              </button>
                                            )}
                                            <button
                                              onClick={() => executeMitigation(inc.id, 'REOPEN', null)}
                                              className="btn-mitigation-reopen-sm"
                                            >
                                              Reopen
                                            </button>
                                          </div>
                                        )}
                                      </div>
                                    </div>

                                    {/* Expandable Evidence Accordion Drawer */}
                                    {isExpanded && (
                                      <div className="ticket-expanded-details animate-fade-in">
                                        <div className="evidence-grid">
                                          <div className="evidence-cell">
                                            <label>Audit Target Account:</label>
                                            <span style={{ color: 'var(--text-primary)' }}>{inc.user_email || 'Anonymous'}</span>
                                          </div>
                                          <div className="evidence-cell">
                                            <label>Assigned Role:</label>
                                            <span style={{ color: 'var(--primary)' }}>{inc.user_role || 'Guest'}</span>
                                          </div>
                                          <div className="evidence-cell">
                                            <label>Client Device Agent:</label>
                                            <span style={{ color: 'var(--text-primary)' }}>{evidence.metadata?.device || 'Unknown Browser Agent'}</span>
                                          </div>
                                          <div className="evidence-cell">
                                            <label>Geolocation & IP:</label>
                                            <span style={{ color: 'var(--text-primary)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                              <MapPin size={12} /> {evidence.metadata ? `${evidence.metadata.city}, ${evidence.metadata.country} (${evidence.metadata.ip})` : '127.0.0.1'}
                                            </span>
                                          </div>
                                        </div>

                                        <div className="incident-protocol-section">
                                          <span className="incident-protocol-title">Recommended Mitigation Response Plan:</span>
                                          <ul className="incident-protocol-list" style={{ color: 'var(--text-secondary)' }}>
                                            {actions.map((act, i) => (
                                              <li key={i}>{act}</li>
                                            ))}
                                          </ul>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                );
                              })
                            )}
                          </div>
                        </div>
                      </>
                    );
                  })()}
                </div>
              )}

              {/* ================= VIEW 2: DEPARTMENT ANALYTICS ================= */}
              {activeTab === 'analytics' && (
                <div className="dept-analytics-panel animate-fade-in">
                  <div className="view-title-block">
                    <h3>Department Privacy Analytics</h3>
                    <p>Aggregated telemetry audit of data accesses, record leaks, and incident risk summaries grouped by department.</p>
                  </div>

                  {/* Summary Ribbon Cards with Units & Tooltips */}
                  <div className="analytics-ribbon" style={{ display: 'flex', gap: '16px', marginBottom: '24px', flexWrap: 'wrap' }}>
                    <div className="app-card ribbon-card has-tooltip" style={{ flex: 1, minWidth: '220px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="section-eyebrow">Monitored Departments</span>
                        <Building2 size={16} color="var(--primary)" />
                      </div>
                      <h3 style={{ fontSize: '28px', fontWeight: '900', marginTop: '6px', color: 'var(--text-primary)' }}>{deptAnalytics.length} <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)' }}>Departments</span></h3>
                      <p className="card-subtitle" style={{ marginTop: '4px' }}>Active organizational business units</p>
                      <div className="tooltip-bubble">
                        <strong className="tooltip-title">Monitored Departments</strong>
                        <span>Total company divisions currently undergoing continuous real-time access log auditing.</span>
                      </div>
                    </div>
                    <div className="app-card ribbon-card has-tooltip" style={{ flex: 1, minWidth: '220px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="section-eyebrow">Top Vulnerability Department</span>
                        <AlertTriangle size={16} color="var(--danger)" />
                      </div>
                      <h3 style={{ fontSize: '18px', fontWeight: '800', marginTop: '8px', color: 'var(--danger)' }}>{getTopRiskDept()}</h3>
                      <p className="card-subtitle" style={{ marginTop: '4px' }}>Highest aggregate incident violation score</p>
                      <div className="tooltip-bubble">
                        <strong className="tooltip-title">Highest Risk Department</strong>
                        <span>Department exhibiting the highest cumulative privacy violation rate and anomalous database access.</span>
                      </div>
                    </div>
                    <div className="app-card ribbon-card has-tooltip" style={{ flex: 1, minWidth: '220px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="section-eyebrow">Highest Data Harvest</span>
                        <FileText size={16} color="var(--warning)" />
                      </div>
                      <h3 style={{ fontSize: '18px', fontWeight: '800', marginTop: '8px', color: 'var(--warning)' }}>{getTopHarvesterDept()}</h3>
                      <p className="card-subtitle" style={{ marginTop: '4px' }}>Peak sensitive read volume recorded</p>
                      <div className="tooltip-bubble">
                        <strong className="tooltip-title">Highest Record Volume</strong>
                        <span>Department with the highest count of unmasked salary and employee profile reads in this audit cycle.</span>
                      </div>
                    </div>
                  </div>

                  {/* Grid of Department Cards with Risk Gauge Ticks & Tooltips */}
                  {isLoadingAnalytics ? (
                    <div className="rules-grid" style={{ marginBottom: '24px' }}>
                      {[1, 2, 3, 4].map((n) => (
                        <SkeletonCard key={n} height="200px" />
                      ))}
                    </div>
                  ) : deptAnalytics.length === 0 ? (
                    <div className="app-card" style={{ padding: '16px', marginBottom: '24px' }}>
                      <EmptyState 
                        icon={<BarChart3 size={32} color="var(--primary)" />} 
                        title="No data available yet" 
                        description="No employee activity has been recorded for this period." 
                        actionText="Refresh Analytics" 
                        onAction={fetchDeptAnalytics} 
                      />
                    </div>
                  ) : (
                    <div className="rules-grid" style={{ marginBottom: '24px' }}>
                      {deptAnalytics.map((dept) => {
                        const avgRisk = parseFloat(dept.avg_risk_score || 0);
                        const maxRisk = parseInt(dept.max_risk_score || 0);
                        const isHighRisk = avgRisk >= 60 || maxRisk >= 75;
                        const isMedRisk = (avgRisk >= 30 && avgRisk < 60) || (maxRisk >= 40 && maxRisk < 75);
                        
                        return (
                          <div 
                            key={dept.department} 
                            className="app-card rule-config-card"
                          >
                            <div className="rule-card-header" style={{ marginBottom: '8px' }}>
                              <div>
                                <span className="rule-card-id" style={{ background: 'var(--primary-glow)', color: 'var(--text-primary)' }}>
                                  {dept.employee_count} {dept.employee_count === 1 ? 'Staff Member' : 'Staff Members'}
                                </span>
                                <h4 className="card-title" style={{ marginTop: '8px' }}>{dept.department || 'General'}</h4>
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
                              {/* Horizontal Risk Bar with Axis Scale Ticks & Tooltip */}
                              <div className="has-tooltip" style={{ marginBottom: '14px', width: '100%', display: 'flex', flexDirection: 'column' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                                  <span style={{ color: 'var(--text-secondary)' }}>Average Privacy Risk Score:</span>
                                  <span style={{ fontWeight: 'bold', color: 'var(--text-primary)' }}>{Math.round(avgRisk)} / 100 Risk</span>
                                </div>
                                <div style={{ height: '7px', background: 'var(--bg-input)', borderRadius: '4px', overflow: 'hidden', border: '1px solid var(--border-glow)' }}>
                                  <div style={{
                                    height: '100%',
                                    width: `${Math.max(avgRisk, 3)}%`,
                                    backgroundColor: isHighRisk ? 'var(--danger)' : isMedRisk ? 'var(--warning)' : 'var(--success)',
                                    borderRadius: '4px',
                                    transition: 'width 0.4s ease'
                                  }} />
                                </div>
                                <div className="risk-scale-axis-ticks">
                                  <span>0 Low</span>
                                  <span>50 Elevated</span>
                                  <span>100 Critical</span>
                                </div>
                                <div className="tooltip-bubble">
                                  <strong className="tooltip-title">{dept.department || 'General'} Privacy Score</strong>
                                  <span>Privacy Score: <strong>{Math.round(avgRisk)}/100</strong>. Measures the overall level of privacy risk based on employee access, record harvest volumes, and policy violations in {dept.department}.</span>
                                </div>
                              </div>

                              <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px', width: '100%' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Triggered Incidents:</span>
                                <span style={{ 
                                  color: dept.incident_count > 0 ? 'var(--danger)' : 'var(--text-primary)', 
                                  fontWeight: dept.incident_count > 0 ? 'bold' : 'normal' 
                                }}>
                                  {dept.incident_count} {dept.incident_count === 1 ? 'Violation' : 'Violations'}
                                </span>
                                <div className="tooltip-bubble">
                                  <strong className="tooltip-title">Triggered Incidents</strong>
                                  <span>Total security rule breach events linked to users in {dept.department}.</span>
                                </div>
                              </div>

                              <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px', width: '100%' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Peak Incident Risk:</span>
                                <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>{maxRisk} / 100 Peak</span>
                                <div className="tooltip-bubble">
                                  <strong className="tooltip-title">Peak Incident Risk</strong>
                                  <span>Highest single risk score recorded for any event in {dept.department}.</span>
                                </div>
                              </div>

                              <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px', width: '100%' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Sensitive Records Read:</span>
                                <span style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>{dept.total_records_accessed} Records</span>
                                <div className="tooltip-bubble">
                                  <strong className="tooltip-title">Sensitive Records Read</strong>
                                  <span>Total employee profile queries and salary lookups audited in {dept.department}.</span>
                                </div>
                              </div>

                              <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', fontSize: '12px', width: '100%' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Total Audit Activities:</span>
                                <span style={{ color: 'var(--text-primary)' }}>{dept.total_actions} Transactions</span>
                                <div className="tooltip-bubble">
                                  <strong className="tooltip-title">Total Audit Activities</strong>
                                  <span>Total telemetry data events generated by members of {dept.department}.</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Analytics Detail Data Table with Units in Columns */}
                  <div className="app-card incidents-card-log">
                    <div className="incidents-log-header">
                      <div>
                        <h3 className="card-title">Department Audit Log Matrix</h3>
                        <p className="card-subtitle">Detailed breakdown of access rates, data leak risks, and compliance levels by department.</p>
                      </div>
                      <button onClick={fetchDeptAnalytics} className="btn-secondary">
                        Refresh Reporting
                      </button>
                    </div>

                    <div className="table-wrapper">
                      <table>
                        <thead>
                          <tr>
                            <th>Department</th>
                            <th>Active Members (Staff)</th>
                            <th>Incident Violations (Events)</th>
                            <th>Average Risk Score (/ 100)</th>
                            <th>Peak Risk Score (/ 100)</th>
                            <th>Sensitive Records Read (Records)</th>
                            <th>Audit Transactions (Operations)</th>
                          </tr>
                        </thead>
                        <tbody>
                          {isLoadingAnalytics ? (
                            <SkeletonTableRows columns={7} rows={4} />
                          ) : deptAnalytics.length === 0 ? (
                            <tr>
                              <td colSpan="7" style={{ padding: '30px 10px', textAlign: 'center' }}>
                                <EmptyState 
                                  icon={<BarChart3 size={32} color="var(--primary)" />} 
                                  title="No data available yet" 
                                  description="No employee activity has been recorded for this period." 
                                />
                              </td>
                            </tr>
                          ) : (
                            deptAnalytics.map((dept, i) => (
                              <tr key={i}>
                                <td data-label="Department" style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{dept.department || 'General'}</td>
                                <td data-label="Active Members" style={{ color: 'var(--text-primary)' }}>{dept.employee_count} members</td>
                                <td data-label="Incident Violations" style={{ color: dept.incident_count > 0 ? 'var(--danger)' : 'var(--text-primary)', fontWeight: dept.incident_count > 0 ? 'bold' : 'normal' }}>
                                  {dept.incident_count} events
                                </td>
                                <td data-label="Average Risk">
                                  <span className="risk-score-pill" style={{
                                    backgroundColor: parseFloat(dept.avg_risk_score) >= 60 ? 'rgba(239, 68, 68, 0.15)' : parseFloat(dept.avg_risk_score) >= 30 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                    color: parseFloat(dept.avg_risk_score) >= 60 ? '#fca5a5' : parseFloat(dept.avg_risk_score) >= 30 ? '#fcd34d' : '#a7f3d0'
                                  }}>
                                    {Math.round(dept.avg_risk_score)} / 100
                                  </span>
                                </td>
                                <td data-label="Peak Risk" style={{ color: 'var(--text-primary)' }}>{dept.max_risk_score} / 100</td>
                                <td data-label="Sensitive Records" style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>{dept.total_records_accessed} records</td>
                                <td data-label="Audit Transactions" style={{ color: 'var(--text-primary)' }}>{dept.total_actions} ops</td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* ================= VIEW 3: DETECTION RULES ================= */}
              {activeTab === 'rules' && (
                <div className="rules-config-panel animate-fade-in">
                  <div className="view-title-block">
                    <h3>Privacy Policy Detection Rules</h3>
                    <p>Dynamically modify threat limits, active sliding windows, risk weights, and toggle rules on/off to adjust security sensitivity levels.</p>
                  </div>

                  {isLoadingRules ? (
                    <div className="rules-grid">
                      {[1, 2, 3, 4, 5, 6].map((n) => (
                        <SkeletonCard key={n} height="190px" />
                      ))}
                    </div>
                  ) : rules.length === 0 ? (
                    <div className="app-card" style={{ padding: '16px' }}>
                      <EmptyState 
                        icon={<Sliders size={32} color="var(--primary)" />} 
                        title="No detection rules configured" 
                        description="No privacy detection rules have been loaded or defined yet." 
                        actionText="Reload Rules" 
                        onAction={fetchRules} 
                      />
                    </div>
                  ) : (
                    <div className="rules-grid">
                      {rules.map((rule) => {
                        const params = typeof rule.parameters === 'object' ? rule.parameters : JSON.parse(rule.parameters || '{}');
                        const isEditing = editingRule && editingRule.id === rule.id;

                        return (
                          <div key={rule.id} className={`app-card rule-config-card ${rule.is_enabled ? 'enabled' : 'disabled'}`}>
                            <div className="rule-card-header">
                              <div>
                                <span className="rule-card-id">{rule.id}</span>
                                <h4 className="card-title" style={{ marginTop: '4px' }}>{rule.name.replace(/_/g, ' ')}</h4>
                              </div>
                              <span className={`status-badge-indicator ${rule.is_enabled ? 'active' : 'inactive'}`}>
                                {rule.is_enabled ? 'Active Policy' : 'Disabled'}
                              </span>
                            </div>
                            
                            <p className="card-subtitle" style={{ minHeight: '38px', marginBottom: '16px' }}>{rule.description}</p>

                            {isEditing ? (
                              <form onSubmit={(e) => handleSaveRule(e, rule.id)} className="rule-edit-form">
                                <div className="edit-form-field">
                                  <label style={{ display: 'block', color: 'var(--text-primary)', marginBottom: '6px', fontSize: '12px' }}>Risk Score Weight (1 - 100 Points):</label>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <input 
                                      type="range" 
                                      min="1" 
                                      max="100" 
                                      value={editWeight} 
                                      onChange={(e) => setEditWeight(parseInt(e.target.value))}
                                      style={{ flex: 1 }}
                                    />
                                    <span style={{ fontWeight: 'bold', minWidth: '45px', textAlign: 'right', color: 'var(--text-primary)' }}>{editWeight} pts</span>
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

                                {/* Custom Parameter Fields with Units */}
                                {rule.id === 'R-02' && (
                                  <div className="edit-form-field inline-fields" style={{ display: 'flex', gap: '12px', margin: '14px 0' }}>
                                    <div style={{ flex: 1 }}>
                                      <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>Start Hour (24h Clock, 11 PM = 23):</label>
                                      <input 
                                        type="number" 
                                        min="0" 
                                        max="23" 
                                        value={editParams.start_hour ?? 23} 
                                        onChange={(e) => setEditParams(prev => ({ ...prev, start_hour: parseInt(e.target.value) }))}
                                        className="form-input-field" 
                                        style={{ padding: '8px' }}
                                      />
                                    </div>
                                    <div style={{ flex: 1 }}>
                                      <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>End Hour (24h Clock, 5 AM = 5):</label>
                                      <input 
                                        type="number" 
                                        min="0" 
                                        max="23" 
                                        value={editParams.end_hour ?? 5} 
                                        onChange={(e) => setEditParams(prev => ({ ...prev, end_hour: parseInt(e.target.value) }))}
                                        className="form-input-field" 
                                        style={{ padding: '8px' }}
                                      />
                                    </div>
                                  </div>
                                )}

                                {rule.id === 'R-05' && (
                                  <div className="edit-form-field inline-fields" style={{ display: 'flex', gap: '12px', margin: '14px 0' }}>
                                    <div style={{ flex: 1 }}>
                                      <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>Profile Reads Threshold (Records):</label>
                                      <input 
                                        type="number" 
                                        min="1" 
                                        value={editParams.limit ?? 10} 
                                        onChange={(e) => setEditParams(prev => ({ ...prev, limit: parseInt(e.target.value) }))}
                                        className="form-input-field" 
                                        style={{ padding: '8px' }}
                                      />
                                    </div>
                                    <div style={{ flex: 1 }}>
                                      <label style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: '4px', fontSize: '11px' }}>Sliding Window (Milliseconds):</label>
                                      <input 
                                        type="number" 
                                        min="1000" 
                                        step="1000"
                                        value={editParams.window_ms ?? 10000} 
                                        onChange={(e) => setEditParams(prev => ({ ...prev, window_ms: parseInt(e.target.value) }))}
                                        className="form-input-field" 
                                        style={{ padding: '8px' }}
                                      />
                                    </div>
                                  </div>
                                )}

                                <div className="edit-form-actions" style={{ display: 'flex', gap: '10px', marginTop: '16px' }}>
                                  <button type="submit" className="btn-primary">Save Changes</button>
                                  <button type="button" onClick={() => setEditingRule(null)} className="btn-secondary">Cancel</button>
                                </div>
                              </form>
                            ) : (
                              <div className="rule-card-metrics" style={{ marginTop: '14px' }}>
                                <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '100%' }}>
                                  <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Risk Score Weight:</span>
                                  <span style={{ color: 'var(--text-primary)', fontWeight: 'bold', fontSize: '12px' }}>{rule.weight} / 100 Points</span>
                                  <div className="tooltip-bubble">
                                    <strong className="tooltip-title">Risk Weight Impact</strong>
                                    <span>Added directly to an incident's composite threat score when this rule detects a breach.</span>
                                  </div>
                                </div>
                                
                                {rule.id === 'R-02' && (
                                  <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '100%' }}>
                                    <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Restricted Timeframe:</span>
                                    <span style={{ color: 'var(--text-primary)', fontSize: '12px', fontWeight: '500' }}>
                                      {params.start_hour ?? 23}:00 to {params.end_hour ?? 5}:00 (Overnight)
                                    </span>
                                    <div className="tooltip-bubble">
                                      <strong className="tooltip-title">Restricted Hours</strong>
                                      <span>Access attempts between {params.start_hour ?? 23}:00 and {params.end_hour ?? 5}:00 are automatically flagged.</span>
                                    </div>
                                  </div>
                                )}

                                {rule.id === 'R-05' && (
                                  <div className="metric-row has-tooltip" style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '100%' }}>
                                    <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Alert Limit Threshold:</span>
                                    <span style={{ color: 'var(--text-primary)', fontSize: '12px', fontWeight: '500' }}>
                                      &gt; {params.limit ?? 10} reads / {(params.window_ms ?? 10000) / 1000}s window
                                    </span>
                                    <div className="tooltip-bubble">
                                      <strong className="tooltip-title">Volumetric Threshold</strong>
                                      <span>Triggers when an account queries more than {params.limit ?? 10} records within {(params.window_ms ?? 10000) / 1000} seconds.</span>
                                    </div>
                                  </div>
                                )}

                                <button 
                                  onClick={() => {
                                    setEditingRule(rule);
                                    setEditWeight(rule.weight);
                                    setEditIsEnabled(rule.is_enabled);
                                    setEditParams(params);
                                  }} 
                                  className="btn-secondary"
                                  style={{ width: '100%', marginTop: '14px' }}
                                >
                                  Edit Policy Configurations
                                </button>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* ================= VIEW 4: POLICY RECOMMENDATIONS ================= */}
              {activeTab === 'recommendations' && (
                <div className="dept-analytics-panel animate-fade-in">
                  <div className="view-title-block">
                    <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Lightbulb size={20} color="var(--primary)" /> Proactive Policy Recommendations
                    </h3>
                    <p>AI-driven security enforcement policies automatically generated based on telemetry patterns, anomalous logins, and system configuration rules.</p>
                  </div>

                  {isLoadingRecommendations ? (
                    <div className="rules-grid">
                      {[1, 2, 3].map((n) => (
                        <SkeletonCard key={n} height="190px" />
                      ))}
                    </div>
                  ) : recommendations.length === 0 ? (
                    <div className="app-card" style={{ gridColumn: '1 / -1', padding: '24px' }}>
                      <EmptyState 
                        icon={<CheckCircle2 size={32} color="var(--success)" />} 
                        title="System Fully Optimized" 
                        description="No active policy recommendations at this time. All detection rules and access thresholds are aligned with current employee activity." 
                        actionText="Refresh Recommendations"
                        onAction={fetchRecommendations}
                      />
                    </div>
                  ) : (
                    <div className="rules-grid">
                      {recommendations.map((rec) => {
                        const isHigh = rec.severity === 'High' || rec.severity === 'Critical';
                        return (
                          <div 
                            key={rec.id} 
                            className="app-card rule-config-card"
                            style={{
                              display: 'flex',
                              flexDirection: 'column',
                              justifyContent: 'space-between'
                            }}
                          >
                            <div>
                              <div className="rule-card-header" style={{ marginBottom: '12px' }}>
                                <div>
                                  <span className="rule-card-id" style={{ background: 'var(--primary-glow)', color: 'var(--text-primary)' }}>{rec.id}</span>
                                  <h4 className="card-title" style={{ marginTop: '8px' }}>{rec.title}</h4>
                                </div>
                                <span className="status-badge-indicator" style={{
                                  backgroundColor: rec.severity === 'Critical' 
                                    ? 'rgba(220, 38, 38, 0.2)' 
                                    : rec.severity === 'High' 
                                      ? 'rgba(220, 38, 38, 0.15)' 
                                      : 'rgba(217, 119, 6, 0.15)',
                                  color: isHigh ? 'var(--danger)' : 'var(--warning)'
                                }}>
                                  {rec.severity} Priority
                                </span>
                              </div>

                              <p className="card-subtitle" style={{ marginBottom: '16px' }}>
                                {rec.description}
                              </p>
                            </div>

                            <div style={{ marginTop: 'auto' }}>
                              {user.role === 'System Administrator' ? (
                                <button
                                  onClick={() => handleApplyRecommendation(rec)}
                                  className="btn-primary"
                                  style={{ width: '100%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                                >
                                  <Zap size={14} /> Apply Policy Recommendation
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
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* ================= VIEW 5: EMPLOYEE DIRECTORY ================= */}
              {activeTab === 'employees' && (
                <div>
                  <div className="view-title-block" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
                    <div>
                      <h3>Employee Directory</h3>
                      <p>View employee directories. Sensitive salary column fields are dynamically masked under privacy shielding policies.</p>
                    </div>
                    {(user.role === 'HR Manager' || user.role === 'System Administrator') && (
                      <button 
                        onClick={() => setShowAddEmployeeForm(true)}
                        className="btn-primary"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                      >
                        <Plus size={15} /> Add Employee
                      </button>
                    )}
                  </div>

                  <div className="app-card table-wrapper">
                    {/* Search & Department Filter Toolbar */}
                    <div className="table-toolbar-bar">
                      <div className="search-box-wrapper">
                        <span className="search-icon"><Search size={14} /></span>
                        <input 
                          type="text" 
                          placeholder="Search employees by name, email, or title..." 
                          value={empSearch}
                          onChange={(e) => setEmpSearch(e.target.value)}
                          className="search-input-field"
                        />
                        {empSearch && (
                          <button onClick={() => setEmpSearch('')} className="btn-clear-search" title="Clear Search">×</button>
                        )}
                      </div>

                      <div className="table-filter-pills">
                        {['all', 'IT', 'HR', 'Sales', 'Operations', 'Executive'].map((dept) => (
                          <button
                            key={dept}
                            onClick={() => setEmpDeptFilter(dept)}
                            className={`filter-pill-btn ${empDeptFilter === dept ? 'active' : ''}`}
                          >
                            {dept === 'all' ? `All (${employees.length})` : dept}
                          </button>
                        ))}
                        <button onClick={fetchEmployees} className="btn-actions-refresh" title="Refresh Directory" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                          <RefreshCw size={12} /> Refresh
                        </button>
                      </div>
                    </div>

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
                        {isLoadingEmployees ? (
                          <SkeletonTableRows columns={6} rows={5} />
                        ) : employees.length === 0 ? (
                          <tr>
                            <td colSpan="6" style={{ padding: '30px 10px', textAlign: 'center' }}>
                              <EmptyState 
                                icon={<Users size={32} color="var(--primary)" />} 
                                title="No employees recorded" 
                                description="No employee profiles currently exist in the organization directory." 
                                actionText={(user.role === 'HR Manager' || user.role === 'System Administrator') ? "Add First Employee" : undefined}
                                onAction={() => setShowAddEmployeeForm(true)}
                              />
                            </td>
                          </tr>
                        ) : getFilteredEmployees().length === 0 ? (
                          <tr>
                            <td colSpan="6" style={{ padding: '30px 10px', textAlign: 'center' }}>
                              <NoResultsState 
                                title="No results found" 
                                query={empSearch}
                                entity="employees"
                                onClear={() => { setEmpSearch(''); setEmpDeptFilter('all'); }} 
                              />
                            </td>
                          </tr>
                        ) : (
                          getFilteredEmployees().map((emp) => (
                            <tr key={emp.id} style={emp.is_canary ? { backgroundColor: 'rgba(220, 38, 38, 0.04)' } : {}}>
                              <td data-label="Name" style={{ fontWeight: '700', color: 'var(--text-primary)' }}>
                                {emp.first_name} {emp.last_name}
                                {emp.is_canary && (
                                  <span className="honeypot-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <Radio size={11} /> Honeypot Decoy
                                  </span>
                                )}
                              </td>
                              <td data-label="Department" style={{ color: 'var(--text-secondary)' }}>{emp.department}</td>
                              <td data-label="Position" style={{ color: 'var(--text-secondary)' }}>{emp.position}</td>
                              <td data-label="Hire Date" style={{ color: 'var(--text-secondary)' }}>{new Date(emp.hire_date).toLocaleDateString()}</td>
                              <td data-label="Sensitive Salary" className="salary-val-sensitive">
                                {salaryMap[emp.id] ? (
                                  <span className="visible">${parseFloat(salaryMap[emp.id]).toLocaleString()}</span>
                                ) : (
                                  <span style={{ color: 'var(--text-secondary)' }}>{emp.salary}</span>
                                )}
                              </td>
                              <td data-label="Action">
                                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                  <button 
                                    onClick={() => fetchSensitiveSalary(emp.id)}
                                    className="btn-secondary"
                                    style={{ padding: '6px 12px', fontSize: '11px' }}
                                  >
                                    {salaryMap[emp.id] ? 'Hide Salary' : 'Query Salary'}
                                  </button>
                                  {(user.role === 'HR Manager' || user.role === 'System Administrator') && !emp.is_canary && (
                                    <button 
                                      onClick={() => handleRemoveEmployee(emp.id, `${emp.first_name} ${emp.last_name}`)}
                                      className="btn-danger"
                                      style={{ padding: '6px 12px', fontSize: '11px' }}
                                    >
                                      Remove
                                    </button>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ================= VIEW 6: LEAVE MANAGEMENT ================= */}
              {activeTab === 'leaves' && (
                <div>
                  <div className="view-title-block">
                    <h3>
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
                    <div className="app-card leave-form-card" style={{ marginBottom: '24px' }}>
                      <h4 className="card-title" style={{ marginBottom: '16px' }}>Request New Leave</h4>
                      {(() => {
                        const leaveErrors = getLeaveFormErrors();
                        return (
                          <form onSubmit={handleRequestLeave} noValidate style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'flex-start' }}>
                            <div style={{ flex: '1 1 200px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label htmlFor="leave-type-select" style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>Leave Type</label>
                              <select 
                                id="leave-type-select"
                                value={leaveType} 
                                onChange={(e) => setLeaveType(e.target.value)}
                                className="form-input-field"
                              >
                                <option value="Annual Leave">Annual Leave</option>
                                <option value="Sick Leave">Sick Leave</option>
                                <option value="Casual Leave">Casual Leave</option>
                                <option value="Maternity Leave">Maternity Leave</option>
                              </select>
                            </div>
                            <div style={{ flex: '1 1 150px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label htmlFor="leave-start-date" style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>Start Date</label>
                              <input 
                                id="leave-start-date"
                                type="date" 
                                value={startDate} 
                                aria-invalid={leaveTouched.startDate && !!leaveErrors.startDate}
                                aria-describedby={leaveTouched.startDate && leaveErrors.startDate ? "leave-start-error" : undefined}
                                onBlur={() => setLeaveTouched(prev => ({ ...prev, startDate: true }))}
                                onChange={(e) => {
                                  setStartDate(e.target.value);
                                  setLeaveTouched(prev => ({ ...prev, startDate: true }));
                                }} 
                                required
                                className={`form-input-field ${leaveTouched.startDate && leaveErrors.startDate ? 'input-error' : leaveTouched.startDate && !leaveErrors.startDate ? 'input-valid' : ''}`}
                              />
                              {leaveTouched.startDate && leaveErrors.startDate && (
                                <div className="field-error-msg" id="leave-start-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                  <AlertTriangle size={12} /> {leaveErrors.startDate}
                                </div>
                              )}
                            </div>
                            <div style={{ flex: '1 1 150px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label htmlFor="leave-end-date" style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>End Date</label>
                              <input 
                                id="leave-end-date"
                                type="date" 
                                value={endDate} 
                                aria-invalid={leaveTouched.endDate && !!leaveErrors.endDate}
                                aria-describedby={leaveTouched.endDate && leaveErrors.endDate ? "leave-end-error" : undefined}
                                onBlur={() => setLeaveTouched(prev => ({ ...prev, endDate: true }))}
                                onChange={(e) => {
                                  setEndDate(e.target.value);
                                  setLeaveTouched(prev => ({ ...prev, endDate: true }));
                                }} 
                                required
                                className={`form-input-field ${leaveTouched.endDate && leaveErrors.endDate ? 'input-error' : leaveTouched.endDate && !leaveErrors.endDate ? 'input-valid' : ''}`}
                              />
                              {leaveTouched.endDate && leaveErrors.endDate && (
                                <div className="field-error-msg" id="leave-end-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                  <AlertTriangle size={12} /> {leaveErrors.endDate}
                                </div>
                              )}
                            </div>
                            <div style={{ flex: '1 1 100%', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label htmlFor="leave-reason-input" style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)' }}>Reason / Notes</label>
                              <textarea 
                                id="leave-reason-input"
                                value={reason} 
                                aria-invalid={leaveTouched.reason && !!leaveErrors.reason}
                                aria-describedby={leaveTouched.reason && leaveErrors.reason ? "leave-reason-error" : undefined}
                                onBlur={() => setLeaveTouched(prev => ({ ...prev, reason: true }))}
                                onChange={(e) => {
                                  setReason(e.target.value);
                                  setLeaveTouched(prev => ({ ...prev, reason: true }));
                                }} 
                                required
                                placeholder="Enter reason for leave (minimum 5 characters)..."
                                className={`form-input-field ${leaveTouched.reason && leaveErrors.reason ? 'input-error' : leaveTouched.reason && !leaveErrors.reason ? 'input-valid' : ''}`}
                                style={{ minHeight: '80px', resize: 'vertical' }}
                              />
                              {leaveTouched.reason && leaveErrors.reason && (
                                <div className="field-error-msg" id="leave-reason-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                  <AlertTriangle size={12} /> {leaveErrors.reason}
                                </div>
                              )}
                            </div>
                            <button 
                              type="submit" 
                              className="btn-primary"
                              style={{ alignSelf: 'flex-start' }}
                            >
                              Submit Leave Request
                            </button>
                          </form>
                        );
                      })()}
                    </div>
                  )}

                  <div className="app-card table-wrapper">
                    {/* Search & Status Filter Toolbar */}
                    <div className="table-toolbar-bar">
                      <div className="search-box-wrapper">
                        <span className="search-icon"><Search size={14} /></span>
                        <input 
                          type="text" 
                          placeholder="Search leave requests by employee or reason..." 
                          value={leaveSearch}
                          onChange={(e) => setLeaveSearch(e.target.value)}
                          className="search-input-field"
                        />
                        {leaveSearch && (
                          <button onClick={() => setLeaveSearch('')} className="btn-clear-search" title="Clear Search">×</button>
                        )}
                      </div>

                      <div className="table-filter-pills">
                        {['all', 'Pending', 'Approved', 'Rejected'].map((status) => (
                          <button
                            key={status}
                            onClick={() => setLeaveStatusFilter(status)}
                            className={`filter-pill-btn ${leaveStatusFilter === status ? 'active' : ''}`}
                          >
                            {status === 'all' ? `All (${leaves.length})` : status}
                          </button>
                        ))}
                        <button onClick={fetchLeaves} className="btn-actions-refresh" title="Refresh Leaves" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                          <RefreshCw size={12} /> Refresh
                        </button>
                      </div>
                    </div>

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
                        {isLoadingLeaves ? (
                          <SkeletonTableRows columns={(user.role === 'HR Manager' || user.role === 'System Administrator') ? 7 : 6} rows={4} />
                        ) : leaves.length === 0 ? (
                          <tr>
                            <td colSpan={(user.role === 'HR Manager' || user.role === 'System Administrator') ? 7 : 6} style={{ padding: '30px 10px', textAlign: 'center' }}>
                              <EmptyState 
                                icon={<Calendar size={32} color="var(--primary)" />} 
                                title="No leave requests" 
                                description="No employee leave requests have been submitted for this period." 
                              />
                            </td>
                          </tr>
                        ) : getFilteredLeaves().length === 0 ? (
                          <tr>
                            <td colSpan={(user.role === 'HR Manager' || user.role === 'System Administrator') ? 7 : 6} style={{ padding: '30px 10px', textAlign: 'center' }}>
                              <NoResultsState 
                                title="No results found" 
                                query={leaveSearch}
                                entity="leave requests"
                                onClear={() => { setLeaveSearch(''); setLeaveStatusFilter('all'); }} 
                              />
                            </td>
                          </tr>
                        ) : (
                          getFilteredLeaves().map((l) => (
                            <tr key={l.id}>
                              <td data-label="Employee" style={{ fontWeight: '700', color: 'var(--text-primary)' }}>{l.employee_name}</td>
                              <td data-label="Leave Type" style={{ color: 'var(--text-secondary)' }}>{l.leave_type}</td>
                              <td data-label="Start Date" style={{ color: 'var(--text-secondary)' }}>{new Date(l.start_date).toLocaleDateString()}</td>
                              <td data-label="End Date" style={{ color: 'var(--text-secondary)' }}>{new Date(l.end_date).toLocaleDateString()}</td>
                              <td data-label="Reason" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{l.reason}</td>
                              <td data-label="Status">
                                <span className={`status-indicator ${l.status.toLowerCase()}`}>
                                  {l.status}
                                </span>
                              </td>
                              {(user.role === 'HR Manager' || user.role === 'System Administrator') && (
                                <td data-label="Actions">
                                  {l.status === 'Pending' && (
                                    <div style={{ display: 'flex', gap: '8px' }}>
                                      <button 
                                        onClick={() => handleLeaveDecision(l.id, 'Approved')}
                                        className="btn-success"
                                      >
                                        Approve
                                      </button>
                                      <button 
                                        onClick={() => handleLeaveDecision(l.id, 'Rejected')}
                                        className="btn-danger"
                                      >
                                        Reject
                                      </button>
                                    </div>
                                  )}
                                </td>
                              )}
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="footer">
        <span>© 2026 DataLens HR.</span>
        {token && <span>Secure Session Audit Active (RBAC Level {user ? user.role : 'Guest'})</span>}
      </footer>

      {/* Add Employee Modal Overlay */}
      {showAddEmployeeForm && (user.role === 'HR Manager' || user.role === 'System Administrator') && (
        <div 
          className="modal-backdrop" 
          onClick={(e) => {
            if (e.target.className === 'modal-backdrop') {
              setShowAddEmployeeForm(false);
            }
          }}
        >
          <div className="modal-card animate-scale-up" role="dialog" aria-modal="true" aria-labelledby="modal-add-emp-title">
            <div className="modal-header">
              <h3 id="modal-add-emp-title">Add New Employee</h3>
              <button 
                onClick={() => setShowAddEmployeeForm(false)} 
                className="btn-close"
                aria-label="Close add employee modal"
                style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}
              >
                <X size={18} />
              </button>
            </div>
            {(() => {
              const empErrors = getEmpFormErrors();
              return (
                <form onSubmit={handleAddEmployee} noValidate className="modal-form">
                  <div className="form-group">
                    <label htmlFor="new-emp-first-name">First Name</label>
                    <input 
                      id="new-emp-first-name"
                      type="text" 
                      placeholder="e.g. Emma"
                      value={newEmpFirstName} 
                      aria-invalid={empFormTouched.first_name && !!empErrors.first_name}
                      aria-describedby={empFormTouched.first_name && empErrors.first_name ? "first-name-error" : undefined}
                      onBlur={() => setEmpFormTouched(prev => ({ ...prev, first_name: true }))}
                      onChange={(e) => {
                        setNewEmpFirstName(e.target.value);
                        setEmpFormTouched(prev => ({ ...prev, first_name: true }));
                      }} 
                      className={`form-input-field ${empFormTouched.first_name && empErrors.first_name ? 'input-error' : empFormTouched.first_name && !empErrors.first_name ? 'input-valid' : ''}`}
                      required 
                    />
                    {empFormTouched.first_name && empErrors.first_name && (
                      <div className="field-error-msg" id="first-name-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={12} /> {empErrors.first_name}
                      </div>
                    )}
                  </div>

                  <div className="form-group">
                    <label htmlFor="new-emp-last-name">Last Name</label>
                    <input 
                      id="new-emp-last-name"
                      type="text" 
                      placeholder="e.g. Watson"
                      value={newEmpLastName} 
                      aria-invalid={empFormTouched.last_name && !!empErrors.last_name}
                      aria-describedby={empFormTouched.last_name && empErrors.last_name ? "last-name-error" : undefined}
                      onBlur={() => setEmpFormTouched(prev => ({ ...prev, last_name: true }))}
                      onChange={(e) => {
                        setNewEmpLastName(e.target.value);
                        setEmpFormTouched(prev => ({ ...prev, last_name: true }));
                      }} 
                      className={`form-input-field ${empFormTouched.last_name && empErrors.last_name ? 'input-error' : empFormTouched.last_name && !empErrors.last_name ? 'input-valid' : ''}`}
                      required 
                    />
                    {empFormTouched.last_name && empErrors.last_name && (
                      <div className="field-error-msg" id="last-name-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={12} /> {empErrors.last_name}
                      </div>
                    )}
                  </div>

                  <div className="form-group full-width">
                    <label htmlFor="new-emp-email">Email Address</label>
                    <input 
                      id="new-emp-email"
                      type="email" 
                      placeholder="emma.watson@datalenshr.com"
                      value={newEmpEmail} 
                      aria-invalid={empFormTouched.email && !!empErrors.email}
                      aria-describedby={empFormTouched.email && empErrors.email ? "email-error" : undefined}
                      onBlur={() => setEmpFormTouched(prev => ({ ...prev, email: true }))}
                      onChange={(e) => {
                        setNewEmpEmail(e.target.value);
                        setEmpFormTouched(prev => ({ ...prev, email: true }));
                      }} 
                      className={`form-input-field ${empFormTouched.email && empErrors.email ? 'input-error' : empFormTouched.email && !empErrors.email ? 'input-valid' : ''}`}
                      required 
                    />
                    {empFormTouched.email && empErrors.email && (
                      <div className="field-error-msg" id="email-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={12} /> {empErrors.email}
                      </div>
                    )}
                  </div>

                  <div className="form-group">
                    <label htmlFor="new-emp-dept">Department</label>
                    <select 
                      id="new-emp-dept"
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
                    <label htmlFor="new-emp-position">Position Title</label>
                    <input 
                      id="new-emp-position"
                      type="text" 
                      placeholder="e.g. HR Director"
                      value={newEmpPosition} 
                      aria-invalid={empFormTouched.position && !!empErrors.position}
                      aria-describedby={empFormTouched.position && empErrors.position ? "position-error" : undefined}
                      onBlur={() => setEmpFormTouched(prev => ({ ...prev, position: true }))}
                      onChange={(e) => {
                        setNewEmpPosition(e.target.value);
                        setEmpFormTouched(prev => ({ ...prev, position: true }));
                      }} 
                      className={`form-input-field ${empFormTouched.position && empErrors.position ? 'input-error' : empFormTouched.position && !empErrors.position ? 'input-valid' : ''}`}
                      required 
                    />
                    {empFormTouched.position && empErrors.position && (
                      <div className="field-error-msg" id="position-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={12} /> {empErrors.position}
                      </div>
                    )}
                  </div>

                  <div className="form-group">
                    <label htmlFor="new-emp-salary">Sensitive Annual Salary ($)</label>
                    <input 
                      id="new-emp-salary"
                      type="number" 
                      placeholder="e.g. 185000"
                      value={newEmpSalary} 
                      aria-invalid={empFormTouched.salary && !!empErrors.salary}
                      aria-describedby={empFormTouched.salary && empErrors.salary ? "salary-error" : undefined}
                      onBlur={() => setEmpFormTouched(prev => ({ ...prev, salary: true }))}
                      onChange={(e) => {
                        setNewEmpSalary(e.target.value);
                        setEmpFormTouched(prev => ({ ...prev, salary: true }));
                      }} 
                      className={`form-input-field ${empFormTouched.salary && empErrors.salary ? 'input-error' : empFormTouched.salary && !empErrors.salary ? 'input-valid' : ''}`}
                      required 
                    />
                    {empFormTouched.salary && empErrors.salary && (
                      <div className="field-error-msg" id="salary-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={12} /> {empErrors.salary}
                      </div>
                    )}
                  </div>

                  <div className="form-group">
                    <label htmlFor="new-emp-hire-date">Hire Date</label>
                    <input 
                      id="new-emp-hire-date"
                      type="date" 
                      value={newEmpHireDate} 
                      aria-invalid={empFormTouched.hire_date && !!empErrors.hire_date}
                      aria-describedby={empFormTouched.hire_date && empErrors.hire_date ? "hire-date-error" : undefined}
                      onBlur={() => setEmpFormTouched(prev => ({ ...prev, hire_date: true }))}
                      onChange={(e) => {
                        setNewEmpHireDate(e.target.value);
                        setEmpFormTouched(prev => ({ ...prev, hire_date: true }));
                      }} 
                      className={`form-input-field ${empFormTouched.hire_date && empErrors.hire_date ? 'input-error' : empFormTouched.hire_date && !empErrors.hire_date ? 'input-valid' : ''}`}
                      required 
                    />
                    {empFormTouched.hire_date && empErrors.hire_date && (
                      <div className="field-error-msg" id="hire-date-error" role="alert" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={12} /> {empErrors.hire_date}
                      </div>
                    )}
                  </div>

                  <div className="modal-actions">
                    <button 
                      type="button" 
                      onClick={() => setShowAddEmployeeForm(false)} 
                      className="btn-modal-cancel"
                    >
                      Cancel
                    </button>
                    <button 
                      type="submit" 
                      className="btn-modal-submit"
                    >
                      Add Employee
                    </button>
                  </div>
                </form>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
