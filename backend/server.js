// DataLens HR Backend Service - Version 1.0.1
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const pg = require('pg');
pg.types.setTypeParser(20, val => parseInt(val, 10)); // Parse bigint (int8) as number
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT']
  }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey123!@#';

// PostgreSQL Connection Pool wrapped to mimic mysql2/promise API
const pgPool = new pg.Pool(process.env.DATABASE_URL ? {
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
} : {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME || 'datalens_hr',
  port: parseInt(process.env.DB_PORT || '5432'),
  max: 15
});

const pool = {
  async query(text, params) {
    let pgText = text;
    if (params && Array.isArray(params)) {
      // Replace sequential MySQL '?' placeholders with Postgres '$1', '$2', ...
      const parts = text.split('?');
      if (parts.length - 1 === params.length) {
        pgText = parts.reduce((acc, part, i) => {
          if (i === 0) return part;
          return acc + '$' + i + part;
        }, '');
      }
    }
    const res = await pgPool.query(pgText, params);
    return [res.rows, null];
  },
  async end() {
    await pgPool.end();
  }
};

// Middleware
app.use(cors());
app.use(express.json());

// In-Memory Tracking for Volumetric Scraping and Failed Logins
const userRequestCounts = {}; // format: { userId: [timestamps] }
const ipFailedLogins = {};    // format: { ipAddress: [timestamps] }

// Helper for Parsing Geolocation & Browser Fingerprints
function parseClientMetadata(req) {
  const userAgent = req.headers['user-agent'] || 'Unknown Browser';
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  
  // Basic mock browser parser
  let browser = 'Chrome';
  if (userAgent.includes('Firefox')) browser = 'Firefox';
  else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) browser = 'Safari';
  else if (userAgent.includes('Edge')) browser = 'Edge';

  let os = 'Windows';
  if (userAgent.includes('Macintosh')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';
  
  // Dynamic mock locations to simulate different places
  let country = 'Sri Lanka';
  let city = 'Colombo';
  
  if (req.headers['x-simulate-location']) {
    const loc = req.headers['x-simulate-location'].split(',');
    city = loc[0].trim();
    country = loc[1] ? loc[1].trim() : 'International';
  }

  return { ip, device: `${browser} on ${os}`, country, city, userAgent };
}

// Token Verification Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    req.user = null;
    return next();
  }
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      req.user = null;
    } else {
      req.user = decoded;
    }
    next();
  });
};

app.use(authenticateToken);

// Real-Time Threat Analysis & Dynamic Risk Scoring Engine
async function analyzePrivacyThreats(req, user, actionType, recordsAccessed = 0) {
  const metadata = parseClientMetadata(req);
  const now = new Date();
  const currentHour = now.getHours();
  
  const triggeredRules = [];
  const rawEvidence = {
    action: actionType,
    recordsAccessed,
    metadata,
    time: now.toISOString()
  };

  // 1. Rule R-02: Unusual Working Hours (Access between 11 PM and 5 AM)
  if (currentHour >= 23 || currentHour < 5) {
    triggeredRules.push({
      id: 'R-02',
      name: 'UNUSUAL_HOURS',
      description: `Access requested at ${now.toLocaleTimeString()} outside standard hours (07:00 - 19:00)`,
      weight: 15
    });
  }

  // 2. Rule R-04: Salary Probing (Attempt to access unauthorized sensitive fields)
  if (actionType === 'UNAUTHORIZED_SALARY_READ') {
    triggeredRules.push({
      id: 'R-04',
      name: 'SPI_SALARY_PROBE',
      description: `Access restriction violation: Unauthorized read attempt on salary endpoint.`,
      weight: 40
    });
  }

  // 3. Rule R-05: Volumetric Scraping (e.g., > 10 profile reads within 10 seconds)
  if (user && actionType === 'PROFILE_READ') {
    const userId = user.id;
    const windowMs = 10000; // 10 seconds sliding window
    if (!userRequestCounts[userId]) userRequestCounts[userId] = [];
    
    // Clear expired timestamps
    userRequestCounts[userId] = userRequestCounts[userId].filter(t => now - t < windowMs);
    userRequestCounts[userId].push(now);
    
    if (userRequestCounts[userId].length > 10) {
      triggeredRules.push({
        id: 'R-05',
        name: 'VOLUMETRIC_SCRAPE',
        description: `High access rate: accessed ${userRequestCounts[userId].length} records in 10s.`,
        weight: 45
      });
      rawEvidence.volumeDetails = `${userRequestCounts[userId].length} hits/10s`;
    }
  }

  // 4. Rule R-06: Canary honeypot access (Fetching decoy record)
  if (actionType === 'CANARY_ACCESS') {
    triggeredRules.push({
      id: 'R-06',
      name: 'CANARY_ACCESS',
      description: `Decoy Canary profile accessed (John Doe - Senior Executive VP).`,
      weight: 80
    });
  }

  // 5. Rule R-03: Impossible Travel / Geolocational anomaly
  if (req.headers['x-simulate-impossible-travel'] === 'true') {
    triggeredRules.push({
      id: 'R-03',
      name: 'IMPOSSIBLE_TRAVEL',
      description: `Impossible geolocational speed: Login location switched from Colombo to Tokyo in 5 mins.`,
      weight: 50
    });
  }

  // Calculate composite risk score
  if (triggeredRules.length === 0) return null;

  // Let role-based vulnerabilities dynamic multiplier apply
  let roleMultiplier = 1.0;
  if (user) {
    if (user.role === 'System Administrator') roleMultiplier = 1.4;
    else if (user.role === 'HR Manager') roleMultiplier = 1.25;
  }
  
  const sumWeights = triggeredRules.reduce((acc, rule) => acc + rule.weight, 0);
  const compositeScore = Math.min(100, Math.round(sumWeights * roleMultiplier));

  let riskLevel = 'Low';
  if (compositeScore >= 70) riskLevel = 'High';
  else if (compositeScore >= 40) riskLevel = 'Medium';

  const recommendedActions = [];
  if (riskLevel === 'High') {
    recommendedActions.push('Lock the account temporarily', 'Terminate active sessions', 'Notify HR Manager immediately');
  } else if (riskLevel === 'Medium') {
    recommendedActions.push('Force a password reset', 'Enable dynamic data masking');
  } else {
    recommendedActions.push('Review audit logs');
  }

  // Insert Incident report
  const incidentId = require('crypto').randomUUID();
  try {
    const rulesJson = JSON.stringify(triggeredRules.map(r => r.name));
    const evidenceJson = JSON.stringify(rawEvidence);
    const actionsJson = JSON.stringify(recommendedActions);
    
    await pool.query(
      `INSERT INTO security_incidents 
       (id, user_id, triggered_rules, raw_evidence, risk_score, risk_level, recommended_actions, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')`,
      [incidentId, user ? user.id : null, rulesJson, evidenceJson, compositeScore, riskLevel, actionsJson]
    );

    // Apply automated lock if High Risk
    if (riskLevel === 'High' && user) {
      const lockDurationMinutes = 15;
      const lockedUntil = new Date(Date.now() + lockDurationMinutes * 60000);
      await pool.query(
        'UPDATE users SET is_active = FALSE, locked_until = ? WHERE id = ?',
        [lockedUntil, user.id]
      );
      console.log(`[MITIGATION] User account ${user.email} locked until ${lockedUntil.toISOString()}`);
    }

    // Broadcast WebSocket Incident Event
    const websocketPayload = {
      id: incidentId,
      detected_at: now.toISOString(),
      user_email: user ? user.email : 'Anonymous',
      user_role: user ? user.role : 'Guest',
      risk_score: compositeScore,
      risk_level: riskLevel,
      triggered_rules: triggeredRules.map(r => r.name),
      evidence: rawEvidence,
      recommended_actions: recommendedActions,
      status: 'Open'
    };
    
    io.emit('NEW_INCIDENT', websocketPayload);
    console.log(`[ALERT] High-risk security incident broadcasted: ${riskLevel} (${compositeScore})`);

  } catch (err) {
    console.error('[DB ERR] Failed to insert incident:', err.message);
  }

  return { riskLevel, score: compositeScore };
}

// Audit Log Database Insertion Helper
async function insertAuditLog(req, user, actionType, recordsAccessed = 0) {
  const metadata = parseClientMetadata(req);
  try {
    await pool.query(
      `INSERT INTO audit_logs 
       (user_id, user_role, ip_address, device_browser, location_country, location_city, request_path, request_method, records_accessed, action_type)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user ? user.id : null,
        user ? user.role : 'Guest',
        metadata.ip,
        metadata.device,
        metadata.country,
        metadata.city,
        req.path,
        req.method,
        recordsAccessed,
        actionType
      ]
    );
  } catch (err) {
    console.error('[DB ERR] Failed to write audit log:', err.message);
  }
}

// ---------------- API ENDPOINTS ----------------

// 1. Setup Mock User Seeds (Invoked automatically if database is empty)
async function seedMockData() {
  try {
    const [rows] = await pool.query('SELECT COUNT(*) as count FROM users');
    if (rows[0].count === 0) {
      console.log('[SEED] Seeding database with mock employees & users...');
      
      const adminId = '11111111-1111-1111-1111-111111111111';
      const managerId = '22222222-2222-2222-2222-222222222222';
      const staffId = '33333333-3333-3333-3333-333333333333';
      const employeeUserId = '44444444-4444-4444-4444-444444444444';

      const hashedPw = await bcrypt.hash('admin123', 10);

      // Seed Users (Roles map: 1=SysAdmin, 2=HRManager, 3=HRStaff, 4=Employee)
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 1)', [adminId, 'admin@datalenshr.com', hashedPw]);
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 2)', [managerId, 'manager@datalenshr.com', hashedPw]);
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 3)', [staffId, 'staff@datalenshr.com', hashedPw]);
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 4)', [employeeUserId, 'employee@datalenshr.com', hashedPw]);

      // Seed Employees
      await pool.query(
        `INSERT INTO employees (id, user_id, first_name, last_name, department, position, salary, email, phone, hire_date, is_canary)
         VALUES 
         ('e1', '${managerId}', 'Emma', 'Watson', 'HR Department', 'HR Director', 185000.00, 'manager@datalenshr.com', '+94 77 123 4567', '2020-01-15', FALSE),
         ('e2', '${staffId}', 'Sarah', 'Connor', 'HR Department', 'HR Assistant', 85000.00, 'staff@datalenshr.com', '+94 77 987 6543', '2023-06-10', FALSE),
         ('e3', '${employeeUserId}', 'David', 'Beckham', 'Sales', 'Account Executive', 65000.00, 'employee@datalenshr.com', '+94 71 555 4321', '2021-08-20', FALSE),
         ('e4', NULL, 'Jane', 'Doe', 'Executive', 'Senior Executive VP (Honeypot)', 350000.00, 'jane.doe@datalenshr.com', '+94 77 111 2222', '2019-11-01', TRUE)` // Canary profile
      );

      // Seed Leaves
      await pool.query(
        `INSERT INTO leave_requests (id, employee_id, leave_type, start_date, end_date, status, reason)
         VALUES 
         ('l1', 'e3', 'Annual Leave', '2026-08-10', '2026-08-15', 'Pending', 'Family vacation abroad')`
      );

      console.log('[SEED] Seeding completed.');
    }
  } catch (err) {
    console.error('[SEED ERR] Seeding failed:', err.message);
  }
}

// Database Connection & Health Verification
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date(), service: 'DataLens HR Privacy Engine' });
});

app.get('/api/db-status', async (req, res) => {
  try {
    await seedMockData();
    const [rows] = await pool.query('SELECT NOW() as now');
    res.json({ status: 'connected', time: rows[0].now });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 2. Auth Login API
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const metadata = parseClientMetadata(req);
  
  try {
    const [users] = await pool.query(
      `SELECT u.*, r.name as role 
       FROM users u 
       JOIN roles r ON u.role_id = r.id 
       WHERE u.email = ?`,
      [email]
    );

    if (users.length === 0) {
      await insertAuditLog(req, null, 'LOGIN_FAILED', 0);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];

    // Check account lockout status
    if (user.locked_until) {
      if (new Date(user.locked_until) > new Date()) {
        await insertAuditLog(req, user, 'LOGIN_ATTEMPT_LOCKED_OUT', 0);
        return res.status(403).json({ 
          message: `Account is temporarily locked due to security anomalies. Try again after ${new Date(user.locked_until).toLocaleTimeString()}.`
        });
      } else {
        // Lockout expired, reactivate user
        await pool.query('UPDATE users SET is_active = TRUE, locked_until = NULL WHERE id = ?', [user.id]);
        user.is_active = 1;
        user.locked_until = null;
      }
    }

    if (!user.is_active) {
      await insertAuditLog(req, user, 'LOGIN_FAILED_DEACTIVATED', 0);
      return res.status(403).json({ message: 'Session suspended. High security threat detected.' });
    }

    // Verify Password
    const isPwValid = await bcrypt.compare(password, user.password_hash);
    if (!isPwValid) {
      await insertAuditLog(req, user, 'LOGIN_FAILED', 0);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create session JWT token
    const tokenPayload = { id: user.id, email: user.email, role: user.role };
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });

    await insertAuditLog(req, tokenPayload, 'LOGIN_SUCCESS', 0);

    res.json({ token, user: { email: user.email, role: user.role, id: user.id } });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Auth Bypass Lockout API (Demo helper)
app.post('/api/auth/bypass-lockout', async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query('UPDATE users SET is_active = TRUE, locked_until = NULL WHERE email = ?', [email]);
    res.json({ message: 'Lockout bypassed successfully. You can now login.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 3. Employee Directory Endpoints
app.get('/api/employees', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

  try {
    // Verify user lockout state in DB
    const [dbUsers] = await pool.query('SELECT is_active, locked_until FROM users WHERE id = ?', [req.user.id]);
    if (dbUsers.length > 0) {
      let isActive = dbUsers[0].is_active;
      let lockedUntil = dbUsers[0].locked_until;
      if (lockedUntil && new Date(lockedUntil) < new Date()) {
        await pool.query('UPDATE users SET is_active = TRUE, locked_until = NULL WHERE id = ?', [req.user.id]);
        isActive = 1;
        lockedUntil = null;
      }
      if (!isActive || (lockedUntil && new Date(lockedUntil) > new Date())) {
        return res.status(403).json({ message: 'Session suspended. High security threat detected.' });
      }
    }

    // Dynamic audit logs mapping
    await insertAuditLog(req, req.user, 'DIRECTORY_READ', 0);
    
    // Check volumetric scraping
    const threat = await analyzePrivacyThreats(req, req.user, 'PROFILE_READ', 5);
    let forceMask = false;
    
    if (threat && threat.riskLevel === 'High') {
      return res.status(403).json({ message: 'Session suspended. High security threat detected.' });
    } else if (threat && threat.riskLevel === 'Medium') {
      forceMask = true;
    }

    const [employees] = await pool.query('SELECT * FROM employees');
    
    // Apply dynamic role-based data masking or dynamic risk masking
    const maskedEmployees = employees.map(emp => {
      const isOwner = emp.user_id === req.user.id;
      const isPrivileged = req.user.role === 'HR Manager' || req.user.role === 'System Administrator';

      const returnEmp = { ...emp };
      
      if (!isOwner && !isPrivileged || forceMask) {
        // Mask Salary completely
        returnEmp.salary = '***.***';
      }
      return returnEmp;
    });

    res.json(maskedEmployees);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/employees - Add new employee (Privileged: HR Manager / System Administrator)
app.post('/api/employees', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

  const isPrivileged = req.user.role === 'HR Manager' || req.user.role === 'System Administrator';
  if (!isPrivileged) {
    return res.status(403).json({ message: 'Access denied: HR Manager permissions required.' });
  }

  const { first_name, last_name, department, position, salary, email, hire_date } = req.body;
  if (!first_name || !last_name || !email || !salary || !hire_date) {
    return res.status(400).json({ message: 'Missing required employee fields.' });
  }

  try {
    const [existing] = await pool.query('SELECT id FROM employees WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'An employee with this email already exists.' });
    }

    const employeeId = require('crypto').randomUUID();
    await pool.query(
      `INSERT INTO employees (id, user_id, first_name, last_name, department, position, salary, email, hire_date, is_canary)
       VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, FALSE)`,
      [employeeId, first_name, last_name, department, position, parseFloat(salary), email, hire_date]
    );

    await insertAuditLog(req, req.user, 'CREATE_EMPLOYEE', 1);
    res.status(201).json({ message: 'Employee added successfully', id: employeeId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /api/employees/:id - Remove employee (Privileged: HR Manager / System Administrator)
app.delete('/api/employees/:id', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

  const isPrivileged = req.user.role === 'HR Manager' || req.user.role === 'System Administrator';
  if (!isPrivileged) {
    return res.status(403).json({ message: 'Access denied: HR Manager permissions required.' });
  }

  const employeeId = req.params.id;

  try {
    const [existing] = await pool.query('SELECT first_name, last_name FROM employees WHERE id = ?', [employeeId]);
    if (existing.length === 0) {
      return res.status(404).json({ message: 'Employee not found.' });
    }

    await pool.query('DELETE FROM employees WHERE id = ?', [employeeId]);
    await insertAuditLog(req, req.user, 'DELETE_EMPLOYEE', 1);
    res.json({ message: `Employee ${existing[0].first_name} ${existing[0].last_name} removed successfully.` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Sensitive Salary Endpoint (Demonstrates explicit RBAC control + unauthorized alert logs)
app.get('/api/employees/:id/salary', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

  const employeeId = req.params.id;
  const isPrivileged = req.user.role === 'HR Manager' || req.user.role === 'System Administrator';

  try {
    // Verify user lockout state in DB
    const [dbUsers] = await pool.query('SELECT is_active, locked_until FROM users WHERE id = ?', [req.user.id]);
    if (dbUsers.length > 0) {
      let isActive = dbUsers[0].is_active;
      let lockedUntil = dbUsers[0].locked_until;
      if (lockedUntil && new Date(lockedUntil) < new Date()) {
        await pool.query('UPDATE users SET is_active = TRUE, locked_until = NULL WHERE id = ?', [req.user.id]);
        isActive = 1;
        lockedUntil = null;
      }
      if (!isActive || (lockedUntil && new Date(lockedUntil) > new Date())) {
        return res.status(403).json({ message: 'Session suspended. High security threat detected.' });
      }
    }
    const [emps] = await pool.query('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (emps.length === 0) return res.status(404).json({ message: 'Employee not found' });
    const emp = emps[0];
    const isOwner = emp.user_id === req.user.id;

    // Honeypot Canary Access Check
    if (emp.is_canary && !isPrivileged) {
      await analyzePrivacyThreats(req, req.user, 'CANARY_ACCESS', 1);
      return res.status(403).json({ message: 'Session suspended. High security threat detected.' });
    }

    if (!isPrivileged && !isOwner) {
      // Alert rules engine that an unauthorized salary access was attempted!
      await analyzePrivacyThreats(req, req.user, 'UNAUTHORIZED_SALARY_READ', 1);
      await insertAuditLog(req, req.user, 'UNAUTHORIZED_SALARY_READ_ATTEMPT', 1);
      return res.status(403).json({ message: 'Access denied: Insufficient role permissions.' });
    }

    await insertAuditLog(req, req.user, 'SALARY_READ', 1);
    res.json({ salary: emp.salary });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 4. Leave Requests API
app.get('/api/leaves', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const isPrivileged = req.user.role === 'HR Manager' || req.user.role === 'System Administrator';
    await insertAuditLog(req, req.user, 'LEAVE_READ', 0);
    
    if (isPrivileged) {
      const [leaves] = await pool.query(
        `SELECT lr.*, CONCAT(e.first_name, ' ', e.last_name) as employee_name 
         FROM leave_requests lr
         JOIN employees e ON lr.employee_id = e.id
         ORDER BY lr.created_at DESC`
      );
      return res.json(leaves);
    } else {
      // Find current user's employee record
      const [emps] = await pool.query('SELECT id FROM employees WHERE user_id = ?', [req.user.id]);
      if (emps.length === 0) {
        return res.json([]); // Return empty list if no profile matches
      }
      const employeeId = emps[0].id;
      const [leaves] = await pool.query(
        `SELECT lr.*, CONCAT(e.first_name, ' ', e.last_name) as employee_name 
         FROM leave_requests lr
         JOIN employees e ON lr.employee_id = e.id
         WHERE lr.employee_id = ?
         ORDER BY lr.created_at DESC`,
        [employeeId]
      );
      return res.json(leaves);
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/leaves', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });

  const { leave_type, start_date, end_date, reason } = req.body;
  if (!leave_type || !start_date || !end_date) {
    return res.status(400).json({ message: 'Missing required leave fields.' });
  }

  try {
    const [emps] = await pool.query('SELECT id FROM employees WHERE user_id = ?', [req.user.id]);
    if (emps.length === 0) {
      return res.status(404).json({ message: 'Employee profile not found.' });
    }
    const employeeId = emps[0].id;
    const leaveId = require('crypto').randomUUID();

    await pool.query(
      `INSERT INTO leave_requests (id, employee_id, leave_type, start_date, end_date, reason, status)
       VALUES (?, ?, ?, ?, ?, ?, 'Pending')`,
      [leaveId, employeeId, leave_type, start_date, end_date, reason]
    );

    await insertAuditLog(req, req.user, 'LEAVE_REQUEST_CREATE', 1);
    res.json({ message: 'Leave request submitted successfully.', leaveId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/leaves/:id/status', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role !== 'HR Manager' && req.user.role !== 'System Administrator') {
    return res.status(403).json({ message: 'Access denied.' });
  }

  const { status } = req.body;
  const leaveId = req.params.id;

  if (status !== 'Approved' && status !== 'Rejected') {
    return res.status(400).json({ message: 'Invalid status update.' });
  }

  try {
    await pool.query('UPDATE leave_requests SET status = ? WHERE id = ?', [status, leaveId]);
    await insertAuditLog(req, req.user, `LEAVE_${status.toUpperCase()}`, 1);
    res.json({ message: `Leave request status updated to ${status}.` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 5. Security Incidents API (For the dashboard)
app.get('/api/incidents', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role !== 'System Administrator' && req.user.role !== 'HR Manager') {
    return res.status(403).json({ message: 'Access denied.' });
  }

  try {
    const [incidents] = await pool.query(
      `SELECT si.*, u.email as user_email, r.name as user_role
       FROM security_incidents si
       LEFT JOIN users u ON si.user_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       ORDER BY si.detected_at DESC`
    );
    res.json(incidents);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Manually trigger dynamic mitigations
app.post('/api/incidents/:id/mitigate', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role !== 'System Administrator') {
    return res.status(403).json({ message: 'Access denied: Admin control only.' });
  }

  const incidentId = req.params.id;
  const { action, userId } = req.body;

  try {
    if (action === 'LOCK_USER' && userId) {
      const lockDurationMinutes = 15;
      const lockedUntil = new Date(Date.now() + lockDurationMinutes * 60000);
      await pool.query('UPDATE users SET is_active = FALSE, locked_until = ? WHERE id = ?', [lockedUntil, userId]);
      await pool.query("UPDATE security_incidents SET status = 'Resolved', mitigation_executed = TRUE, notes = ? WHERE id = ?", [`Manual Mitigated: locked account until ${lockedUntil.toLocaleTimeString()}`, incidentId]);
      
      io.emit('INCIDENT_RESOLVED', { id: incidentId, note: 'User Locked Successfully' });
      return res.json({ message: 'User account has been locked for 15 minutes.' });
    }
    
    if (action === 'UNLOCK_USER' && userId) {
      await pool.query('UPDATE users SET is_active = TRUE, locked_until = NULL WHERE id = ?', [userId]);
      await pool.query("UPDATE security_incidents SET status = 'Resolved', mitigation_executed = TRUE, notes = 'Manual Mitigated: account unlocked' WHERE id = ?", [incidentId]);
      
      io.emit('INCIDENT_RESOLVED', { id: incidentId, note: 'User Unlocked Successfully' });
      return res.json({ message: 'User account has been unlocked.' });
    }

    if (action === 'DISMISS') {
      await pool.query("UPDATE security_incidents SET status = 'False Positive' WHERE id = ?", [incidentId]);
      io.emit('INCIDENT_RESOLVED', { id: incidentId, note: 'Incident dismissed as False Positive' });
      return res.json({ message: 'Incident dismissed as False Positive.' });
    }

    if (action === 'REOPEN') {
      await pool.query("UPDATE security_incidents SET status = 'Open' WHERE id = ?", [incidentId]);
      io.emit('INCIDENT_RESOLVED', { id: incidentId, note: 'Incident reopened successfully' });
      return res.json({ message: 'Incident reopened successfully.' });
    }

    res.status(400).json({ message: 'Invalid action payload.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST Threat Simulator API
app.post('/api/simulate/threat', async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  const { threatType } = req.body;
  try {
    if (threatType === 'IMPOSSIBLE_TRAVEL') {
      req.headers['x-simulate-impossible-travel'] = 'true';
      await analyzePrivacyThreats(req, req.user, 'LOGIN_SUCCESS');
      return res.json({ message: 'Impossible travel threat simulated successfully.' });
    }
    res.status(400).json({ message: 'Invalid threat simulation type.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Server Initialization
server.listen(PORT, async () => {
  console.log(`[SERVER] DataLens HR Backend running on port ${PORT}`);
  try {
    await seedMockData();
    console.log('[SERVER] Database health verified, seeds evaluated.');
  } catch (e) {
    console.error('[SERVER] Database is not fully initialized. Run node setup_db.js first.', e.message);
  }
});
