// DataLens HR Backend Service - Version 1.0.1
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const pg = require('pg');
const fs = require('fs');
const path = require('path');

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

// Configurable Privacy Rules in-memory cache
let activeRulesCache = {};

async function refreshRulesCache() {
  try {
    const [rows] = await pool.query('SELECT * FROM privacy_rules');
    const newCache = {};
    rows.forEach(rule => {
      newCache[rule.id] = {
        name: rule.name,
        description: rule.description,
        weight: rule.weight,
        is_enabled: rule.is_enabled,
        parameters: typeof rule.parameters === 'object' ? rule.parameters : JSON.parse(rule.parameters || '{}')
      };
    });
    activeRulesCache = newCache;
    console.log('[DB CACHE] Privacy detection rules cache loaded/refreshed.', Object.keys(activeRulesCache).length, 'rules active.');
  } catch (err) {
    console.error('[DB CACHE ERR] Failed to refresh rules cache:', err.message);
  }
}


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
  if (Object.keys(activeRulesCache).length === 0) {
    await refreshRulesCache();
  }

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

  // 1. Rule R-02: Unusual Working Hours
  const r02 = activeRulesCache['R-02'];
  if (r02 && r02.is_enabled) {
    const startHour = r02.parameters.start_hour ?? 23;
    const endHour = r02.parameters.end_hour ?? 5;
    if (currentHour >= startHour || currentHour < endHour) {
      triggeredRules.push({
        id: 'R-02',
        name: r02.name,
        description: `Access requested at ${now.toLocaleTimeString()} outside standard hours (${startHour}:00 - ${endHour}:00)`,
        weight: r02.weight
      });
    }
  }

  // 2. Rule R-04: Salary Probing
  const r04 = activeRulesCache['R-04'];
  if (r04 && r04.is_enabled && actionType === 'UNAUTHORIZED_SALARY_READ') {
    triggeredRules.push({
      id: 'R-04',
      name: r04.name,
      description: `Access restriction violation: Unauthorized read attempt on salary endpoint.`,
      weight: r04.weight
    });
  }

  // 3. Rule R-05: Volumetric Scraping
  const r05 = activeRulesCache['R-05'];
  if (r05 && r05.is_enabled && user && actionType === 'PROFILE_READ') {
    const userId = user.id;
    const limit = r05.parameters.limit ?? 10;
    const windowMs = r05.parameters.window_ms ?? 10000;
    if (!userRequestCounts[userId]) userRequestCounts[userId] = [];

    // Clear expired timestamps
    userRequestCounts[userId] = userRequestCounts[userId].filter(t => now - t < windowMs);
    userRequestCounts[userId].push(now);

    if (userRequestCounts[userId].length > limit) {
      triggeredRules.push({
        id: 'R-05',
        name: r05.name,
        description: `High access rate: accessed ${userRequestCounts[userId].length} records in ${windowMs / 1000}s.`,
        weight: r05.weight
      });
      rawEvidence.volumeDetails = `${userRequestCounts[userId].length} hits/${windowMs / 1000}s`;
    }
  }

  // 4. Rule R-06: Canary honeypot access (Fetching decoy record)
  const r06 = activeRulesCache['R-06'];
  if (r06 && r06.is_enabled && actionType === 'CANARY_ACCESS') {
    triggeredRules.push({
      id: 'R-06',
      name: r06.name,
      description: `Decoy Canary profile accessed (John Doe - Senior Executive VP).`,
      weight: r06.weight
    });
  }

  // 5. Rule R-03: Impossible Travel / Geolocational anomaly
  const r03 = activeRulesCache['R-03'];
  if (r03 && r03.is_enabled && req.headers['x-simulate-impossible-travel'] === 'true') {
    triggeredRules.push({
      id: 'R-03',
      name: r03.name,
      description: `Impossible geolocational speed: Login location switched from Colombo to Tokyo in 5 mins.`,
      weight: r03.weight
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

// 1. Setup Mock User Seeds & Auto-Create Tables
async function seedMockData() {
  try {
    // Automatically read and execute schema.sql to create tables if they don't exist
    const schemaPath = path.join(__dirname, 'schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      await pool.query(schemaSql);
      console.log('[DB] Database schema tables initialized/verified.');
    }

    const [rows] = await pool.query('SELECT COUNT(*) as count FROM users');
    const adminId = '11111111-1111-1111-1111-111111111111';

    if (rows[0].count === 0) {
      console.log('[SEED] Seeding database with mock employees & users...');

      const managerId = '22222222-2222-2222-2222-222222222222';
      const staffId = '33333333-3333-3333-3333-333333333333';
      const employeeUserId = '44444444-4444-4444-4444-444444444444';

      const hashedPw = await bcrypt.hash('admin123', 10);

      // Seed Users
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 1)', [adminId, 'admin@datalenshr.com', hashedPw]);
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 2)', [managerId, 'manager@datalenshr.com', hashedPw]);
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 3)', [staffId, 'staff@datalenshr.com', hashedPw]);
      await pool.query('INSERT INTO users (id, email, password_hash, role_id) VALUES (?, ?, ?, 4)', [employeeUserId, 'employee@datalenshr.com', hashedPw]);

      // Seed Employees
      await pool.query(
        `INSERT INTO employees (id, user_id, first_name, last_name, department, position, salary, email, phone, hire_date, is_canary)
         VALUES 
         ('e1', '${managerId}', 'Emma', 'Davis', 'HR Department', 'HR Director', 185000.00, 'manager@datalenshr.com', '+94 77 123 4567', '2020-01-15', FALSE),
         ('e2', '${staffId}', 'Sarah', 'Miller', 'HR Department', 'HR Assistant', 85000.00, 'staff@datalenshr.com', '+94 77 987 6543', '2023-06-10', FALSE),
         ('e3', '${employeeUserId}', 'David', 'Clark', 'Sales', 'Account Executive', 65000.00, 'employee@datalenshr.com', '+94 71 555 4321', '2021-08-20', FALSE),
         ('e4', NULL, 'Jane', 'Honeypot', 'Executive', 'Senior Executive VP (Honeypot)', 350000.00, 'jane.doe@datalenshr.com', '+94 77 111 2222', '2019-11-01', TRUE),
         ('e5', '${adminId}', 'System', 'Administrator', 'Executive', 'System Administrator', 150000.00, 'admin@datalenshr.com', '+94 77 000 0000', '2018-05-20', FALSE)`
      );

      console.log('[SEED] Seeding completed.');
    } else {
      const [adminEmpCheck] = await pool.query('SELECT * FROM employees WHERE user_id = ?', [adminId]);
      if (adminEmpCheck.length === 0) {
        await pool.query(
          `INSERT INTO employees (id, user_id, first_name, last_name, department, position, salary, email, phone, hire_date, is_canary)
            VALUES ('e5', ?, 'System', 'Administrator', 'Executive', 'System Administrator', 150000.00, 'admin@datalenshr.com', '+94 77 000 0000', '2018-05-20', FALSE)`,
          [adminId]
        );
        console.log('[SEED] Admin employee profile e5 seeded successfully.');
      }
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
    const [existing] = await pool.query('SELECT first_name, last_name, user_id FROM employees WHERE id = ?', [employeeId]);
    if (existing.length === 0) {
      return res.status(404).json({ message: 'Employee not found.' });
    }

    // Explicitly delete any dependent leave requests first to prevent foreign key errors
    await pool.query('DELETE FROM leave_requests WHERE employee_id = ?', [employeeId]);
    await pool.query('DELETE FROM employees WHERE id = ?', [employeeId]);
    await insertAuditLog(req, req.user, 'DELETE_EMPLOYEE', 1);
    res.json({ message: `Employee ${existing[0].first_name} ${existing[0].last_name} removed successfully.` });
  } catch (err) {
    console.error('[DELETE EMP ERR]', err.message);
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

// GET Department Privacy Analytics & Reporting
app.get('/api/analytics/departments', async (req, res) => {
  if (!req.user || (req.user.role !== 'System Administrator' && req.user.role !== 'HR Manager')) {
    return res.status(403).json({ message: 'Access denied: Privileged access required.' });
  }
  try {
    const query = `
      WITH dept_employees AS (
          SELECT department, COUNT(id) as employee_count
          FROM employees
          GROUP BY department
      ),
      dept_incidents AS (
          SELECT e.department, COUNT(si.id) as incident_count, COALESCE(AVG(si.risk_score), 0) as avg_risk_score, COALESCE(MAX(si.risk_score), 0) as max_risk_score
          FROM security_incidents si
          JOIN employees e ON si.user_id = e.user_id
          GROUP BY e.department
      ),
      dept_audits AS (
          SELECT e.department, COUNT(al.id) as total_actions, COALESCE(SUM(al.records_accessed), 0) as total_records_accessed
          FROM audit_logs al
          JOIN employees e ON al.user_id = e.user_id
          GROUP BY e.department
      )
      SELECT 
          de.department,
          de.employee_count,
          COALESCE(di.incident_count, 0) as incident_count,
          COALESCE(di.avg_risk_score, 0) as avg_risk_score,
          COALESCE(di.max_risk_score, 0) as max_risk_score,
          COALESCE(da.total_actions, 0) as total_actions,
          COALESCE(da.total_records_accessed, 0) as total_records_accessed
      FROM dept_employees de
      LEFT JOIN dept_incidents di ON de.department = di.department
      LEFT JOIN dept_audits da ON de.department = da.department
      ORDER BY avg_risk_score DESC;
    `;
    const [analytics] = await pool.query(query);
    res.json(analytics);
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

// 6. Configurable Privacy Rules Endpoints
app.get('/api/rules', async (req, res) => {
  if (!req.user || (req.user.role !== 'System Administrator' && req.user.role !== 'HR Manager')) {
    return res.status(403).json({ message: 'Access denied: Privileged access required.' });
  }
  try {
    const [rules] = await pool.query('SELECT * FROM privacy_rules ORDER BY id ASC');
    res.json(rules);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/rules/:id', async (req, res) => {
  if (!req.user || req.user.role !== 'System Administrator') {
    return res.status(403).json({ message: 'Access denied: Admin control only.' });
  }
  const ruleId = req.params.id;
  const { weight, is_enabled, parameters } = req.body;
  try {
    await pool.query(
      `UPDATE privacy_rules 
       SET weight = ?, is_enabled = ?, parameters = ?, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [weight, is_enabled, JSON.stringify(parameters), ruleId]
    );
    await refreshRulesCache();
    await insertAuditLog(req, req.user, `RULE_UPDATE_${ruleId}`, 1);
    res.json({ message: `Rule ${ruleId} updated successfully.` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// GET Proactive Recommendations Engine
app.get('/api/analytics/recommendations', authenticateToken, async (req, res) => {
  if (!req.user || (req.user.role !== 'System Administrator' && req.user.role !== 'HR Manager')) {
    return res.status(403).json({ message: 'Access denied: Privileged access required.' });
  }

  try {
    const recommendations = [];

    // Query active incidents and logs
    const [incidents] = await pool.query(
      `SELECT si.*, u.email as user_email 
       FROM security_incidents si
       LEFT JOIN users u ON si.user_id = u.id
       WHERE si.status = 'Open'`
    );

    // Track which recommendations have been generated to prevent duplicates
    const generated = new Set();

    for (const inc of incidents) {
      const triggeredRules = Array.isArray(inc.triggered_rules) ? inc.triggered_rules : JSON.parse(inc.triggered_rules || '[]');
      const userEmail = inc.user_email || 'Anonymous';
      const userId = inc.user_id;

      // 1. Impossible Travel -> Enforce MFA
      if (triggeredRules.includes('IMPOSSIBLE_TRAVEL') && userId) {
        const key = `MFA_${userId}`;
        if (!generated.has(key)) {
          // Check if MFA is already enabled for the user
          const [uRows] = await pool.query('SELECT mfa_enabled FROM users WHERE id = ?', [userId]);
          if (uRows.length > 0 && !uRows[0].mfa_enabled) {
            recommendations.push({
              id: `REC-MFA-${userId.substring(0, 8)}`,
              type: 'ENFORCE_MFA',
              title: `Enforce MFA Policy`,
              description: `Multiple geolocational speed anomalies detected for account ${userEmail}. Enforcing Multi-Factor Authentication will block unauthorized sessions.`,
              severity: 'High',
              target_user_id: userId,
              target_email: userEmail,
              incident_id: inc.id
            });
            generated.add(key);
          }
        }
      }

      // 2. Canary Honeypot Access -> Administrative Quarantine
      if (triggeredRules.includes('CANARY_ACCESS') && userId) {
        const key = `QUARANTINE_${userId}`;
        if (!generated.has(key)) {
          const [uRows] = await pool.query('SELECT is_active FROM users WHERE id = ?', [userId]);
          if (uRows.length > 0 && uRows[0].is_active) {
            recommendations.push({
              id: `REC-QUAR-${userId.substring(0, 8)}`,
              type: 'QUARANTINE_USER',
              title: `Administrative Quarantine`,
              description: `Honeypot canary profile ('Jane Doe') accessed by ${userEmail}. Quarantine the user session immediately to prevent data leakage.`,
              severity: 'Critical',
              target_user_id: userId,
              target_email: userEmail,
              incident_id: inc.id
            });
            generated.add(key);
          }
        }
      }

      // 3. Unauthorized Salary Probing -> Mandatory Security Training
      if (triggeredRules.includes('UNAUTHORIZED_SALARY_READ') && userId) {
        const key = `TRAINING_${userId}`;
        if (!generated.has(key)) {
          recommendations.push({
            id: `REC-TRAIN-${userId.substring(0, 8)}`,
            type: 'SCHEDULE_TRAINING',
            title: `Mandatory Security Review`,
            description: `Unauthorized attempts to query restricted annual salary data detected for ${userEmail}. Schedule mandatory privacy training and log warning.`,
            severity: 'Medium',
            target_user_id: userId,
            target_email: userEmail,
            incident_id: inc.id
          });
          generated.add(key);
        }
      }
    }

    const [volIncidents] = await pool.query(
      `SELECT COUNT(*) as count FROM security_incidents 
       WHERE triggered_rules @> '["VOLUMETRIC_SCRAPE"]' AND status = 'Open'`
    );
    if (volIncidents[0].count > 0) {
      // Find R-05 rule to see if it's already tight
      const [r05] = await pool.query("SELECT parameters FROM privacy_rules WHERE id = 'R-05'");
      const params = typeof r05[0].parameters === 'string' ? JSON.parse(r05[0].parameters) : r05[0].parameters;
      const currentLimit = params.limit ?? 10;
      if (currentLimit > 5) {
        recommendations.push({
          id: `REC-THRESH-R05`,
          type: 'TIGHTEN_SCRAPE_LIMIT',
          title: `Tighten Volumetric Limits`,
          description: `Active volumetric scrape events detected in telemetry logs. Tighten profile read limit from ${currentLimit} down to 5 to protect directory details.`,
          severity: 'High',
          target_rule_id: 'R-05',
          target_limit: 5,
          current_limit: currentLimit
        });
      }
    }

    res.json(recommendations);
  } catch (err) {
    console.error('[REC GET ERR]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// Apply Recommendation action dynamically
app.post('/api/recommendations/apply', authenticateToken, async (req, res) => {
  if (!req.user || req.user.role !== 'System Administrator') {
    return res.status(403).json({ message: 'Access denied: Admin control only.' });
  }

  const { type, target_user_id, target_email, target_rule_id, target_limit, incident_id } = req.body;

  try {
    if (type === 'ENFORCE_MFA' && target_user_id) {
      // Update user to enable MFA
      await pool.query('UPDATE users SET mfa_enabled = TRUE WHERE id = ?', [target_user_id]);
      if (incident_id) {
        await pool.query("UPDATE security_incidents SET status = 'Resolved', mitigation_executed = TRUE, notes = 'Mitigated: MFA Enforced' WHERE id = ?", [incident_id]);
      }
      await insertAuditLog(req, req.user, `MFA_ENFORCED_USER_${target_user_id}`, 1);
      io.emit('INCIDENT_RESOLVED', { id: incident_id, note: `MFA Enforced for ${target_email}` });
      return res.json({ message: `MFA has been successfully enforced for ${target_email}.` });
    }

    if (type === 'QUARANTINE_USER' && target_user_id) {
      // Lock user account
      const lockDurationMinutes = 60;
      const lockedUntil = new Date(Date.now() + lockDurationMinutes * 60000);
      await pool.query('UPDATE users SET is_active = FALSE, locked_until = ? WHERE id = ?', [lockedUntil, target_user_id]);
      if (incident_id) {
        await pool.query("UPDATE security_incidents SET status = 'Resolved', mitigation_executed = TRUE, notes = 'Quarantined user account for 60m' WHERE id = ?", [incident_id]);
      }
      await insertAuditLog(req, req.user, `QUARANTINE_USER_${target_user_id}`, 1);
      io.emit('INCIDENT_RESOLVED', { id: incident_id, note: `User ${target_email} quarantined` });
      return res.json({ message: `User ${target_email} has been quarantined for 60 minutes.` });
    }

    if (type === 'SCHEDULE_TRAINING' && target_user_id) {
      // Resolve/Mitigate incident by scheduling security training
      if (incident_id) {
        await pool.query("UPDATE security_incidents SET status = 'Resolved', mitigation_executed = TRUE, notes = 'Scheduled Privacy Review Session' WHERE id = ?", [incident_id]);
      }
      await insertAuditLog(req, req.user, `SCHEDULED_TRAINING_USER_${target_user_id}`, 1);
      io.emit('INCIDENT_RESOLVED', { id: incident_id, note: `Scheduled security training for ${target_email}` });
      return res.json({ message: `Scheduled mandatory security training for ${target_email}. Log entry updated.` });
    }

    if (type === 'TIGHTEN_SCRAPE_LIMIT' && target_rule_id) {
      // Update rule configuration parameters
      const [rRows] = await pool.query('SELECT parameters FROM privacy_rules WHERE id = ?', [target_rule_id]);
      if (rRows.length > 0) {
        const params = typeof rRows[0].parameters === 'string' ? JSON.parse(rRows[0].parameters) : rRows[0].parameters;
        params.limit = target_limit;
        await pool.query('UPDATE privacy_rules SET parameters = ? WHERE id = ?', [JSON.stringify(params), target_rule_id]);
        await refreshRulesCache();
        await insertAuditLog(req, req.user, `RULE_UPDATE_${target_rule_id}_LIMIT_${target_limit}`, 1);

        // Resolve all open volumetric scrape incidents
        await pool.query("UPDATE security_incidents SET status = 'Resolved', mitigation_executed = TRUE, notes = 'Limit tightened to 5' WHERE triggered_rules @> '[\"VOLUMETRIC_SCRAPE\"]' AND status = 'Open'");
        io.emit('INCIDENT_RESOLVED', { note: `Scraping limit tightened to ${target_limit}` });

        return res.json({ message: `Scraping limit for rule ${target_rule_id} has been tightened to ${target_limit}.` });
      }
    }

    res.status(400).json({ message: 'Invalid recommendation action type.' });
  } catch (err) {
    console.error('[REC APPLY ERR]', err.message);
    res.status(500).json({ message: err.message });
  }
});


// Server Initialization
server.listen(PORT, async () => {
  console.log(`[SERVER] DataLens HR Backend running on port ${PORT}`);
  try {
    await seedMockData();
    await refreshRulesCache();
    console.log('[SERVER] Database health verified, seeds evaluated.');
  } catch (e) {
    console.error('[SERVER] Database is not fully initialized. Run node setup_db.js first.', e.message);
  }
});