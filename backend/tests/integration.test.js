const request = require('supertest');

const BASE_URL = 'http://localhost:5000';

describe('DataLens HR Integration Test Suite', () => {
  let adminToken = '';
  let managerToken = '';
  let employeeToken = '';
  let staffToken = '';

  beforeAll(async () => {
    // 1. Log in as System Administrator
    const adminRes = await request(BASE_URL)
      .post('/api/auth/login')
      .send({ email: 'admin@datalenshr.com', password: 'admin123' });
    if (adminRes.status === 200) {
      adminToken = adminRes.body.token;
    }

    // 2. Log in as HR Manager
    const managerRes = await request(BASE_URL)
      .post('/api/auth/login')
      .send({ email: 'manager@datalenshr.com', password: 'admin123' });
    if (managerRes.status === 200) {
      managerToken = managerRes.body.token;
    }

    // 3. Log in as HR Staff
    const staffRes = await request(BASE_URL)
      .post('/api/auth/login')
      .send({ email: 'staff@datalenshr.com', password: 'admin123' });
    if (staffRes.status === 200) {
      staffToken = staffRes.body.token;
    }

    // 4. Log in as Employee
    const employeeRes = await request(BASE_URL)
      .post('/api/auth/login')
      .send({ email: 'employee@datalenshr.com', password: 'admin123' });
    if (employeeRes.status === 200) {
      employeeToken = employeeRes.body.token;
    }
  });

  // ================= 1. AUTHENTICATION MODULE TESTS =================
  describe('Authentication API', () => {
    it('should login admin user successfully', () => {
      expect(adminToken).not.toBe('');
    });

    it('should reject invalid password login attempts', async () => {
      const res = await request(BASE_URL)
        .post('/api/auth/login')
        .send({ email: 'admin@datalenshr.com', password: 'wrongpassword' });
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('Invalid credentials');
    });

    it('should reject invalid email login attempts', async () => {
      const res = await request(BASE_URL)
        .post('/api/auth/login')
        .send({ email: 'fakeuser@datalenshr.com', password: 'admin123' });
      expect(res.status).toBe(401);
    });
  });

  // ================= 2. EMPLOYEE DIRECTORY & RBAC TESTS =================
  describe('Employee Directory API & RBAC Boundary Enforcements', () => {
    it('should block unauthorized employee reads without JWT token', async () => {
      const res = await request(BASE_URL).get('/api/employees');
      expect(res.status).toBe(401);
    });

    it('should allow employee list query for authorized users', async () => {
      const res = await request(BASE_URL)
        .get('/api/employees')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });

    it('should allow HR Managers to read sensitive salary details of employees', async () => {
      // HR Manager Emma Watson (e1) tries to fetch Sarah Connor's salary (e2)
      const res = await request(BASE_URL)
        .get('/api/employees/e2/salary')
        .set('Authorization', `Bearer ${managerToken}`);
      expect(res.status).toBe(200);
      expect(res.body.salary).toBeDefined();
    });

    it('should block HR Staff role from reading other employees salary details', async () => {
      // HR Staff Sarah Connor (e2) tries to fetch Emma Watson's salary (e1)
      const res = await request(BASE_URL)
        .get('/api/employees/e1/salary')
        .set('Authorization', `Bearer ${staffToken}`);
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('Access denied');
    });
  });

  // ================= 3. PRIVACY DETECTION CONFIGURABLE RULES TESTS =================
  describe('Configurable Privacy Rules API', () => {
    it('should allow Admin to fetch configuration rules list', async () => {
      const res = await request(BASE_URL)
        .get('/api/rules')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.length).toBeGreaterThan(0);
    });

    it('should deny Employee role from fetching privacy rules', async () => {
      const res = await request(BASE_URL)
        .get('/api/rules')
        .set('Authorization', `Bearer ${employeeToken}`);
      expect(res.status).toBe(403);
    });

    it('should allow Admin to update rule weights and toggles', async () => {
      // Update Rule R-02 Unusual Hour Weight
      const res = await request(BASE_URL)
        .put('/api/rules/R-02')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          weight: 45,
          is_enabled: true,
          parameters: { start_hour: 23, end_hour: 5 }
        });
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('updated successfully');
    });
  });

  // ================= 4. RECOMMENDATIONS ENGINE TESTS =================
  describe('Proactive Recommendations Engine API', () => {
    it('should deny Employee role from reading security recommendations', async () => {
      const res = await request(BASE_URL)
        .get('/api/analytics/recommendations')
        .set('Authorization', `Bearer ${employeeToken}`);
      expect(res.status).toBe(403);
    });

    it('should allow Admin to fetch policy recommendations', async () => {
      const res = await request(BASE_URL)
        .get('/api/analytics/recommendations')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });
});
