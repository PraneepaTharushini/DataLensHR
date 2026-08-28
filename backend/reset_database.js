require('dotenv').config();
const { Client } = require('pg');

async function reset() {
  const config = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    port: parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME || 'datalens_hr'
  };

  const client = new Client(config);
  try {
    await client.connect();
    console.log('[RESET] Connected to datalens_hr database.');

    console.log('[RESET] Truncating all data tables...');
    await client.query('TRUNCATE TABLE security_incidents, audit_logs, leave_requests, employees, users CASCADE;');
    console.log('[RESET] Tables truncated successfully.');

    await client.end();
    console.log('[RESET] Complete.');
  } catch (err) {
    console.error('[RESET ERR]', err.message);
    process.exit(1);
  }
}

reset();
