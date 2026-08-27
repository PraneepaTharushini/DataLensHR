require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function runSetup() {
  console.log('[DB SETUP] Starting PostgreSQL initialization...');

  const dbName = process.env.DB_NAME || 'datalens_hr';
  const connectionString = process.env.DATABASE_URL;

  if (connectionString) {
    console.log('[DB SETUP] DATABASE_URL detected. Connecting directly to cloud database...');
    // Connect directly via connection string
    const client = new Client({
      connectionString: connectionString,
      ssl: { rejectUnauthorized: false }
    });

    try {
      await client.connect();
      console.log('[DB SETUP] Connected. Running schema.sql...');
      const schemaPath = path.join(__dirname, 'schema.sql');
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      
      await client.query(schemaSql);
      console.log('[DB SETUP] Database schema and initial seeds applied successfully!');
      await client.end();
      return;
    } catch (err) {
      console.error('[DB SETUP] Error setting up database via DATABASE_URL:', err.message);
      process.exit(1);
    }
  }

  // Local PostgreSQL Configuration
  const config = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    port: parseInt(process.env.DB_PORT || '5432'),
  };

  // 1. Connect to standard 'postgres' database to verify/create target database
  const clientMain = new Client({
    ...config,
    database: 'postgres'
  });

  try {
    await clientMain.connect();
    console.log('[DB SETUP] Connected to local PostgreSQL server (default postgres DB).');

    // Check if database exists
    const checkDbResult = await clientMain.query(
      'SELECT 1 FROM pg_database WHERE datname = $1',
      [dbName]
    );

    if (checkDbResult.rows.length === 0) {
      console.log(`[DB SETUP] Database "${dbName}" not found. Creating it...`);
      // CREATE DATABASE cannot be executed inside a transaction or via parameterized statement
      // Standard identifier validation is not needed here as it comes from our controlled environment configuration
      await clientMain.query(`CREATE DATABASE ${dbName}`);
      console.log(`[DB SETUP] Database "${dbName}" created successfully.`);
    } else {
      console.log(`[DB SETUP] Database "${dbName}" already exists.`);
    }
    await clientMain.end();

    // 2. Connect directly to target database to run schema.sql
    const clientTarget = new Client({
      ...config,
      database: dbName
    });

    await clientTarget.connect();
    console.log(`[DB SETUP] Connected to target database "${dbName}".`);
    console.log(`[DB SETUP] Applying schemas on database "${dbName}"...`);
    
    const schemaPath = path.join(__dirname, 'schema.sql');
    if (!fs.existsSync(schemaPath)) {
      throw new Error(`schema.sql not found at: ${schemaPath}`);
    }

    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    
    // Execute all statements
    await clientTarget.query(schemaSql);
    console.log('[DB SETUP] Database schema and initial seeds applied successfully!');
    await clientTarget.end();
  } catch (err) {
    console.error('[DB SETUP] Error during PostgreSQL setup:', err.message);
    console.error('[DB SETUP] Make sure PostgreSQL is running on port 5432 and username/password are correct.');
    process.exit(1);
  }
}

runSetup();
