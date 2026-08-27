# DataLens HR - Privacy Monitoring & Incident Response System

DataLens HR is a security-centric Human Resource Information System (HRIS) designed to demonstrate real-time threat detection, role-based access control (RBAC), volumetric scraping prevention, decoy canary monitoring, and automated session mitigation.

---

## Repository Structure

*   `backend/` - Node.js & Express API service (PostgreSQL database integration, threat analysis, WebSocket alerts)
*   `frontend/` - React & Vite SPA client dashboard and employee directories

---

## Getting Started

### Prerequisites

*   **Node.js** (v18 or higher recommended)
*   **PostgreSQL** (v14 or higher)

---

### Step 1: Database Setup

1.  Make sure your local PostgreSQL server is running.
2.  Navigate to the `backend/` folder and create a `.env` file based on `.env.example`:
    ```ini
    PORT=5000
    DB_USER=postgres
    DB_HOST=localhost
    DB_NAME=datalens_hr
    DB_PASSWORD=your_postgres_password
    DB_PORT=5432
    JWT_SECRET=supersecretjwtkey123!@#
    JWT_EXPIRES_IN=24h
    ```
3.  Install dependencies and run the database setup script to create the tables and seed initial mock data:
    ```bash
    cd backend
    npm install
    node setup_db.js
    ```

---

### Step 2: Running the Application Locally

#### Start the Backend Server:
```bash
cd backend
npm run dev
```
The API server will run at [http://localhost:5000](http://localhost:5000).

#### Start the Frontend Client:
```bash
cd ../frontend
npm install
npm run dev
```
The client dashboard will run at [http://localhost:5173](http://localhost:5173).

---

## Seed Credentials (Local Development)

You can log in to the dashboard using these seeded mock user accounts:

*   **System Administrator**: `admin@datalenshr.com` / password: `admin123`
*   **HR Manager**: `manager@datalenshr.com` / password: `admin123`
*   **HR Staff**: `staff@datalenshr.com` / password: `admin123`
*   **Employee**: `employee@datalenshr.com` / password: `admin123`
