# DataLens HR – Privacy Analytics and Decision Support System for HRIS

## 📌 Overview

**DataLens HR** is an intelligent **Privacy Analytics and Incident Response System** built on top of a basic Human Resource Information System (HRIS).

The HRIS provides a simple environment where users can perform common HR activities. DataLens HR continuously monitors these activities, analyzes user behaviour, detects unusual or suspicious activities, assigns risk levels, and alerts authorized personnel when potential privacy or security incidents occur.

The main focus of the project is **privacy monitoring, suspicious behaviour detection, risk assessment, and incident response**, rather than developing a complete enterprise-level HRIS.

---

## 🎯 Objectives

* Provide a basic HRIS environment for managing employee-related activities.
* Implement secure user authentication and role-based access control.
* Monitor user activities through audit logs.
* Detect unusual and suspicious user behaviour.
* Calculate a privacy/security risk score for detected activities.
* Classify incidents as **Low, Medium, or High** risk.
* Notify HR Managers or System Administrators about serious incidents.
* Recommend appropriate actions based on incident severity.
* Provide a privacy analytics dashboard for monitoring security trends.
* Support investigation through detailed incident and audit records.

---

## 🏢 Basic HRIS Modules

The project includes a limited HRIS module that acts as the environment for demonstrating privacy monitoring.

### 1. User Login
* User authentication & secure password storage
* Failed login tracking and lockout thresholds
* Session management with JWT-based authentication

### 2. Employee Management
* Add, view, update, and remove employee records
* Search and filter directories
* Control access and data masking for sensitive fields (e.g., salary)

### 3. Leave Management
* Submit, view, and approve/reject leave requests
* Track leave history

### 4. User Roles (RBAC)
* **System Administrator**
* **HR Manager**
* **HR Staff**
* **Employee**

---

## 🔐 Privacy Monitoring System

DataLens HR continuously tracks events and uses a composite risk scoring system to detect suspicious behavior, assigning one of three risk levels:
```text
0 – 29     → LOW
30 – 59    → MEDIUM
60+        → HIGH
```

### Suspicious Behaviour Detection Rules:
*   **Unfamiliar Device**: Logs in using a device hash not previously seen.
*   **Unusual Location**: Geolocation switches dynamically to simulate impossible travel.
*   **Failed Logins**: Repeated authentication failures lock the user temporarily.
*   **Unusual Working Hours**: Accesses sensitive metrics between 11 PM and 5 AM.
*   **Volumetric Scraping**: Accesses excessive employee directories within short windows.
*   **Canary Trap / Honeypot Profile**: Accesses fake employee profile (`Jane Doe - Senior Executive VP`) designed to trigger immediate alerts.
*   **Unauthorized Salary Probing**: Attempts to query restricted data without privileges.

---

## 🛠️ Getting Started & Installation

### Prerequisites

*   **Node.js** (v18 or higher)
*   **PostgreSQL** (v14 or higher)

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
3.  Install dependencies and run the database setup script to initialize PostgreSQL and seed initial mock tables:
    ```bash
    cd backend
    npm install
    node setup_db.js
    ```

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

## 👥 Seed Credentials (Local Development)

You can log in to the dashboard using these seeded mock user accounts:

*   **System Administrator**: `admin@datalenshr.com` / password: `admin123`
*   **HR Manager**: `manager@datalenshr.com` / password: `admin123`
*   **HR Staff**: `staff@datalenshr.com` / password: `admin123`
*   **Employee**: `employee@datalenshr.com` / password: `admin123`

---

## 🧰 Technology Stack

*   **Frontend**: React.js, TailwindCSS (for responsive UI elements), Socket.io Client
*   **Backend**: Node.js, Express, Socket.io (for real-time dashboard threat alerts)
*   **Database**: PostgreSQL (pooling handled with the `pg` client driver)
