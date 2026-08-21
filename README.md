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

* User authentication
* Secure password storage
* Login/logout
* Failed login tracking
* Session management
* JWT-based authentication

### 2. Employee Management

* Add employees
* View employee profiles
* Update employee information
* Delete/deactivate employee records
* Search and filter employees
* Control access to sensitive employee information

### 3. Leave Management

* Submit leave requests
* View leave requests
* Approve/reject leave requests
* Track leave history
* Monitor user activity related to leave management

### 4. User Roles

Role-Based Access Control (RBAC) is used to control access to system functionality.

Example roles:

* **System Administrator**
* **HR Manager**
* **Employee**

Different roles have different permissions for accessing employee information and HR functions.

---

# 🔐 Privacy Monitoring System

The core component of DataLens HR is the **Privacy Monitoring and Incident Response Module**.

The system monitors user activities and identifies behaviour that may indicate unauthorized access, compromised accounts, insider threats, or potential data exposure.

---

## 🚨 Suspicious Behaviour Detection

The system can detect activities such as:

### Unfamiliar Device

A user logs in using a device that has not previously been associated with their account.

### Unusual Location

A login occurs from a location that is significantly different from the user's normal login locations.

### Multiple Failed Login Attempts

Repeated failed login attempts may indicate a brute-force attack or compromised credentials.

### Unusual Working Hours

A user accesses the system outside their normal working hours.

### Excessive Employee Record Access

A user views an unusually large number of employee records within a short period.

### Unauthorized Salary Access

A user attempts to access salary or other sensitive employee information without the required permission.

### Large Data Export

A user exports an unusually large amount of employee information.

### Other Suspicious Behaviour

The system can be extended with additional behavioural rules as required.

---

# 📊 Risk Scoring

Each suspicious activity is assigned a risk score.

Example:

| Activity                           | Example Score |
| ---------------------------------- | ------------: |
| Unfamiliar device                  |            20 |
| Login outside working hours        |            15 |
| Unusual location                   |            40 |
| Multiple failed logins             |            35 |
| Unauthorized sensitive-data access |            50 |
| Large data export                  |            50 |
| Excessive employee record access   |            40 |

The system combines relevant risk factors to determine the overall risk level.

### Risk Levels

```text
0 – 29     → LOW
30 – 59    → MEDIUM
60+        → HIGH
```

The scoring thresholds can be adjusted during implementation and testing.

---

# ⚠️ Incident Management

When suspicious behaviour is detected, DataLens HR creates a security/privacy incident.

Each incident stores information such as:

* Incident ID
* Date and time
* User account
* User role
* IP address
* Device information
* Location
* Activity performed
* Incident type
* Risk score
* Risk level
* Incident status
* Recommended action
* Resolution information

Example:

```text
Incident ID: INC00125
User: EMP204
Activity: Large employee-data export
Risk Score: 85
Risk Level: HIGH
IP Address: 192.168.10.15
Device: Windows 11 / Chrome
Status: Open
Recommended Action: Terminate active session and review audit logs
```

---

# 🔔 Notifications

When a suspicious activity reaches a defined risk level, the system notifies authorized administrators.

Example:

```text
⚠ HIGH RISK INCIDENT

User: EMP204

Activity:
Large employee data export

Risk Score:
85

Time:
10:45 AM

Recommended Action:
Terminate active session and investigate audit logs.
```

Notifications can be displayed through the system dashboard and can later be extended to email or other notification channels.

---

# 🛡️ Recommended Security Actions

Depending on the detected behaviour and risk level, the system can recommend actions such as:

* Temporarily lock the user account
* Force a password reset
* Enable Multi-Factor Authentication (MFA)
* Terminate active sessions
* Review audit logs
* Investigate the incident
* Restrict access to sensitive information
* Notify affected employees if personal information may have been exposed

The system can provide recommendations to administrators rather than automatically executing every action.

---

# 📈 Privacy Analytics Dashboard

The dashboard provides an overview of privacy and security activities.

Possible analytics include:

* Total login attempts
* Successful vs failed logins
* Suspicious activities
* High-risk incidents
* Medium-risk incidents
* Low-risk incidents
* Most common incident types
* Users with unusual behaviour
* Sensitive-data access attempts
* Data export activities
* Incident trends over time
* Department/user-level risk trends

---

# 📝 Audit Logging

Important user activities are recorded in an audit log.

Example activities:

```text
LOGIN
LOGOUT
FAILED_LOGIN
VIEW_EMPLOYEE
UPDATE_EMPLOYEE
VIEW_SALARY
SUBMIT_LEAVE
APPROVE_LEAVE
EXPORT_DATA
UNAUTHORIZED_ACCESS
```

Audit logs support:

* Security monitoring
* Incident investigation
* User activity tracking
* Privacy analysis
* Incident response

---

# 🏗️ System Architecture

The proposed architecture follows a layered web application structure.

```text
                    ┌──────────────────────┐
                    │      React.js        │
                    │     Frontend UI      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    REST API Layer    │
                    │   Node.js + Express  │
                    └──────────┬───────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
        ┌────────────┐ ┌──────────────┐ ┌─────────────┐
        │    HRIS    │ │   Privacy    │ │    Auth &   │
        │   Module   │ │  Monitoring  │ │    RBAC     │
        └────────────┘ └──────┬───────┘ └─────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Risk Scoring    │
                     │ & Detection     │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │    Incident     │
                     │    Management   │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │   PostgreSQL    │
                     │    Database     │
                     └─────────────────┘
```

---

# 🗄️ Main Database Components

The database can contain tables such as:

```text
users
employees
roles
permissions
leave_requests
audit_logs
login_attempts
user_devices
user_locations
security_incidents
risk_events
notifications
sessions
```

The exact database structure can be adjusted during system design and implementation.

---

# 🧰 Technology Stack

### Frontend

* React.js
* HTML5
* CSS3
* JavaScript
* Chart/analytics library

### Backend

* Node.js
* Express.js
* REST APIs
* JWT Authentication

### Database

* PostgreSQL

### Security

* JWT
* Password hashing
* Role-Based Access Control
* Audit logging
* Session management

### Analytics

* Rule-based behavioural detection
* Risk scoring
* Privacy analytics
* Optional lightweight machine-learning enhancement

---

# 🤖 Intelligent Component

The first implementation can use a **rule-based detection engine** because it is practical and explainable for a final-year project.

For example:

```text
IF failed_login_attempts > 5
THEN create HIGH risk incident

IF employee_records_viewed > 200
WITHIN 5 minutes
THEN create HIGH risk incident

IF login_location IS unusual
THEN create MEDIUM/HIGH risk incident

IF user_role does not have salary permission
AND salary_data is accessed
THEN create HIGH risk incident
```

A lightweight machine-learning component can optionally be introduced later to identify behavioural patterns that are difficult to detect using predefined rules.

---

# 🔄 Example System Flow

```text
User Login
     ↓
Authentication
     ↓
User Performs HR Activity
     ↓
Activity Recorded in Audit Log
     ↓
Privacy Monitoring Engine
     ↓
Analyse Behaviour
     ↓
Suspicious?
   /     \
 No       Yes
 |         |
Continue   Risk Calculation
             ↓
       Risk Classification
             ↓
      Create Incident
             ↓
       Notify Admin
             ↓
      Recommend Action
             ↓
       Investigation
```

---

# 👥 Target Users

### System Administrator

* Manage users and roles
* Monitor system security
* Review incidents
* Investigate suspicious activities
* Take recommended security actions

### HR Manager

* Manage employees
* Manage leave requests
* View privacy analytics
* Review security incidents
* Investigate employee-data access

### Employee

* View own profile
* Submit leave requests
* View leave status
* Perform permitted HR activities

---

# 🎯 Project Scope

## Included

* User authentication
* Employee management
* Leave management
* Role-based access control
* Audit logging
* Privacy monitoring
* Suspicious behaviour detection
* Risk scoring
* Incident management
* Notifications
* Privacy analytics dashboard
* Recommended security actions

## Not Included

To keep the project achievable within the project timeline, the system does not aim to implement a complete enterprise HRIS.

The following are outside the core scope:

* Payroll processing
* Recruitment management
* Performance management
* Full attendance management
* Benefits management
* Complete employee self-service suite

---

# 🌟 Key Value of DataLens HR

Unlike a traditional HRIS that mainly records user activities, **DataLens HR actively analyzes those activities**.

```text
Traditional HRIS

User → Activity → Database


DataLens HR

User
  ↓
Activity
  ↓
Audit Log
  ↓
Behaviour Analysis
  ↓
Risk Detection
  ↓
Risk Score
  ↓
Incident
  ↓
Notification
  ↓
Recommended Response
```

This allows the system to identify potentially dangerous behaviour and support administrators in responding to privacy and security incidents.

---

# 🚀 Future Enhancements

Potential future improvements include:

* Machine-learning-based anomaly detection
* Adaptive user behaviour profiles
* Multi-Factor Authentication
* Email/SMS security alerts
* Advanced geographical anomaly detection
* Automated session termination
* Automated account locking
* Privacy policy simulation
* Advanced threat intelligence integration
* Real-time security monitoring
* Predictive privacy risk analytics

---

# 📌 Project Summary

**DataLens HR** combines a lightweight HRIS with an intelligent privacy monitoring layer.

The basic HRIS provides:

> **Login + Employee Management + Leave Management + User Roles**

The main innovation is:

> **Behaviour Monitoring + Suspicious Activity Detection + Risk Scoring + Incident Management + Privacy Analytics**

The goal is to help organizations identify unusual access behaviour, detect potential privacy incidents, notify responsible personnel, and support appropriate security responses.
