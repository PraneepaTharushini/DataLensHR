# DataLens HR – System Architecture & Engineering Guide

This guide explains the inner workings, database design, real-time detection logic, and automatic mitigation architecture of the **DataLens HR Privacy Analytics Suite**.

---

## 🏗️ 1. High-Level Architecture

DataLens HR is designed as a secure, audited middleware sitting on top of a standard Human Resource Information System (HRIS).

```text
       [ React.js Frontend UI ]
                   │
         HTTP REST / WebSockets
                   │
                   ▼
       [ Express REST API Gateway ] ◄──► [ Memory Caching (activeRulesCache) ]
                   │
      ┌────────────┴────────────┐
      ▼                         ▼
 [ Audit Logging Engine ]   [ Threat Detection Engine ]
      │                         │
      └────────────┬────────────┘
                   ▼
     [ PostgreSQL Database Layer ]
```

1.  **Frontend (React.js)**: Displays directories, leaf controls, and the specialized SecOps dashboard. Communicates with backend REST APIs and listens to real-time incident broadcasts using **WebSockets (Socket.io)**.
2.  **API Gateway (Express.js)**: Integrates session authorization (`authenticateToken` JWT middleware) and routes requests.
3.  **Threat & Auditing Engines**: Scrapes parameters from an in-memory cache, checks client metadata, registers logs, and flags security incidents.
4.  **Database (PostgreSQL)**: Serves as the immutable storage layer for telemetry, user data, and rule parameters.

---

## 🗄️ 2. Database Models & Schema

The database consists of 6 primary tables in [schema.sql](file:///e:/IEEE%20YP%202026/DataLens%20HR/backend/schema.sql):

1.  **`roles`**: Contains security clearance level classifications (SysAdmin, HR Manager, HR Staff, Employee).
2.  **`users`**: Stores logins, password hashes, dynamic activity locks (`is_active`, `locked_until`), and MFA enforcement flags (`mfa_enabled`).
3.  **`employees`**: Stores personal profiles and links to `users.id` to establish owner bounds.
4.  **`audit_logs`**: An **immutable ledger** (enforced by a PostgreSQL update/delete trigger) logging IP, browser user agent, country, city, URL path, and method for every request.
5.  **`security_incidents`**: Logs active alert incidents containing threat lists, raw geolocational evidence, and dynamic mitigation details.
6.  **`privacy_rules`**: Stores parameters (JSONB) and detection weights for the rules engine.

---

## 🛡️ 3. Real-Time Detection & Risk Scoring

Threat detection is managed in [server.js](file:///e:/IEEE%20YP%202026/DataLens%20HR/backend/server.js) inside the core function `analyzePrivacyThreats`:

### The 5 Active Security Rules:
*   **R-02 (Unusual Working Hours)**: If a user attempts to read sensitive directories or fields outside the configured hours (default: 11 PM to 5 AM), the rule triggers.
*   **R-03 (Impossible Travel)**: Compares consecutive logins. If the geographic speed indicates impossible physical travel (Colombo to Tokyo in 5 minutes), it flags a geolocational anomaly.
*   **R-04 (Salary Probing)**: If a non-privileged user (like HR Staff) attempts to fetch salary data, this immediately flags an access violation.
*   **R-05 (Volumetric Scraping)**: Uses a rolling list of timestamps (`userRequestCounts`). If a user fetches more profiles than the configured limit inside the window (e.g. >10 profile reads/10s), it flags a harvesting threat.
*   **R-06 (Canary Trap / Honeypot)**: Accesses fake employee profile (`Jane Honeypot`) designed specifically to trap hackers.

### Composite Risk Scoring Formula:
When rules trigger, the system sums their configuration weights and applies a role-based clearance multiplier:
$$\text{Composite Score} = \text{Min}\left(100, \sum(\text{Rule Weights}) \times \text{Role Multiplier}\right)$$
*   **System Admin Multiplier**: $1.4\times$ (High impact).
*   **HR Manager Multiplier**: $1.25\times$.
*   **Incident Classification**:
    *   $\text{Score} \ge 70$: **High Risk** (triggers automatic user account lockouts).
    *   $40 \le \text{Score} < 70$: **Medium Risk**.
    *   $\text{Score} < 40$: **Low Risk**.

---

## 💡 4. Proactive Recommendation Engine

The recommendation engine evaluates active open incidents to generate policy modifications:
1.  **MFA Enforce**: Recommends multi-factor authentication for users flagged with locational travel anomalies.
2.  **Quarantine**: Recommends administrative locking for honeypot canary breaches.
3.  **Scrape Tightening**: Proposes reducing the `R-05` scrape limit from 10 to 5 if harvesting alerts occur.
4.  **Training**: Recommends mandatory privacy review for minor salary probes.

Clicking **Apply Policy Recommendation** in the UI makes a POST request to `/api/recommendations/apply` which automatically enforces the mitigation database-wide (e.g. locks user, activates MFA, or modifies rules parameters).
