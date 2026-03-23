---
name: security-ops
description: Cybersecurity expert skill for threat detection, incident response, vulnerability management, and security operations. Integrates with Snowflake for log analysis and leverages OWASP, MITRE ATT&CK, and NIST CSF frameworks.
allowed-tools: "*"
---

# Security Operations Expert Skill

Transform Cortex Code into a cybersecurity expert capable of threat detection, incident investigation, vulnerability management, and security operations. This skill provides deep knowledge of security frameworks (OWASP, MITRE ATT&CK, NIST CSF) and specialized expertise in analyzing security logs stored in Snowflake.

**When to invoke:** Use for any cybersecurity task including threat hunting, incident response, vulnerability analysis, security log analysis, compliance assessment, or security architecture review.

---

## Core Capabilities

1. **Threat Detection & Hunting** — Identify attacks, anomalies, and indicators of compromise
2. **Incident Response** — Investigate, contain, and remediate security incidents
3. **Vulnerability Management** — Assess, prioritize, and track vulnerability remediation
4. **Log Analysis** — Query and analyze security logs (especially in Snowflake)
5. **Compliance & Frameworks** — Apply OWASP, MITRE ATT&CK, NIST CSF guidance
6. **Security Architecture** — Review and recommend security controls

---

## Security Frameworks Reference

### OWASP Top 10:2025

The OWASP Top 10 represents the most critical web application security risks:

| Rank | Risk | Description |
|------|------|-------------|
| A01 | **Broken Access Control** | Users acting outside intended permissions; IDOR, privilege escalation |
| A02 | **Security Misconfiguration** | Missing hardening, default credentials, verbose errors, unnecessary features |
| A03 | **Software Supply Chain Failures** | Vulnerable dependencies, compromised packages, CI/CD attacks |
| A04 | **Cryptographic Failures** | Weak encryption, improper key management, cleartext transmission |
| A05 | **Injection** | SQL, NoSQL, OS, LDAP injection; XSS now included here |
| A06 | **Insecure Design** | Missing security controls, threat modeling gaps, insecure patterns |
| A07 | **Authentication Failures** | Credential stuffing, weak passwords, session fixation, MFA bypass |
| A08 | **Software/Data Integrity Failures** | Insecure deserialization, unsigned updates, CI/CD compromise |
| A09 | **Security Logging & Alerting Failures** | Missing audit logs, no alerting, insufficient monitoring |
| A10 | **Mishandling of Exceptional Conditions** | Unhandled errors revealing info, DoS via error conditions |

### MITRE ATT&CK Enterprise Tactics

The ATT&CK framework describes adversary behavior across the attack lifecycle:

| ID | Tactic | Description | Key Techniques |
|----|--------|-------------|----------------|
| TA0043 | **Reconnaissance** | Gathering information | Active scanning, phishing for info |
| TA0042 | **Resource Development** | Establishing infrastructure | Acquire access, compromise infrastructure |
| TA0001 | **Initial Access** | Getting into the network | Phishing, exploit public apps, valid accounts |
| TA0002 | **Execution** | Running malicious code | Command interpreter, scripting, native API |
| TA0003 | **Persistence** | Maintaining access | Account manipulation, scheduled tasks, implants |
| TA0004 | **Privilege Escalation** | Getting higher permissions | Exploitation, valid accounts, access token manipulation |
| TA0005 | **Defense Evasion** | Avoiding detection | Obfuscation, indicator removal, masquerading |
| TA0006 | **Credential Access** | Stealing credentials | Brute force, credential dumping, keylogging |
| TA0007 | **Discovery** | Learning the environment | Account discovery, network scanning, file enumeration |
| TA0008 | **Lateral Movement** | Moving through network | Remote services, pass-the-hash, RDP |
| TA0009 | **Collection** | Gathering target data | Data from repositories, email collection, screen capture |
| TA0011 | **Command & Control** | Communicating with implants | Encrypted channels, web protocols, DNS tunneling |
| TA0010 | **Exfiltration** | Stealing data | Exfil over C2, web service, physical medium |
| TA0040 | **Impact** | Disruption and destruction | Data destruction, ransomware, defacement |

### NIST Cybersecurity Framework 2.0

The CSF organizes security activities into six core functions:

| Function | Purpose | Key Categories |
|----------|---------|----------------|
| **GOVERN (GV)** | Risk management strategy & oversight | Context, strategy, roles, policy, oversight, supply chain |
| **IDENTIFY (ID)** | Understand assets and risks | Asset management, risk assessment, improvement |
| **PROTECT (PR)** | Safeguards to manage risk | Identity/access, awareness, data security, platform security |
| **DETECT (DE)** | Find attacks and compromises | Continuous monitoring, adverse event analysis |
| **RESPOND (RS)** | Take action on incidents | Incident management, analysis, mitigation, reporting |
| **RECOVER (RC)** | Restore operations | Recovery planning, communication |

---

## Snowflake Security Log Analysis

Snowflake provides extensive security logging through the `SNOWFLAKE.ACCOUNT_USAGE` schema. These views are essential for security monitoring.

### Key Snowflake Security Views

| View | Purpose | Key Columns | MITRE Mapping |
|------|---------|-------------|---------------|
| `LOGIN_HISTORY` | Authentication events | EVENT_TIMESTAMP, USER_NAME, CLIENT_IP, IS_SUCCESS, FIRST_AUTHENTICATION_FACTOR | T1078 Valid Accounts |
| `QUERY_HISTORY` | All SQL queries executed | QUERY_TEXT, USER_NAME, ROLE_NAME, EXECUTION_STATUS, ROWS_PRODUCED | TA0003 Persistence |
| `ACCESS_HISTORY` | Data access tracking | USER_NAME, DIRECT_OBJECTS_ACCESSED, BASE_OBJECTS_ACCESSED | T1078 Valid Accounts |
| `SESSIONS` | Active sessions | USER_NAME, CLIENT_IP, AUTHENTICATION_METHOD | T1550 Alternate Auth |
| `GRANTS_TO_ROLES` | Role privilege grants | PRIVILEGE, GRANTED_ON, GRANTEE_NAME, GRANTED_BY | T1078 Privilege Escalation |
| `GRANTS_TO_USERS` | User role grants | ROLE, GRANTEE_NAME, GRANTED_BY | T1078 Privilege Escalation |
| `USERS` | User accounts | NAME, CREATED_ON, DELETED_ON, HAS_PASSWORD, HAS_RSA_PUBLIC_KEY | TA0003 Persistence |
| `ROLES` | Role definitions | NAME, CREATED_ON, DELETED_ON | TA0003 Persistence |
| `COPY_HISTORY` | Data loading/unloading | FILE_NAME, STAGE_LOCATION, ROW_COUNT | T1074 Data Staged |
| `DATA_TRANSFER_HISTORY` | Cross-region/cloud transfers | SOURCE_CLOUD, TARGET_CLOUD, BYTES_TRANSFERRED | T1041 Exfiltration |
| `MASKING_POLICIES` | Data masking configs | POLICY_NAME, CREATED, LAST_ALTERED | TA0005 Defense Evasion |
| `ROW_ACCESS_POLICIES` | Row-level security | POLICY_NAME, CREATED, LAST_ALTERED | TA0005 Defense Evasion |

**Note:** Account Usage views have a latency of 45 minutes to 3 hours. For real-time monitoring, use Information Schema table functions.

### Discovering Available Log Tables

Before writing queries, discover what security data is available:

```sql
-- List all views in ACCOUNT_USAGE
SELECT TABLE_NAME, COMMENT
FROM SNOWFLAKE.INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'ACCOUNT_USAGE'
ORDER BY TABLE_NAME;

-- Check what columns are available in a specific view
DESCRIBE TABLE SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY;

-- Sample data to understand structure
SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY LIMIT 10;
```

---

## Threat Detection Patterns

### Authentication Attacks

#### Brute Force Detection
```sql
-- Detect brute force attempts (configurable thresholds)
WITH login_failures AS (
    SELECT 
        CLIENT_IP,
        USER_NAME,
        COUNT(*) as failed_attempts,
        MIN(EVENT_TIMESTAMP) as first_attempt,
        MAX(EVENT_TIMESTAMP) as last_attempt,
        DATEDIFF('minute', MIN(EVENT_TIMESTAMP), MAX(EVENT_TIMESTAMP)) as duration_minutes
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE IS_SUCCESS = 'NO'
      AND EVENT_TIMESTAMP >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
    GROUP BY CLIENT_IP, USER_NAME
)
SELECT *
FROM login_failures
WHERE failed_attempts >= 10  -- Adjust threshold
  AND duration_minutes <= 60  -- Within 1 hour
ORDER BY failed_attempts DESC;
```

#### Credential Stuffing Indicators
```sql
-- Multiple users from same IP with failures
SELECT 
    CLIENT_IP,
    COUNT(DISTINCT USER_NAME) as unique_users_attempted,
    SUM(CASE WHEN IS_SUCCESS = 'NO' THEN 1 ELSE 0 END) as failures,
    SUM(CASE WHEN IS_SUCCESS = 'YES' THEN 1 ELSE 0 END) as successes
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE EVENT_TIMESTAMP >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
GROUP BY CLIENT_IP
HAVING unique_users_attempted >= 5 AND failures > successes
ORDER BY unique_users_attempted DESC;
```

#### Impossible Travel Detection
```sql
-- Users logging in from different geolocations in short time
WITH user_logins AS (
    SELECT 
        USER_NAME,
        EVENT_TIMESTAMP,
        CLIENT_IP,
        REPORTED_CLIENT_TYPE,
        LAG(CLIENT_IP) OVER (PARTITION BY USER_NAME ORDER BY EVENT_TIMESTAMP) as prev_ip,
        LAG(EVENT_TIMESTAMP) OVER (PARTITION BY USER_NAME ORDER BY EVENT_TIMESTAMP) as prev_time
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE IS_SUCCESS = 'YES'
      AND EVENT_TIMESTAMP >= DATEADD('day', -7, CURRENT_TIMESTAMP())
)
SELECT *
FROM user_logins
WHERE prev_ip IS NOT NULL 
  AND CLIENT_IP != prev_ip
  AND DATEDIFF('minute', prev_time, EVENT_TIMESTAMP) < 60  -- Less than 1 hour apart
ORDER BY USER_NAME, EVENT_TIMESTAMP;
```

### Privilege Escalation Detection

```sql
-- Detect new role grants (potential privilege escalation)
SELECT 
    CREATED_ON,
    ROLE,
    GRANTEE_NAME,
    GRANTED_BY
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE CREATED_ON >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN')  -- High-privilege roles
ORDER BY CREATED_ON DESC;

-- Detect privilege grants to roles
SELECT 
    CREATED_ON,
    PRIVILEGE,
    GRANTED_ON,
    NAME as object_name,
    GRANTEE_NAME,
    GRANTED_BY
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE CREATED_ON >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND PRIVILEGE IN ('OWNERSHIP', 'ALL', 'MANAGE GRANTS')
ORDER BY CREATED_ON DESC;
```

### Data Exfiltration Indicators

```sql
-- Large data exports via COPY INTO
SELECT 
    QUERY_START_TIME,
    USER_NAME,
    ROLE_NAME,
    QUERY_TEXT,
    ROWS_PRODUCED,
    BYTES_SCANNED
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE QUERY_TYPE = 'UNLOAD'
  AND QUERY_START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND ROWS_PRODUCED > 100000  -- Large exports
ORDER BY ROWS_PRODUCED DESC;

-- Cross-region data transfers
SELECT 
    START_TIME,
    SOURCE_CLOUD,
    SOURCE_REGION,
    TARGET_CLOUD,
    TARGET_REGION,
    BYTES_TRANSFERRED
FROM SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY
WHERE START_TIME >= DATEADD('day', -30, CURRENT_TIMESTAMP())
ORDER BY BYTES_TRANSFERRED DESC;
```

### Suspicious Query Patterns

```sql
-- Queries accessing sensitive tables (customize table list)
SELECT 
    QUERY_START_TIME,
    USER_NAME,
    ROLE_NAME,
    QUERY_TEXT,
    EXECUTION_STATUS
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE QUERY_START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND (
    LOWER(QUERY_TEXT) LIKE '%password%'
    OR LOWER(QUERY_TEXT) LIKE '%credit_card%'
    OR LOWER(QUERY_TEXT) LIKE '%ssn%'
    OR LOWER(QUERY_TEXT) LIKE '%secret%'
  )
ORDER BY QUERY_START_TIME DESC;

-- Failed queries (potential SQL injection or recon)
SELECT 
    QUERY_START_TIME,
    USER_NAME,
    ERROR_CODE,
    ERROR_MESSAGE,
    QUERY_TEXT
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE EXECUTION_STATUS = 'FAIL'
  AND QUERY_START_TIME >= DATEADD('day', -1, CURRENT_TIMESTAMP())
ORDER BY QUERY_START_TIME DESC
LIMIT 100;
```

---

## Web Application Attack Detection

For web access logs stored in Snowflake, use these detection patterns:

### SQL Injection Detection
```sql
-- Detect SQLi patterns in request data
-- Adjust table/column names to match your log schema
SELECT 
    timestamp_col,
    source_ip,
    request_path,
    user_agent
FROM your_database.your_schema.access_logs
WHERE LOWER(request_path) REGEXP '.*(union.*select|select.*from|insert.*into|drop.*table|;.*--|\'.*or.*\'|1=1|benchmark\().*'
ORDER BY timestamp_col DESC
LIMIT 100;
```

### XSS Detection
```sql
-- Detect XSS attempts
SELECT 
    timestamp_col,
    source_ip,
    request_path,
    request_body
FROM your_database.your_schema.access_logs
WHERE LOWER(request_path) REGEXP '.*(<script|javascript:|onerror=|onload=|onclick=|<iframe|<img.*src=).*'
   OR LOWER(request_body) REGEXP '.*(<script|javascript:|onerror=|onload=).*'
ORDER BY timestamp_col DESC;
```

### Path Traversal Detection
```sql
-- Detect directory traversal attempts
SELECT 
    timestamp_col,
    source_ip,
    request_path
FROM your_database.your_schema.access_logs
WHERE request_path LIKE '%../%'
   OR request_path LIKE '%..\\%'
   OR request_path LIKE '%/etc/passwd%'
   OR request_path LIKE '%/etc/shadow%'
   OR request_path LIKE '%boot.ini%'
   OR request_path LIKE '%win.ini%'
ORDER BY timestamp_col DESC;
```

### Command Injection Detection
```sql
-- Detect OS command injection attempts
SELECT 
    timestamp_col,
    source_ip,
    request_path,
    request_body
FROM your_database.your_schema.access_logs
WHERE LOWER(request_path) REGEXP '.*(;.*cat |;.*ls |\\|.*cat |\\|.*ls |`.*`|\\$\\(.*\\)).*'
   OR LOWER(request_body) REGEXP '.*(;.*cat |;.*ls |\\|.*cat |`.*`).*'
ORDER BY timestamp_col DESC;
```

---

## Cloud Security Posture Analysis

For cloud provider logs (AWS CloudTrail, GCP Audit Logs, Azure Activity Logs) stored in Snowflake:

### IAM/Permission Changes
```sql
-- Detect IAM changes (adjust for your log schema)
-- Example for AWS CloudTrail in JSON format
SELECT 
    event_time,
    V:userIdentity:userName::STRING as user_name,
    V:eventName::STRING as event_name,
    V:sourceIPAddress::STRING as source_ip,
    V:requestParameters::STRING as request_params
FROM your_database.your_schema.cloudtrail_logs
WHERE V:eventName::STRING IN (
    'AttachRolePolicy',
    'AttachUserPolicy',
    'CreateRole',
    'CreateUser',
    'CreateAccessKey',
    'PutRolePolicy',
    'PutUserPolicy',
    'AddUserToGroup',
    'UpdateLoginProfile'
)
ORDER BY event_time DESC;
```

### Security Group Changes
```sql
-- Detect security group/firewall modifications
SELECT 
    event_time,
    V:userIdentity:userName::STRING as user_name,
    V:eventName::STRING as event_name,
    V:requestParameters::STRING as request_params
FROM your_database.your_schema.cloudtrail_logs
WHERE V:eventName::STRING IN (
    'AuthorizeSecurityGroupIngress',
    'AuthorizeSecurityGroupEgress',
    'RevokeSecurityGroupIngress',
    'CreateSecurityGroup',
    'DeleteSecurityGroup',
    'ModifyNetworkAcl'
)
ORDER BY event_time DESC;
```

---

## Incident Investigation Workflows

### Workflow 1: Investigate Suspicious User

```sql
-- Step 1: User login history
SELECT EVENT_TIMESTAMP, CLIENT_IP, IS_SUCCESS, FIRST_AUTHENTICATION_FACTOR
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE USER_NAME = '<USER>'
ORDER BY EVENT_TIMESTAMP DESC
LIMIT 50;

-- Step 2: User's recent queries
SELECT QUERY_START_TIME, QUERY_TYPE, QUERY_TEXT, ROWS_PRODUCED, EXECUTION_STATUS
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE USER_NAME = '<USER>'
  AND QUERY_START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY QUERY_START_TIME DESC;

-- Step 3: User's data access
SELECT QUERY_START_TIME, DIRECT_OBJECTS_ACCESSED, BASE_OBJECTS_ACCESSED
FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY
WHERE USER_NAME = '<USER>'
  AND QUERY_START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY QUERY_START_TIME DESC;

-- Step 4: User's role grants
SELECT CREATED_ON, ROLE, GRANTED_BY
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE GRANTEE_NAME = '<USER>'
ORDER BY CREATED_ON DESC;
```

### Workflow 2: Investigate IP Address

```sql
-- Step 1: Login attempts from IP
SELECT EVENT_TIMESTAMP, USER_NAME, IS_SUCCESS, ERROR_CODE
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE CLIENT_IP = '<IP_ADDRESS>'
ORDER BY EVENT_TIMESTAMP DESC;

-- Step 2: All users that logged in from this IP
SELECT DISTINCT USER_NAME, COUNT(*) as login_count
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE CLIENT_IP = '<IP_ADDRESS>'
  AND IS_SUCCESS = 'YES'
GROUP BY USER_NAME;

-- Step 3: Sessions from this IP
SELECT USER_NAME, CREATED_ON, AUTHENTICATION_METHOD
FROM SNOWFLAKE.ACCOUNT_USAGE.SESSIONS
WHERE CLIENT_IP = '<IP_ADDRESS>'
ORDER BY CREATED_ON DESC;
```

### Workflow 3: Build Incident Timeline

```sql
-- Combined timeline across log sources
-- Adjust table names for your environment

-- Snowflake events
SELECT 
    EVENT_TIMESTAMP as event_time,
    'LOGIN' as event_type,
    USER_NAME as actor,
    CLIENT_IP as source,
    CASE WHEN IS_SUCCESS = 'YES' THEN 'SUCCESS' ELSE 'FAILED' END as result
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE EVENT_TIMESTAMP BETWEEN '<START_TIME>' AND '<END_TIME>'

UNION ALL

SELECT 
    QUERY_START_TIME as event_time,
    'QUERY' as event_type,
    USER_NAME as actor,
    ROLE_NAME as source,
    EXECUTION_STATUS as result
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE QUERY_START_TIME BETWEEN '<START_TIME>' AND '<END_TIME>'
  AND QUERY_TYPE NOT IN ('SELECT')  -- Focus on write operations

ORDER BY event_time;
```

---

## Vulnerability Assessment

### CVE Severity Classification

| CVSS Score | Severity | Response Time |
|------------|----------|---------------|
| 9.0 - 10.0 | Critical | 24-48 hours |
| 7.0 - 8.9 | High | 7 days |
| 4.0 - 6.9 | Medium | 30 days |
| 0.1 - 3.9 | Low | 90 days |

### Common CVE Categories to Monitor

| Category | Examples | Detection Approach |
|----------|----------|-------------------|
| Remote Code Execution | Log4Shell, Spring4Shell | Scan dependencies, WAF rules |
| SQL Injection | Various CVEs | Input validation, parameterized queries |
| Authentication Bypass | OAuth flaws, JWT issues | Auth log monitoring, token analysis |
| Privilege Escalation | Kernel vulns, misconfigs | System hardening, monitoring |
| Denial of Service | ReDoS, resource exhaustion | Rate limiting, anomaly detection |

---

## Integration with Snowflake Skills

This security skill is designed to work seamlessly with other Cortex Code Snowflake skills. Use the skill command (e.g., `/skill-name`) to invoke these integrations.

### Data Governance & Access Control

| Skill | Security Use Case |
|-------|-------------------|
| **data-governance** | Audit masking policies, row access policies, tag-based access controls. Review who has access to sensitive data. Essential for compliance (GDPR, HIPAA, PCI-DSS). |
| **lineage** | Trace data flow from source to consumption. Identify all downstream consumers of compromised or sensitive data. Critical for breach impact assessment. |
| **data-quality** | Detect data tampering or integrity issues. Anomalous data quality metrics may indicate injection attacks or unauthorized modifications. |

**Example workflow:** After detecting suspicious access, use `lineage` to identify all tables/views the attacker could have accessed, then use `data-governance` to audit what masking policies protected sensitive columns.

### Monitoring & Observability

| Skill | Security Use Case |
|-------|-------------------|
| **dynamic-tables** | Create real-time security dashboards with auto-refresh. Build multi-stage detection pipelines: raw → enriched → aggregated → alerts. Use DOWNSTREAM for intermediates, TARGET_LAG for final alert tables. See [Dynamic Tables for Security Monitoring](#dynamic-tables-for-security-monitoring) section. |
| **cost-intelligence** | Detect cryptomining (unusual compute spikes), data exfiltration (expensive queries moving large data), or compromised service accounts running unexpected workloads. |
| **trust-center** | Review Snowflake Trust Center security findings, scanner results, CIS benchmarks, and security posture. Integrate with vulnerability management workflows. |

**Example workflow:** Use `dynamic-tables` to create a 3-stage pipeline: `dt_enriched_logins` (DOWNSTREAM) → `dt_login_aggregates` (DOWNSTREAM) → `dt_brute_force_alerts` (5-minute lag). Create an Alert on the final DT to notify SOC. Use `cost-intelligence` to correlate with compute anomalies.

### Identity & Organization

| Skill | Security Use Case |
|-------|-------------------|
| **organization-management** | Audit cross-account access, review organization-wide security posture, identify accounts with weak MFA adoption, review globalorgadmin usage. |
| **cortex-agent** | Build security chatbots that can answer questions about your security posture using natural language queries against your log data. |

**Example workflow:** Use `organization-management` to get a 30-day security summary across all accounts, identify users without MFA, review authentication failures org-wide.

### Data Pipeline Security

| Skill | Security Use Case |
|-------|-------------------|
| **openflow** | Audit data ingestion pipelines for security. Review connector configurations, detect unauthorized data sources, monitor CDC replication for tampering. Use ListenOTLP processor for native OpenTelemetry ingestion. |
| **dbt-projects-on-snowflake** | Apply Detection-as-Code practices: version-controlled detection models, automated testing, CI/CD deployment. Create staging/intermediate/marts layers for security data. Audit transformations for SQL injection risks. See [dbt for Security Data Transformation](#dbt-for-security-data-transformation) section. |
| **iceberg** | Audit external table access, review catalog integrations, monitor auto-refresh for unauthorized external data access attempts. |

**Example workflow:** Use `dbt-projects-on-snowflake` to build a security data warehouse with `stg_login_history` → `int_failed_logins` → `det_brute_force` models. Use dbt tests to validate detection quality. Deploy critical detections as Dynamic Tables for production monitoring.

### Application Security

| Skill | Security Use Case |
|-------|-------------------|
| **developing-with-streamlit** | Build security dashboards and incident response tools. Create internal SOC applications for threat hunting and investigation. |
| **deploy-to-spcs** | Review container security for SPCS deployments. Audit network policies, secrets management, and container image sources. |
| **build-react-app** | Create custom security portals for stakeholders to view security metrics and incident status. |
| **snowflake-notebooks** | Develop and share security analysis notebooks. Create reproducible investigation workflows and threat hunting playbooks. |

**Example workflow:** Use `developing-with-streamlit` to build a SOC dashboard showing real-time login failures, privilege escalations, and data exfiltration alerts.

### AI & Analytics Security

| Skill | Security Use Case |
|-------|-------------------|
| **cortex-ai-functions** | Use AI_CLASSIFY for log categorization, AI_EXTRACT for parsing unstructured security logs, AI_SENTIMENT for analyzing threat intel reports. |
| **machine-learning** | Build anomaly detection models for user behavior analytics (UEBA). Train models to detect insider threats and compromised accounts. |
| **semantic-view** | Create semantic models over security data for natural language querying by non-technical security stakeholders. |
| **search-optimization** | Optimize Cortex Search for security log searches. Enable fast full-text search across incident reports and threat intel. |

**Example workflow:** Use `machine-learning` to train a model on normal user behavior, then score new sessions for anomaly detection. Use `cortex-ai-functions` to automatically categorize security events.

### Collaboration & Sharing

| Skill | Security Use Case |
|-------|-------------------|
| **data-cleanrooms** | Securely share threat intelligence with partners without exposing raw data. Collaborate on cross-organization threat hunting. |
| **declarative-sharing** | Share security dashboards and aggregated threat metrics with subsidiaries or partners via Snowflake data sharing. |
| **integrations** | Set up API integrations for SIEM tools, SOAR platforms, and ticketing systems (ServiceNow, Jira). |

**Example workflow:** Use `data-cleanrooms` to collaborate with industry partners on threat indicators without exposing your raw log data.

### Infrastructure & Database

| Skill | Security Use Case |
|-------|-------------------|
| **snowflake-postgres** | Monitor Snowflake Postgres instances for security. Review connection patterns, audit queries, detect SQL injection attempts. |

### Skill Cross-Reference Matrix

| Security Task | Primary Skill | Supporting Skills |
|---------------|---------------|-------------------|
| Breach investigation | **security-ops** | lineage, data-governance, cost-intelligence |
| Compliance audit | **data-governance** | trust-center, organization-management |
| Real-time monitoring | **dynamic-tables** | security-ops, developing-with-streamlit |
| Anomaly detection | **machine-learning** | security-ops, cortex-ai-functions |
| Incident dashboard | **developing-with-streamlit** | security-ops, dynamic-tables |
| Threat intel sharing | **data-cleanrooms** | declarative-sharing, integrations |
| Security chatbot | **cortex-agent** | security-ops, semantic-view |
| Pipeline audit | **openflow** | lineage, dbt-projects-on-snowflake |
| Container security | **deploy-to-spcs** | security-ops, trust-center |
| Org-wide posture | **organization-management** | trust-center, security-ops |

---

## Alert Thresholds (Configurable)

| Metric | Warning | Critical |
|--------|---------|----------|
| Failed logins (per user/hour) | 5 | 10 |
| Failed logins (per IP/hour) | 10 | 25 |
| Unique users from single IP (per hour) | 3 | 10 |
| Large data exports (rows) | 100,000 | 1,000,000 |
| Privilege grants to admin roles | 1 | 3 |
| New users created (per day) | 5 | 20 |
| Security policy changes (per day) | 2 | 5 |

---

## Response Checklists

### When Detecting Potential Breach
1. **Contain** — Disable compromised accounts, revoke sessions
2. **Preserve** — Capture logs, don't modify evidence
3. **Investigate** — Build timeline, identify scope
4. **Remediate** — Patch vulnerabilities, rotate credentials
5. **Report** — Document incident, notify stakeholders
6. **Improve** — Update detection rules, address gaps

### SQL Commands for Containment
```sql
-- Disable a compromised user
ALTER USER suspicious_user SET DISABLED = TRUE;

-- Kill active sessions for a user
-- (Requires ACCOUNTADMIN or SECURITYADMIN role)
SELECT SYSTEM$ABORT_SESSION(<session_id>);

-- Revoke all privileges from a role
REVOKE ALL PRIVILEGES ON ALL SCHEMAS IN DATABASE mydb FROM ROLE compromised_role;
```

---

## Quick Reference

| Task | Approach |
|------|----------|
| Check for brute force | Query LOGIN_HISTORY for failed attempts by IP |
| Detect privilege escalation | Query GRANTS_TO_USERS/ROLES for recent admin grants |
| Find data exfiltration | Query QUERY_HISTORY for UNLOAD, COPY_HISTORY |
| Investigate user | Query LOGIN_HISTORY, QUERY_HISTORY, ACCESS_HISTORY |
| Build incident timeline | UNION across log sources with time filter |
| Check authentication methods | Query SESSIONS for AUTHENTICATION_METHOD |
| Find policy changes | Query MASKING_POLICIES, ROW_ACCESS_POLICIES |

---

## Snowflake-Native Security Architecture Best Practices

### Philosophy: Raw Logs First, Transform Only When Necessary

**Core Principle:** Keep logs in their original format as long as possible. Transformation should serve specific purposes, not compliance to arbitrary schemas.

#### When to Transform Logs

| Transform For | Examples | Justification |
|---------------|----------|---------------|
| **Team collaboration** | Unified analyst dashboard views | Different teams need different perspectives |
| **Tool interoperability** | Grafana, Streamlit, external SIEM | Required format for consumption |
| **Dashboarding** | Executive metrics, SOC KPIs | Aggregated views need structure |
| **Specific integrations** | SOAR playbooks, ticketing | API payload requirements |
| **Performance optimization** | Pre-aggregated metrics tables | Query performance on hot paths |

#### When NOT to Transform

| Avoid Transformation For | Reason |
|--------------------------|--------|
| Schema compliance alone | Adds complexity without value |
| "Industry standard" conformance | Original logs contain maximum context |
| Future-proofing | Requirements change; raw data is flexible |
| Vendor lock-in avoidance | Snowflake handles any schema natively |

### Industry Log Schema Standards (Reference Only)

These are common standards you may encounter. **Do not transform logs to these formats just for compliance.** Reference them when integrating with tools that require them.

| Standard | Purpose | Key Characteristics |
|----------|---------|---------------------|
| **OCSF** (Open Cybersecurity Schema Framework) | Vendor-agnostic security events | JSON-based, extensible, Linux Foundation project |
| **ECS** (Elastic Common Schema) | Elastic ecosystem | Field naming conventions, nested objects |
| **CEF** (Common Event Format) | Legacy SIEM integration | Key=value pairs, syslog transport |
| **LEEF** (Log Event Extended Format) | IBM QRadar | Tab-separated, similar to CEF |
| **STIX** (Structured Threat Information eXpression) | Threat intelligence sharing | JSON-based, describes threats and indicators |
| **TAXII** (Trusted Automated eXchange of Intelligence Information) | STIX transport protocol | HTTPS-based, collection/channel model |

### Recommended Snowflake Architecture for Security Logs

```
┌─────────────────────────────────────────────────────────────────────┐
│                     RAW INGESTION LAYER                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  Snowpipe    │  │  Snowpipe    │  │  External    │               │
│  │  Streaming   │  │  (Batch)     │  │  Functions   │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                 │                        │
│         ▼                 ▼                 ▼                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              RAW_LOGS Database (VARIANT columns)             │    │
│  │  • cloudtrail_raw  • vpc_flow_raw  • okta_raw  • etc.       │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     PROCESSING LAYER                                 │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │           Stored Procedures (Detection as Code)               │   │
│  │  • Scheduled via Tasks                                        │   │
│  │  • Parameterized detection logic                              │   │
│  │  • Version controlled in Git                                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │           Dynamic Tables (Real-time Monitoring)               │   │
│  │  • Continuous refresh for dashboards                          │   │
│  │  • Aggregated security metrics                                │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     OUTPUT LAYER                                     │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │  Alerts    │  │  Findings  │  │  Incidents │  │  Dashboards│    │
│  │  Table     │  │  Table     │  │  Table     │  │  (Views)   │    │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │
│        │               │               │               │            │
│        ▼               ▼               ▼               ▼            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │           Notification Integration                            │   │
│  │  • Email  • Webhooks  • Jira/ServiceNow  • PagerDuty         │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Raw Log Ingestion via Snowpipe

#### Snowpipe Streaming (Recommended for Real-time)

```sql
-- Create a stage for incoming logs
CREATE OR REPLACE STAGE raw_logs_stage
  URL = 's3://your-bucket/security-logs/'
  STORAGE_INTEGRATION = your_storage_integration;

-- Create raw log table with VARIANT for flexibility
CREATE OR REPLACE TABLE raw_logs.cloudtrail_raw (
    ingestion_time TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    source_file VARCHAR,
    raw_data VARIANT
);

-- Create Snowpipe for automatic ingestion
CREATE OR REPLACE PIPE raw_logs.cloudtrail_pipe
  AUTO_INGEST = TRUE
  AS
  COPY INTO raw_logs.cloudtrail_raw (source_file, raw_data)
  FROM (
    SELECT 
      METADATA$FILENAME,
      $1
    FROM @raw_logs_stage
  )
  FILE_FORMAT = (TYPE = JSON);
```

#### Why VARIANT Columns

- Preserves original structure completely
- No schema migration when log format changes
- Query nested fields with `:`notation: `raw_data:userIdentity:userName`
- Automatic type inference on query
- Compress well due to repeated structure

---

## Triage and False Positive Management

### Understanding False Positives in Context

A **false positive** is an alert that fires but doesn't represent a real threat. However, many alerts fire on activity that IS happening but is **already mitigated** by other controls.

#### Triage Decision Framework

```
┌─────────────────────────────────────────────────────────────────┐
│                      Alert Generated                             │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Is this activity actually occurring?                    │
│  ┌─────────┐                           ┌─────────┐              │
│  │   NO    │ → Log error, fix detection│   YES   │              │
│  └─────────┘                           └────┬────┘              │
└─────────────────────────────────────────────┼───────────────────┘
                                              │
                          ┌───────────────────┴───────────────────┐
                          ▼                                       │
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Is this activity authorized?                            │
│  (Check against KNOWN_AUTHORIZED_ACTIVITIES table)               │
│  ┌─────────┐                           ┌─────────┐              │
│  │   YES   │ → Close as expected       │   NO    │              │
│  └─────────┘                           └────┬────┘              │
└─────────────────────────────────────────────┼───────────────────┘
                                              │
                          ┌───────────────────┴───────────────────┐
                          ▼                                       │
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: Is this mitigated by other controls?                    │
│  (Check against COMPENSATING_CONTROLS table)                     │
│  ┌─────────┐                           ┌─────────┐              │
│  │   YES   │ → Close, document control │   NO    │              │
│  └─────────┘                           └────┬────┘              │
└─────────────────────────────────────────────┼───────────────────┘
                                              │
                          ┌───────────────────┴───────────────────┐
                          ▼                                       │
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: ESCALATE AS TRUE POSITIVE                               │
│  → Create incident                                               │
│  → Begin investigation                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Knowledge Tables for Triage

```sql
-- Table of known authorized activities (whitelist)
CREATE TABLE security_ops.known_authorized_activities (
    id INT AUTOINCREMENT,
    activity_type VARCHAR,
    pattern VARCHAR,  -- Regex or exact match
    authorized_users ARRAY,
    authorized_ips ARRAY,
    authorized_roles ARRAY,
    justification VARCHAR,
    approved_by VARCHAR,
    approved_on TIMESTAMP_LTZ,
    expires_on TIMESTAMP_LTZ,
    is_active BOOLEAN DEFAULT TRUE
);

-- Table of compensating controls
CREATE TABLE security_ops.compensating_controls (
    id INT AUTOINCREMENT,
    threat_type VARCHAR,  -- e.g., 'brute_force', 'data_exfil'
    control_type VARCHAR,  -- e.g., 'network_segmentation', 'mfa_required'
    control_description VARCHAR,
    mitigates_risk_by VARCHAR,  -- How it reduces risk
    evidence_query VARCHAR,  -- SQL to verify control is active
    last_verified TIMESTAMP_LTZ,
    is_active BOOLEAN DEFAULT TRUE
);

-- Table of known threat actors/IOCs
CREATE TABLE security_ops.threat_indicators (
    id INT AUTOINCREMENT,
    indicator_type VARCHAR,  -- 'ip', 'domain', 'hash', 'email', 'user_agent'
    indicator_value VARCHAR,
    threat_actor VARCHAR,
    confidence VARCHAR,  -- 'high', 'medium', 'low'
    source VARCHAR,
    first_seen TIMESTAMP_LTZ,
    last_seen TIMESTAMP_LTZ,
    is_active BOOLEAN DEFAULT TRUE
);
```

### AI-Assisted Triage with Cortex

Use Cortex AI functions to assist with triage decisions:

```sql
-- AI-assisted alert triage
CREATE OR REPLACE PROCEDURE security_ops.ai_triage_alert(alert_id INT)
RETURNS TABLE (
    alert_id INT,
    triage_decision VARCHAR,
    confidence FLOAT,
    reasoning VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    alert_context VARCHAR;
BEGIN
    -- Gather alert context
    SELECT OBJECT_CONSTRUCT(
        'alert_type', alert_type,
        'source_ip', source_ip,
        'user', user_name,
        'activity', activity_description,
        'known_authorized', (
            SELECT COUNT(*) FROM known_authorized_activities 
            WHERE pattern = :alert_type AND is_active = TRUE
        ),
        'compensating_controls', (
            SELECT ARRAY_AGG(control_description) 
            FROM compensating_controls 
            WHERE threat_type = :alert_type AND is_active = TRUE
        )
    )::VARCHAR
    INTO alert_context
    FROM security_alerts WHERE id = alert_id;

    -- Use Cortex to analyze
    RETURN TABLE(
        SELECT 
            alert_id,
            SNOWFLAKE.CORTEX.COMPLETE(
                'mistral-large',
                'You are a security analyst. Based on this alert context, provide a triage decision (ESCALATE, CLOSE_AUTHORIZED, CLOSE_MITIGATED, INVESTIGATE_FURTHER) and brief reasoning. Context: ' || alert_context
            ):decision::VARCHAR as triage_decision,
            SNOWFLAKE.CORTEX.COMPLETE(...):confidence::FLOAT as confidence,
            SNOWFLAKE.CORTEX.COMPLETE(...):reasoning::VARCHAR as reasoning
    );
END;
$$;
```

---

## Knowledge Graphs for Threat Tracking

### Attack Actor Ontology Model

Track threat actors, their infrastructure, and lateral movement using a graph-like structure in Snowflake.

#### Entity Tables

```sql
-- Actors (threat actors, users, service accounts)
CREATE TABLE security_ops.kg_actors (
    actor_id VARCHAR PRIMARY KEY,
    actor_type VARCHAR,  -- 'threat_actor', 'user', 'service_account', 'external_entity'
    name VARCHAR,
    first_seen TIMESTAMP_LTZ,
    last_seen TIMESTAMP_LTZ,
    attributes VARIANT,  -- Flexible attributes
    threat_score FLOAT,  -- 0.0 to 1.0
    is_active BOOLEAN DEFAULT TRUE
);

-- Devices/Infrastructure (servers, endpoints, cloud resources)
CREATE TABLE security_ops.kg_infrastructure (
    infra_id VARCHAR PRIMARY KEY,
    infra_type VARCHAR,  -- 'server', 'endpoint', 'cloud_resource', 'c2_server', 'vpn_exit'
    identifier VARCHAR,  -- IP, hostname, resource ARN
    first_seen TIMESTAMP_LTZ,
    last_seen TIMESTAMP_LTZ,
    attributes VARIANT,
    compromise_status VARCHAR,  -- 'clean', 'suspected', 'confirmed_compromised'
    is_active BOOLEAN DEFAULT TRUE
);

-- Relationships (edges in the graph)
CREATE TABLE security_ops.kg_relationships (
    relationship_id INT AUTOINCREMENT,
    source_type VARCHAR,  -- 'actor' or 'infrastructure'
    source_id VARCHAR,
    relationship_type VARCHAR,  -- See relationship types below
    target_type VARCHAR,
    target_id VARCHAR,
    first_observed TIMESTAMP_LTZ,
    last_observed TIMESTAMP_LTZ,
    observation_count INT DEFAULT 1,
    confidence FLOAT,  -- 0.0 to 1.0
    evidence VARIANT,  -- Supporting log references
    is_active BOOLEAN DEFAULT TRUE
);

-- Relationship types:
-- Actor → Infrastructure: 'used', 'controlled', 'accessed', 'authenticated_from'
-- Actor → Actor: 'impersonated', 'phished', 'collaborated_with', 'infected'
-- Infrastructure → Infrastructure: 'connected_to', 'lateral_movement', 'data_exfil_to'
```

#### Timeline Events

```sql
-- Chronological attack timeline
CREATE TABLE security_ops.kg_timeline (
    event_id INT AUTOINCREMENT,
    event_time TIMESTAMP_LTZ,
    actor_id VARCHAR,
    infra_id VARCHAR,
    event_type VARCHAR,  -- 'initial_access', 'execution', 'lateral_movement', etc.
    mitre_technique VARCHAR,  -- e.g., 'T1078'
    description VARCHAR,
    raw_log_reference VARCHAR,  -- Pointer to original log
    investigation_id VARCHAR,  -- Links events to an investigation
    is_confirmed BOOLEAN DEFAULT FALSE
);
```

#### Graph Queries for Lateral Movement

```sql
-- Find all infrastructure touched by a threat actor (direct and indirect)
WITH RECURSIVE actor_reach AS (
    -- Direct connections
    SELECT 
        r.target_id as infra_id,
        1 as hop_count,
        ARRAY_CONSTRUCT(r.source_id, r.target_id) as path
    FROM security_ops.kg_relationships r
    WHERE r.source_type = 'actor' 
      AND r.source_id = :threat_actor_id
      AND r.target_type = 'infrastructure'
    
    UNION ALL
    
    -- Lateral movement (infrastructure to infrastructure)
    SELECT 
        r.target_id,
        ar.hop_count + 1,
        ARRAY_APPEND(ar.path, r.target_id)
    FROM actor_reach ar
    JOIN security_ops.kg_relationships r
        ON r.source_id = ar.infra_id
        AND r.source_type = 'infrastructure'
        AND r.target_type = 'infrastructure'
        AND r.relationship_type = 'lateral_movement'
    WHERE ar.hop_count < 10  -- Limit recursion depth
      AND NOT ARRAY_CONTAINS(r.target_id::VARIANT, ar.path)  -- Prevent cycles
)
SELECT DISTINCT 
    infra_id,
    MIN(hop_count) as min_hops,
    i.infra_type,
    i.identifier,
    i.compromise_status
FROM actor_reach ar
JOIN security_ops.kg_infrastructure i ON ar.infra_id = i.infra_id
GROUP BY infra_id, i.infra_type, i.identifier, i.compromise_status
ORDER BY min_hops;
```

---

## Detection as Code

### Stored Procedures as Detection Rules

Detection as Code applies software engineering practices to security detection:
- **Version control** — Git-based workflows for detection logic
- **Testing** — Validate detections against known-good and known-bad data
- **CI/CD** — Automated deployment of detection updates
- **Code review** — Peer review for detection logic changes

#### Detection Procedure Template

```sql
CREATE OR REPLACE PROCEDURE security_ops.detect_<detection_name>(
    lookback_hours INT DEFAULT 24,
    dry_run BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    detection_id VARCHAR,
    detection_name VARCHAR,
    severity VARCHAR,
    confidence FLOAT,
    entity_type VARCHAR,
    entity_id VARCHAR,
    description VARCHAR,
    evidence VARIANT,
    mitre_technique VARCHAR,
    recommended_action VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    run_id VARCHAR := UUID_STRING();
    detection_time TIMESTAMP_LTZ := CURRENT_TIMESTAMP();
BEGIN
    -- Log detection run start
    INSERT INTO security_ops.detection_runs (run_id, detection_name, started_at, parameters)
    VALUES (:run_id, '<detection_name>', :detection_time, OBJECT_CONSTRUCT('lookback_hours', :lookback_hours));

    -- Detection logic here
    CREATE OR REPLACE TEMPORARY TABLE detection_results AS
    SELECT
        UUID_STRING() as detection_id,
        '<detection_name>' as detection_name,
        'HIGH' as severity,
        0.85 as confidence,
        'user' as entity_type,
        user_name as entity_id,
        'Suspicious activity detected' as description,
        OBJECT_CONSTRUCT('key_evidence', '...') as evidence,
        'T1078' as mitre_technique,
        'Investigate user activity' as recommended_action
    FROM <your_log_table>
    WHERE <detection_conditions>
      AND event_time >= DATEADD('hour', -:lookback_hours, CURRENT_TIMESTAMP());

    -- If not dry run, insert into alerts table
    IF (NOT dry_run) THEN
        INSERT INTO security_ops.alerts (
            detection_id, detection_name, severity, confidence,
            entity_type, entity_id, description, evidence,
            mitre_technique, recommended_action, created_at
        )
        SELECT *, :detection_time FROM detection_results;
    END IF;

    -- Log detection run completion
    UPDATE security_ops.detection_runs 
    SET completed_at = CURRENT_TIMESTAMP(),
        alerts_generated = (SELECT COUNT(*) FROM detection_results)
    WHERE run_id = :run_id;

    RETURN TABLE(SELECT * FROM detection_results);
END;
$$;
```

#### Scheduling Detections with Tasks

```sql
-- Create a task to run detection every hour
CREATE OR REPLACE TASK security_ops.task_detect_brute_force
  WAREHOUSE = security_warehouse
  SCHEDULE = 'USING CRON 0 * * * * UTC'  -- Every hour
AS
  CALL security_ops.detect_brute_force(lookback_hours => 2, dry_run => FALSE);

-- Enable the task
ALTER TASK security_ops.task_detect_brute_force RESUME;
```

### Trust Center Integration via Native Apps

Package your detection procedures as a **Trust Center Extension** for organization-wide deployment:

1. **Create scanner package manifest** (`tc_extension_manifest.yml`)
2. **Implement scanner stored procedures** returning findings in Trust Center format
3. **Package as Native App** with `trust_center_integration_role`
4. **Register with Trust Center** via `SNOWFLAKE.TRUST_CENTER.REGISTER_EXTENSION`

See [Trust Center Extensions Documentation](https://docs.snowflake.com/en/user-guide/trust-center/trust-center-extensions) for detailed steps.

---

## Notification and Incident Integration

### Snowflake Native Notifications

```sql
-- Create notification integration for email
CREATE OR REPLACE NOTIFICATION INTEGRATION security_email_notifications
  TYPE = EMAIL
  ENABLED = TRUE
  ALLOWED_RECIPIENTS = ('soc@company.com', 'security-alerts@company.com');

-- Create notification integration for webhooks (Slack, Teams, PagerDuty)
CREATE OR REPLACE NOTIFICATION INTEGRATION security_webhook_notifications
  TYPE = QUEUE
  ENABLED = TRUE
  DIRECTION = OUTBOUND
  -- Configure based on your webhook destination
```

### External Access Integration for API Calls

Use External Access Integration to call external APIs (Jira, ServiceNow, etc.):

```sql
-- Create network rule for Jira
CREATE OR REPLACE NETWORK RULE jira_network_rule
  TYPE = HOST_PORT
  VALUE_LIST = ('your-company.atlassian.net:443');

-- Create secret for API token
CREATE OR REPLACE SECRET jira_api_token
  TYPE = GENERIC_STRING
  SECRET_STRING = '<your-api-token>';

-- Create external access integration
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION jira_integration
  ALLOWED_NETWORK_RULES = (jira_network_rule)
  ALLOWED_AUTHENTICATION_SECRETS = (jira_api_token)
  ENABLED = TRUE;

-- UDF to create Jira ticket
CREATE OR REPLACE FUNCTION security_ops.create_jira_ticket(
    project_key VARCHAR,
    summary VARCHAR,
    description VARCHAR,
    priority VARCHAR
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.9'
PACKAGES = ('requests')
HANDLER = 'create_ticket'
EXTERNAL_ACCESS_INTEGRATIONS = (jira_integration)
SECRETS = ('api_token' = jira_api_token)
AS
$$
import requests
import json
import _snowflake

def create_ticket(project_key, summary, description, priority):
    api_token = _snowflake.get_generic_secret_string('api_token')
    
    url = "https://your-company.atlassian.net/rest/api/3/issue"
    headers = {
        "Authorization": f"Basic {api_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": {"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": description}]}
            ]},
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority}
        }
    }
    
    response = requests.post(url, headers=headers, json=payload)
    return {"status": response.status_code, "response": response.json()}
$$;
```

### Automated Incident Creation Task

```sql
-- Task to create incidents for critical alerts
CREATE OR REPLACE TASK security_ops.task_create_incidents
  WAREHOUSE = security_warehouse
  SCHEDULE = 'USING CRON */5 * * * * UTC'  -- Every 5 minutes
AS
BEGIN
    -- Find unprocessed critical alerts
    FOR alert IN (
        SELECT * FROM security_ops.alerts 
        WHERE severity = 'CRITICAL' 
          AND incident_created = FALSE
          AND created_at >= DATEADD('hour', -1, CURRENT_TIMESTAMP())
    )
    DO
        -- Create Jira ticket
        LET ticket_result VARIANT := security_ops.create_jira_ticket(
            'SEC',
            alert.detection_name || ': ' || alert.entity_id,
            alert.description || '\n\nEvidence: ' || alert.evidence::VARCHAR,
            'High'
        );
        
        -- Update alert with incident reference
        UPDATE security_ops.alerts 
        SET incident_created = TRUE,
            incident_reference = :ticket_result:response:key
        WHERE detection_id = alert.detection_id;
    END FOR;
END;
```

---

## Automated SIEM/XDR Integration

Snowflake can automatically alert your SIEM or XDR system of suspicious events without needing to export logs or run external code. This enables automated, fast incident response entirely within Snowflake.

**Benefits:**
- React to security incidents automatically without manual intervention
- No need to host or maintain code outside Snowflake
- Leverage Snowflake's compute for detection while SIEM handles incident workflow
- Monitor any data in Snowflake, not just Snowflake audit logs

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DETECTION LAYER (Snowflake)                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Snowflake Alert Task (runs every 1 minute)                   │   │
│  │  • Checks LOGIN_HISTORY for failed password attempts          │   │
│  │  • Records new events to LOGIN_EVENTS table (deduplicated)    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  LOGIN_EVENTS Table                                           │   │
│  │  • SENT = FALSE (new events)                                  │   │
│  │  • SENT = TRUE (already sent to SIEM)                         │   │
│  │  • SIEM_RESPONSE (API response stored)                        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Snowflake Task (runs every 1 minute)                         │   │
│  │  • Finds unsent events (SENT = FALSE)                         │   │
│  │  • Calls External Access UDF to POST to SIEM API              │   │
│  │  • Updates SENT = TRUE, stores SIEM_RESPONSE                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SIEM/XDR LAYER                                    │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Splunk / Sentinel / CrowdStrike / etc.                       │   │
│  │  • Receives incident via REST API                             │   │
│  │  • Triggers incident response workflow                        │   │
│  │  • Can call back to Snowflake to disable user, get more logs  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Use Case: Service Account Password Monitoring

This pattern is especially valuable for service accounts that must use password authentication (where OAuth/Keypair isn't possible). A single failed login for these accounts should raise an alarm immediately.

**Example:** PowerBI Cloud Service connecting from dynamic IPs where Network Policies are impractical.

### Complete Implementation

#### Step 1: Create SIEM Monitor Role

```sql
-- Create dedicated role for SIEM monitoring
USE ROLE ACCOUNTADMIN;
CREATE OR REPLACE ROLE SIEM_MONITOR;

-- Grant necessary privileges
GRANT CREATE WAREHOUSE ON ACCOUNT TO ROLE SIEM_MONITOR;
GRANT CREATE DATABASE ON ACCOUNT TO ROLE SIEM_MONITOR;
GRANT CREATE ROLE ON ACCOUNT TO ROLE SIEM_MONITOR;
GRANT EXECUTE TASK ON ACCOUNT TO ROLE SIEM_MONITOR;
GRANT EXECUTE ALERT ON ACCOUNT TO ROLE SIEM_MONITOR;
GRANT CREATE INTEGRATION ON ACCOUNT TO ROLE SIEM_MONITOR;

-- Create warehouse and database
USE ROLE SIEM_MONITOR;
CREATE OR REPLACE WAREHOUSE siem_alert_wh WITH WAREHOUSE_SIZE='X-SMALL';
CREATE OR REPLACE DATABASE SIEM_ALERT_DB;
CREATE OR REPLACE SCHEMA SIEM_SCHEMA;

-- Create role with MONITOR privilege on users
CREATE OR REPLACE ROLE MONITOR_USERS;
GRANT ROLE MONITOR_USERS TO ROLE SIEM_MONITOR;

-- Grant MONITOR on all users (requires ACCOUNTADMIN)
USE ROLE ACCOUNTADMIN;
GRANT MONITOR ON USER <user1> TO ROLE MONITOR_USERS;
GRANT MONITOR ON USER <user2> TO ROLE MONITOR_USERS;
-- ... repeat for users to monitor, or use stored procedure to grant on all users
```

#### Step 2: Create Login Events Table and Alert

```sql
USE ROLE SIEM_MONITOR;
USE DATABASE SIEM_ALERT_DB;
USE SCHEMA SIEM_SCHEMA;

-- Table to hold suspicious/failed logins with SIEM tracking
CREATE OR REPLACE TABLE LOGIN_EVENTS (
    EVENT_TIMESTAMP TIMESTAMP_LTZ(3),
    EVENT_ID NUMBER(38,0),
    EVENT_TYPE VARCHAR,
    USER_NAME VARCHAR,
    CLIENT_IP VARCHAR,
    REPORTED_CLIENT_TYPE VARCHAR,
    REPORTED_CLIENT_VERSION VARCHAR,
    FIRST_AUTHENTICATION_FACTOR VARCHAR,
    SECOND_AUTHENTICATION_FACTOR VARCHAR,
    IS_SUCCESS VARCHAR(3),
    ERROR_CODE NUMBER(38,0),
    ERROR_MESSAGE VARCHAR,
    RELATED_EVENT_ID NUMBER(38,0),
    CONNECTION VARCHAR,
    SENT BOOLEAN DEFAULT FALSE,           -- Tracks if sent to SIEM
    SENT_TIME TIMESTAMP_NTZ(9),           -- When it was sent
    SIEM_RESPONSE VARCHAR                 -- API response from SIEM
);

-- View for failed password logins in the last 5 minutes
CREATE OR REPLACE VIEW failed_password_logins AS
SELECT * FROM TABLE(
    INFORMATION_SCHEMA.LOGIN_HISTORY(
        TIME_RANGE_START => DATEADD('minutes', -5, CURRENT_TIMESTAMP()),
        TIME_RANGE_END => CURRENT_TIMESTAMP()
    )
)
WHERE IS_SUCCESS = 'NO'
  AND FIRST_AUTHENTICATION_FACTOR = 'PASSWORD'
ORDER BY EVENT_TIMESTAMP;

-- Alert that checks every minute and records new failed logins
CREATE OR REPLACE ALERT detect_failed_logins
    WAREHOUSE = siem_alert_wh
    SCHEDULE = '1 minute'
    IF (EXISTS (SELECT EVENT_ID FROM failed_password_logins))
    THEN
        INSERT INTO LOGIN_EVENTS
        SELECT *, FALSE, NULL, NULL
        FROM failed_password_logins AS src
        WHERE NOT EXISTS (
            SELECT EVENT_ID FROM LOGIN_EVENTS AS tgt
            WHERE tgt.EVENT_ID = src.EVENT_ID
        );

ALTER ALERT detect_failed_logins RESUME;
```

#### Step 3: Create External Access Function for SIEM API

```sql
-- Network rule for your SIEM endpoint
-- Replace with your actual SIEM URL
CREATE OR REPLACE NETWORK RULE siem_network_rule
    MODE = EGRESS
    TYPE = HOST_PORT
    VALUE_LIST = ('your-siem.example.com:443');

-- External access integration
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION siem_api_integration
    ALLOWED_NETWORK_RULES = (siem_network_rule)
    ENABLED = TRUE;

-- Secret for SIEM API authentication
CREATE OR REPLACE SECRET siem_api_token
    TYPE = GENERIC_STRING
    SECRET_STRING = '<your-bearer-token>';

-- Function to send incident to SIEM
CREATE OR REPLACE FUNCTION send_to_siem(incident VARIANT, api_url VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.9'
HANDLER = 'send_incident'
EXTERNAL_ACCESS_INTEGRATIONS = (siem_api_integration)
SECRETS = ('api_token' = siem_api_token)
PACKAGES = ('requests')
AS
$$
import requests
import json
import _snowflake

def send_incident(incident, api_url):
    api_token = _snowflake.get_generic_secret_string('api_token')
    
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    # Adapt payload structure to your SIEM's API format
    payload = {
        "title": f"Snowflake Failed Login: {incident.get('USER_NAME', 'Unknown')}",
        "severity": "high",
        "source": "snowflake",
        "event_time": str(incident.get('EVENT_TIMESTAMP', '')),
        "details": incident
    }
    
    response = requests.post(api_url, headers=headers, json=payload)
    
    return {
        "status_code": response.status_code,
        "response": response.text,
        "incident_id": response.json().get('id') if response.ok else None
    }
$$;
```

#### Step 4: Create Stored Procedure to Send Events

```sql
CREATE OR REPLACE PROCEDURE send_events_to_siem(siem_api_url VARCHAR)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.9'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS CALLER
AS
$$
from snowflake.snowpark import Session
import json

def run(session, siem_api_url):
    # Get unsent events as JSON
    sql_get_events = """
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(*)) AS events
        FROM LOGIN_EVENTS
        WHERE SENT = FALSE
    """
    
    result = session.sql(sql_get_events).collect()
    events = json.loads(result[0]['EVENTS']) if result[0]['EVENTS'] else []
    
    sent_count = 0
    for event in events:
        event_id = event.get('EVENT_ID')
        
        # Send to SIEM
        sql_send = f"""
            UPDATE LOGIN_EVENTS
            SET SENT = TRUE,
                SENT_TIME = CURRENT_TIMESTAMP(),
                SIEM_RESPONSE = send_to_siem(
                    PARSE_JSON('{json.dumps(event)}'),
                    '{siem_api_url}'
                )::VARCHAR
            WHERE EVENT_ID = {event_id}
              AND SENT = FALSE
        """
        session.sql(sql_send).collect()
        sent_count += 1
    
    return f"Sent {sent_count} events to SIEM"
$$;
```

#### Step 5: Schedule the Task

```sql
-- Task to send events to SIEM every minute
CREATE OR REPLACE TASK send_to_siem_task
    WAREHOUSE = siem_alert_wh
    SCHEDULE = '1 minute'
AS
    CALL send_events_to_siem('https://your-siem.example.com/api/v1/incidents');

ALTER TASK send_to_siem_task RESUME;
```

### SIEM API References

| SIEM | Incident API Documentation |
|------|----------------------------|
| **Splunk** | [Splunk Incidents API](https://dev.splunk.com/observability/reference/api/incidents/latest) |
| **Microsoft Sentinel** | [Sentinel Incidents REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents) |
| **CrowdStrike** | [CrowdStrike Falcon API](https://falcon.crowdstrike.com/documentation/85/detection-and-prevention-policies-apis) |
| **Palo Alto XSOAR** | [XSOAR Incidents API](https://xsoar.pan.dev/docs/reference/api/incidents) |

### Monitoring the Integration

```sql
-- Check alert execution history
SELECT *
FROM TABLE(INFORMATION_SCHEMA.ALERT_HISTORY(
    SCHEDULED_TIME_RANGE_START => DATEADD('hour', -24, CURRENT_TIMESTAMP())
))
WHERE NAME = 'DETECT_FAILED_LOGINS'
ORDER BY SCHEDULED_TIME DESC;

-- Check task execution history
SELECT *
FROM TABLE(INFORMATION_SCHEMA.TASK_HISTORY(
    SCHEDULED_TIME_RANGE_START => DATEADD('hour', -24, CURRENT_TIMESTAMP())
))
WHERE NAME = 'SEND_TO_SIEM_TASK'
ORDER BY SCHEDULED_TIME DESC;

-- Review sent events and SIEM responses
SELECT 
    EVENT_TIMESTAMP,
    USER_NAME,
    CLIENT_IP,
    ERROR_MESSAGE,
    SENT,
    SENT_TIME,
    PARSE_JSON(SIEM_RESPONSE):status_code::INT as siem_status,
    PARSE_JSON(SIEM_RESPONSE):incident_id::VARCHAR as siem_incident_id
FROM LOGIN_EVENTS
ORDER BY EVENT_TIMESTAMP DESC
LIMIT 50;
```

### Extending the Pattern

This pattern can be extended beyond failed logins:

| Detection | What to Monitor | Alert Condition |
|-----------|-----------------|-----------------|
| **Network Policy Changes** | `QUERY_HISTORY` | `QUERY_TEXT ILIKE '%NETWORK POLICY%'` |
| **Privilege Escalation** | `GRANTS_TO_USERS` | New ACCOUNTADMIN grants |
| **Data Exfiltration** | `COPY_HISTORY` | Large row counts to external stages |
| **Service Account Activity** | `QUERY_HISTORY` | Queries from specific service users |
| **After-Hours Access** | `LOGIN_HISTORY` | Logins outside business hours |
| **Container Events** | Event tables | SPCS security events |

**Reference:** Based on [How to Let Snowflake Raise Security Incidents in Your SIEM or XDR Automatically](https://kevinkeller.org/posts/snowflake-siem-xdr-automated-security-incidents/) by Kevin Keller.

---

## Splunk DB Connect to Snowflake

Splunk DB Connect enables bidirectional integration: query Snowflake data from Splunk searches, or enrich Splunk events with Snowflake lookups. This is ideal for SOC teams using Splunk as their primary SIEM while storing security analytics in Snowflake.

### Splunk Cloud Quick Start

Copy these values into **Configuration → Settings → General**:

| Setting | Value |
|---------|-------|
| **JRE Installation Path (JAVA_HOME)** | `/usr/lib/jvm/java-17-openjdk-amd64` |
| **Task Server Port** | `9998` |
| **Task Server JVM Options** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED` |
| **Query Server JVM Options** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED` |

> **Note:** For Splunk On-Premise, values may differ based on your JVM installation path and network configuration.

### Snowflake JDBC Driver Setup

1. Download the Snowflake JDBC driver from [Snowflake Maven Repository](https://repo1.maven.org/maven2/net/snowflake/snowflake-jdbc/)
2. Upload to Splunk DB Connect: **Configuration → Settings → Drivers → New Driver**
3. Configure driver settings:

| Field | Value |
|-------|-------|
| **Driver Name** | `Snowflake` |
| **Class Name** | `net.snowflake.client.jdbc.SnowflakeDriver` |
| **Connection URL Format** | `jdbc:snowflake://<account>.snowflakecomputing.com/?warehouse=<warehouse>&db=<database>&schema=<schema>` |

### Create Snowflake Identity

Create a connection identity in **Configuration → Databases → Identities → New Identity**:

| Field | Value |
|-------|-------|
| **Identity Name** | `snowflake_security` |
| **Username** | Your Snowflake username |
| **Password** | Your Snowflake password (or use key-pair auth) |

### Create Snowflake Connection

In **Configuration → Databases → Connections → New Connection**:

| Field | Value |
|-------|-------|
| **Connection Name** | `snowflake_security_logs` |
| **Identity** | `snowflake_security` (from above) |
| **Connection Type** | `Snowflake` |
| **JDBC URL Format** | `jdbc:snowflake://<ACCOUNT>.snowflakecomputing.com/?warehouse=SECURITY_WH&db=SECURITY_DB&schema=SECURITY_OPS` |
| **Timezone** | `UTC` |
| **Enable SSL** | `Yes` |

### Example: Query Snowflake Detection Results from Splunk

```spl
| dbxquery 
    connection="snowflake_security_logs"
    query="SELECT detection_name, severity, entity_id, description, created_at 
           FROM security_ops.alerts 
           WHERE created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
             AND severity IN ('CRITICAL', 'HIGH')
           ORDER BY created_at DESC"
| table detection_name severity entity_id description created_at
```

### Example: Enrich Splunk Events with Snowflake Lookups

```spl
index=security sourcetype=firewall
| lookup snowflake_threat_actors actor_ip AS src_ip OUTPUT threat_score, threat_actor_name, first_seen
| where threat_score > 0.7
| table _time src_ip dest_ip threat_actor_name threat_score
```

To create the lookup, configure a **DB Input** in Splunk that periodically syncs the `threat_indicators` table.

### Scheduled Input: Sync Snowflake Alerts to Splunk

Create a DB Input to continuously ingest Snowflake alerts into Splunk:

1. **Configuration → Databases → Inputs → New Input**
2. Configure:

| Field | Value |
|-------|-------|
| **Input Name** | `snowflake_alerts` |
| **Connection** | `snowflake_security_logs` |
| **Query** | See below |
| **Execution Frequency** | `*/5 * * * *` (every 5 minutes) |
| **Source** | `snowflake:security:alerts` |
| **Sourcetype** | `snowflake:alerts` |

**Rising Column Query** (tracks incremental ingestion):
```sql
SELECT 
    detection_id,
    detection_name,
    severity,
    entity_type,
    entity_id,
    description,
    evidence,
    mitre_technique,
    created_at
FROM security_ops.alerts
WHERE created_at > ?
ORDER BY created_at ASC
```

### Key-Pair Authentication (Recommended)

For production deployments, use key-pair authentication instead of passwords:

```sql
-- In Snowflake: Create user with RSA key
ALTER USER splunk_service_account SET RSA_PUBLIC_KEY='MIIBIjANBg...';
```

JDBC URL with key-pair:
```
jdbc:snowflake://<account>.snowflakecomputing.com/?warehouse=SECURITY_WH&db=SECURITY_DB&schema=SECURITY_OPS&authenticator=SNOWFLAKE_JWT&private_key_file=/path/to/rsa_key.p8
```

### Troubleshooting DB Connect

| Issue | Solution |
|-------|----------|
| **Connection timeout** | Check Snowflake network policy allows Splunk Cloud IPs |
| **SSL handshake failure** | Ensure `Enable SSL = Yes` and correct account URL |
| **Query timeout** | Increase `Query Timeout` in connection settings; optimize Snowflake query |
| **JVM errors** | Verify `--add-opens` flags in JVM Options |
| **Driver not found** | Confirm JDBC JAR uploaded and Class Name correct |

---

## Ingesting Incident Management Logs

### Why Ingest Jira/ServiceNow Data

Ingesting incident ticket history enables:
- **Trend analysis** — Which systems generate the most incidents?
- **Response metrics** — MTTD, MTTR by incident type
- **Pattern recognition** — Recurring vulnerabilities across infrastructure
- **Resource planning** — Where to invest in security controls

### Jira Incident Ingestion

```sql
-- Store Jira incidents for analysis
CREATE TABLE security_ops.jira_incidents (
    ingestion_time TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    issue_key VARCHAR,
    project VARCHAR,
    summary VARCHAR,
    description VARCHAR,
    status VARCHAR,
    priority VARCHAR,
    created TIMESTAMP_LTZ,
    updated TIMESTAMP_LTZ,
    resolved TIMESTAMP_LTZ,
    assignee VARCHAR,
    reporter VARCHAR,
    labels ARRAY,
    components ARRAY,
    custom_fields VARIANT,
    changelog VARIANT  -- Full history of changes
);

-- Analyze incident trends
SELECT 
    DATE_TRUNC('week', created) as week,
    COUNT(*) as incident_count,
    AVG(DATEDIFF('hour', created, resolved)) as avg_resolution_hours,
    COUNT_IF(priority = 'Critical') as critical_count
FROM security_ops.jira_incidents
WHERE created >= DATEADD('month', -6, CURRENT_TIMESTAMP())
GROUP BY 1
ORDER BY 1;

-- Find most vulnerable systems
SELECT 
    component,
    COUNT(*) as incident_count,
    COUNT_IF(priority IN ('Critical', 'High')) as high_severity_count
FROM security_ops.jira_incidents,
     LATERAL FLATTEN(input => components) c
WHERE created >= DATEADD('year', -1, CURRENT_TIMESTAMP())
GROUP BY 1
ORDER BY 2 DESC
LIMIT 20;
```

---

## Security Dashboards with Streamlit

Use the **developing-with-streamlit** skill for building SOC dashboards. Key components:

### Essential SOC Dashboard Panels

| Panel | Metrics | Refresh Rate |
|-------|---------|--------------|
| **Alert Funnel** | New → Triaged → Escalated → Resolved | Real-time |
| **Severity Distribution** | Critical/High/Medium/Low counts | 5 min |
| **MTTD/MTTR Trends** | Mean time to detect/respond over time | Hourly |
| **Top Threat Types** | Alert categories ranked by volume | 15 min |
| **Geographic Map** | Attack sources by country/region | 15 min |
| **User Risk Score** | Top risky users by behavior score | 30 min |
| **Failed Login Heatmap** | Time-of-day patterns | 5 min |
| **Active Investigations** | Open incidents with status | Real-time |

### Streamlit Dashboard Pattern

```python
import streamlit as st
from snowflake.snowpark.context import get_active_session

session = get_active_session()

st.set_page_config(layout="wide", page_title="Security Operations Center")

# Header metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    critical = session.sql("""
        SELECT COUNT(*) FROM security_ops.alerts 
        WHERE severity = 'CRITICAL' AND status = 'OPEN'
    """).collect()[0][0]
    st.metric("Critical Alerts", critical, delta_color="inverse")

with col2:
    # MTTR calculation
    mttr = session.sql("""
        SELECT AVG(DATEDIFF('minute', created_at, resolved_at))
        FROM security_ops.alerts 
        WHERE resolved_at IS NOT NULL 
          AND created_at >= DATEADD('day', -7, CURRENT_TIMESTAMP())
    """).collect()[0][0]
    st.metric("MTTR (min)", f"{mttr:.0f}" if mttr else "N/A")

# Alert trend chart
st.subheader("Alert Trend (7 Days)")
trend_data = session.sql("""
    SELECT DATE_TRUNC('hour', created_at) as hour, 
           severity,
           COUNT(*) as count
    FROM security_ops.alerts
    WHERE created_at >= DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY 1, 2
""").to_pandas()
st.area_chart(trend_data.pivot(index='HOUR', columns='SEVERITY', values='COUNT'))

# Real-time alert feed
st.subheader("Latest Alerts")
alerts = session.sql("""
    SELECT created_at, severity, detection_name, entity_id, status
    FROM security_ops.alerts
    ORDER BY created_at DESC
    LIMIT 50
""").to_pandas()
st.dataframe(alerts, use_container_width=True)
```

**Invoke developing-with-streamlit skill** for complete dashboard implementation guidance.

---

## OpenTelemetry Observability Data Lake

Snowflake can serve as a unified observability data lake for logs, traces, and metrics using the OpenTelemetry (OTel) ecosystem. This enables centralized SIEM & APM capabilities with unlimited scalability.

### Benefits of OpenTelemetry + Snowflake

| Benefit | Description |
|---------|-------------|
| **Vendor-agnostic** | OTel collectors work with any source and destination |
| **Unlimited scale** | Snowflake handles petabyte-scale log storage |
| **Hot storage** | All data queryable instantly, no rehydration needed |
| **Open format** | Write to Iceberg tables for multi-engine access |
| **Cost-effective** | Pay for storage + compute, no per-GB ingestion fees |
| **Unified platform** | Combine security logs, APM traces, and metrics in one place |

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LOG SOURCES                                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │CloudTrail│ │ Okta   │ │ K8s    │ │ Custom │ │ Syslog │        │
│  │ VPC Flow│ │ EntraID │ │ Pods   │ │ Apps   │ │ Servers│        │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘       │
│       │          │          │          │          │               │
│       └──────────┴──────────┴──────────┴──────────┘               │
│                             │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │           OpenTelemetry Collector                             │  │
│  │  • Receives: OTLP/gRPC, OTLP/HTTP, Jaeger, Prometheus        │  │
│  │  • Processes: Batch, filter, transform, enrich               │  │
│  │  • Exports: OTLP/HTTP to Snowflake receiver                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SNOWFLAKE CONTAINER SERVICES                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │           Snowflake OpenTelemetry Receiver                    │  │
│  │  • Receives OTLP/HTTP on port 4318                           │  │
│  │  • Writes to raw tables: logs, metrics, traces               │  │
│  │  • OAuth authentication for security                          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                               │                                     │
│                               ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │           Raw Tables (VARIANT columns)                        │  │
│  │  LOGS: timestamp, log_level, message, attributes              │  │
│  │  METRICS: timestamp, metric_name, value, attributes           │  │
│  │  TRACES: trace_id, span_id, name, start/end_time, attributes  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                               │                                     │
│                               ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │           ECS Schema Tables (via Streams + Tasks)             │  │
│  │  • Elastic Common Schema format for standardization           │  │
│  │  • Can be Iceberg tables for open data lake                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Quick Setup

#### 1. Create Raw Tables

```sql
CREATE DATABASE otel;
CREATE SCHEMA otelschema;

CREATE OR REPLACE TABLE metrics (
    timestamp TIMESTAMP_NTZ,
    metric_name STRING,
    value DOUBLE,
    attributes VARCHAR
);

CREATE OR REPLACE TABLE logs (
    timestamp TIMESTAMP_NTZ,
    log_level STRING,
    message STRING,
    attributes VARCHAR
);

CREATE OR REPLACE TABLE traces (
    trace_id STRING,
    span_id STRING,
    name STRING,
    start_time TIMESTAMP_NTZ,
    end_time TIMESTAMP_NTZ,
    attributes VARCHAR
);
```

#### 2. Deploy OTel Receiver in SPCS

```sql
-- Create compute pool
CREATE COMPUTE POOL IF NOT EXISTS otel_compute_pool
    MIN_NODES = 1
    MAX_NODES = 1
    INSTANCE_FAMILY = CPU_X64_S
    AUTO_RESUME = TRUE;

-- Create service with public endpoint
CREATE SERVICE otel_service
    IN COMPUTE POOL otel_compute_pool
    MIN_INSTANCES = 1
    MAX_INSTANCES = 1
    FROM SPECIFICATION
    $$
    spec:
      containers:
      - name: "otel"
        image: "/otel/otelschema/oteltestimages/otel-image:latest"
        env:
          SNOWFLAKE_DATABASE: "otel"
          SNOWFLAKE_WAREHOUSE: "otelwh"
          SNOWFLAKE_SCHEMA: "otelschema"
          SPCS: "True"
      endpoints:
      - name: otelhttp
        port: 4318
        public: true
    $$;

-- Get the endpoint URL
SHOW ENDPOINTS IN SERVICE otel_service;
```

#### 3. Configure OTel Collector

```yaml
# collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 10s
    send_batch_size: 1000

exporters:
  otlphttp:
    endpoint: "https://<your-spcs-endpoint>.snowflakecomputing.app"
    tls:
      insecure: false
    headers:
      Authorization: "Bearer <snowflake-oauth-token>"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
```

#### 4. Transform to ECS Schema

```sql
-- Create streams on source tables
CREATE OR REPLACE STREAM logs_stream ON TABLE logs APPEND_ONLY = TRUE;
CREATE OR REPLACE STREAM metrics_stream ON TABLE metrics APPEND_ONLY = TRUE;
CREATE OR REPLACE STREAM traces_stream ON TABLE traces APPEND_ONLY = TRUE;

-- Create ECS schema tables
CREATE SCHEMA IF NOT EXISTS ecs_schema;

CREATE TABLE IF NOT EXISTS ecs_schema.logs (
    "@timestamp" TIMESTAMP_NTZ,
    "message" STRING,
    "log.level" STRING,
    "attributes" VARIANT
);

CREATE TABLE IF NOT EXISTS ecs_schema.metrics (
    "@timestamp" TIMESTAMP_NTZ,
    "metricset.name" STRING,
    "metric.value" FLOAT,
    "attributes" VARIANT
);

CREATE TABLE IF NOT EXISTS ecs_schema.traces (
    "trace.id" STRING,
    "span.id" STRING,
    "span.name" STRING,
    "span.start" TIMESTAMP_NTZ,
    "span.end" TIMESTAMP_NTZ,
    "span.duration" FLOAT,
    "attributes" VARIANT
);

-- Task to transform data every minute
CREATE OR REPLACE TASK ecs_transform_task
    WAREHOUSE = otelwh
    SCHEDULE = '1 MINUTE'
AS
    CALL ecs_transform_incremental();

ALTER TASK ecs_transform_task RESUME;
```

#### 5. Convert to Iceberg Tables (Optional)

```sql
-- For open data lake access from any query engine
CREATE OR REPLACE ICEBERG TABLE ecs_schema.logs (
    "@timestamp" TIMESTAMP_NTZ,
    "message" VARCHAR,
    "log.level" VARCHAR,
    "attributes" VARIANT
)
CATALOG = 'SNOWFLAKE'
EXTERNAL_VOLUME = 'my_ext_vol'
BASE_LOCATION = 'observability/logs';
```

**Reference:** [Ingest OpenTelemetry Logs, Traces and Metrics Directly into Snowflake](https://kevinkeller.org/posts/opentelemetry-snowflake-observability-datalake/) by Kevin Keller.

---

## Snowflake Openflow for Log Ingestion

Snowflake Openflow (based on Apache NiFi) provides a native **ListenOTLP** processor for receiving OpenTelemetry data directly.

### ListenOTLP Processor

| Property | Description |
|----------|-------------|
| **Address** | IP address to listen on (default: all addresses) |
| **Port** | TCP port for OTLP requests (default: 4318) |
| **Batch Size** | Max OTLP resource elements per FlowFile |
| **Queue Capacity** | Max elements queued before backpressure |
| **SSL Context Service** | Enable TLS for HTTPS |
| **Worker Threads** | Threads for decoding requests |

**Output Attributes:**
- `mime.type`: `application/json`
- `resource.type`: `LOGS`, `METRICS`, or `TRACES`
- `resource.count`: Number of resource elements

### Openflow Pipeline for OTel → Snowflake

```
ListenOTLP (port 4318)
    │
    ├─── [resource.type = LOGS] ──→ PutSnowflakeTable (logs table)
    │
    ├─── [resource.type = METRICS] ──→ PutSnowflakeTable (metrics table)
    │
    └─── [resource.type = TRACES] ──→ PutSnowflakeTable (traces table)
```

Use the **openflow** skill for detailed Openflow pipeline configuration.

---

## Alternative Log Ingestion Methods

### Fluentd → Snowflake via S3 + Snowpipe

Fluentd is an open-source log collector that can route logs to Snowflake via S3 external stages.

**Architecture:**
```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Log Source  │ →  │   Fluentd    │ →  │  S3 Bucket   │ →  │  Snowpipe    │
│  (Apache,    │    │  (td-agent)  │    │  (gzip files)│    │  (auto-ingest)│
│   syslog)    │    │              │    │              │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

**Fluentd Configuration:**
```xml
<source>
  @type tail
  path /var/log/httpd/access_log
  pos_file /var/log/td-agent/apache2.access_log.pos
  <parse>
    @type apache2
  </parse>
  tag s3.apache.access
</source>

<match s3.*.*>
  @type s3
  aws_key_id [AWS_ACCESS_KEY]
  aws_sec_key [AWS_SECRET_KEY]
  s3_bucket [BUCKET_NAME]
  path logs/
  <buffer>
    @type file
    path /var/log/td-agent/s3
    timekey 60
    timekey_wait 1m
    chunk_limit_size 256m
  </buffer>
  time_slice_format %Y%m%d%H
</match>
```

**Snowflake Setup:**
```sql
-- Storage integration
CREATE STORAGE INTEGRATION s3_int_fluentd
    TYPE = EXTERNAL_STAGE
    STORAGE_PROVIDER = S3
    ENABLED = TRUE
    STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::xxx:role/SnowflakeRole'
    STORAGE_ALLOWED_LOCATIONS = ('s3://bucket/logs/');

-- External stage
CREATE STAGE fluentd_stage
    URL = 's3://bucket/logs/'
    STORAGE_INTEGRATION = s3_int_fluentd;

-- File format (Fluentd uses tab delimiter)
CREATE FILE FORMAT fluentd_format
    TYPE = CSV
    FIELD_DELIMITER = '\t'
    COMPRESSION = GZIP;

-- Target table
CREATE TABLE logs (
    time DATETIME,
    tag STRING,
    record VARIANT
);

-- Snowpipe for auto-ingestion
CREATE PIPE fluentd_pipe AUTO_INGEST = TRUE AS
    COPY INTO logs
    FROM @fluentd_stage
    FILE_FORMAT = fluentd_format;
```

**Reference:** [Snowflake Fluentd Quickstart](https://www.snowflake.com/en/developers/guides/integrating-fluentd-with-snowflake/)

### Vector.dev → Snowflake

[Vector](https://vector.dev/) is a high-performance observability data pipeline. Route to Snowflake via:

1. **S3 sink** → Snowpipe (recommended for production)
2. **HTTP sink** → Custom Snowflake receiver
3. **OpenTelemetry sink** → OTel Collector → Snowflake

**Vector Configuration (S3 → Snowpipe):**
```toml
[sources.logs]
type = "file"
include = ["/var/log/**/*.log"]

[transforms.parse]
type = "remap"
inputs = ["logs"]
source = '''
. = parse_json!(.message)
'''

[sinks.s3]
type = "aws_s3"
inputs = ["parse"]
bucket = "your-snowflake-stage-bucket"
key_prefix = "logs/"
compression = "gzip"
encoding.codec = "json"
```

### Datadog Observability Pipelines

Datadog Observability Pipelines can route logs to Snowflake while maintaining Datadog monitoring:

**Capabilities:**
- **Dual ship** — Send logs to both Datadog and Snowflake
- **Filter** — Reduce volume before storage
- **Enrich** — Add metadata from reference tables
- **Redact** — Remove PII before routing
- **Transform** — Convert to OCSF or ECS format

**Use Case:** Keep recent data (7 days) in Datadog for real-time alerting, archive all data to Snowflake for long-term analysis and compliance.

---

## Log Ingestion Comparison

| Method | Latency | Complexity | Best For |
|--------|---------|------------|----------|
| **OpenTelemetry + SPCS** | Real-time | Medium | Modern cloud-native apps |
| **Openflow ListenOTLP** | Real-time | Low | Native Snowflake solution |
| **Fluentd + Snowpipe** | Minutes | Medium | Traditional infrastructure |
| **Vector + S3** | Minutes | Low | High-volume streaming |
| **Datadog OP** | Real-time | Low | Existing Datadog users |

---

## Dynamic Tables for Security Monitoring

> **Skill Integration:** Use the `dynamic-tables` skill for detailed guidance on creating, monitoring, troubleshooting, and optimizing Dynamic Tables.

Dynamic Tables provide continuous, declarative data transformation ideal for security monitoring pipelines. Unlike Tasks that require procedural scheduling, DTs automatically refresh based on source data changes with minimal configuration.

### Why Dynamic Tables for Security

| Benefit | Security Application |
|---------|---------------------|
| **Declarative refresh** | Define detection logic once; Snowflake manages scheduling |
| **Incremental processing** | Only process new events, reducing compute costs |
| **Automatic dependency management** | Chain DTs for multi-stage threat detection |
| **TARGET_LAG control** | Balance freshness vs cost per detection type |
| **DOWNSTREAM refresh mode** | Efficient for intermediate aggregation steps |

### Security Detection Pipeline with Dynamic Tables

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                   DYNAMIC TABLE DETECTION PIPELINE                            │
│                                                                               │
│  ┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐           │
│  │ RAW_LOGS    │────▶│ DT_ENRICHED_LOGS │────▶│ DT_SUSPICIOUS    │           │
│  │ (Snowpipe)  │     │ (DOWNSTREAM)     │     │ (DOWNSTREAM)     │           │
│  └─────────────┘     │ - Add geo IP     │     │ - Filter threats │           │
│                      │ - Parse fields   │     │ - Score risk     │           │
│                      └─────────────────┘     └────────┬─────────┘           │
│                                                        │                      │
│        ┌──────────────────────────────────────────────┼─────────────────┐    │
│        │                                              │                  │    │
│        ▼                                              ▼                  ▼    │
│  ┌──────────────────┐   ┌───────────────────┐   ┌──────────────────┐        │
│  │ DT_BRUTE_FORCE   │   │ DT_DATA_EXFIL     │   │ DT_PRIV_ESCALATE │        │
│  │ (5 min lag)      │   │ (5 min lag)       │   │ (5 min lag)      │        │
│  │ - Failed logins  │   │ - Large transfers │   │ - Role changes   │        │
│  │ - IP clustering  │   │ - Unusual queries │   │ - Grant patterns │        │
│  └──────────────────┘   └───────────────────┘   └──────────────────┘        │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Example: Failed Login Detection with Dynamic Tables

```sql
-- Stage 1: Enrich raw login events (DOWNSTREAM - refreshes when source changes)
CREATE OR REPLACE DYNAMIC TABLE security_ops.dt_enriched_logins
  TARGET_LAG = DOWNSTREAM
  WAREHOUSE = security_warehouse
  REFRESH_MODE = INCREMENTAL
AS
SELECT
    l.event_timestamp,
    l.user_name,
    l.client_ip,
    l.error_code,
    l.error_message,
    l.first_authentication_factor,
    l.second_authentication_factor,
    l.reported_client_type,
    -- Enrich with geo IP (assuming lookup table exists)
    g.country,
    g.city,
    g.is_vpn,
    g.is_tor,
    -- Add time-based features
    EXTRACT(HOUR FROM event_timestamp) AS login_hour,
    DAYOFWEEK(event_timestamp) AS login_dow,
    -- Flag suspicious patterns
    CASE 
        WHEN error_code = 'INCORRECT_PASSWORD' THEN TRUE
        WHEN error_code LIKE '%INVALID%' THEN TRUE
        ELSE FALSE
    END AS is_failed_attempt
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY l
LEFT JOIN security_ops.geo_ip_lookup g ON l.client_ip = g.ip_address
WHERE l.event_timestamp >= DATEADD('day', -30, CURRENT_TIMESTAMP());

-- Stage 2: Aggregate by user/IP for brute force detection (DOWNSTREAM)
CREATE OR REPLACE DYNAMIC TABLE security_ops.dt_login_aggregates
  TARGET_LAG = DOWNSTREAM
  WAREHOUSE = security_warehouse
  REFRESH_MODE = INCREMENTAL
AS
SELECT
    DATE_TRUNC('minute', event_timestamp) AS minute_bucket,
    user_name,
    client_ip,
    country,
    is_vpn,
    is_tor,
    COUNT(*) AS total_attempts,
    SUM(CASE WHEN is_failed_attempt THEN 1 ELSE 0 END) AS failed_attempts,
    COUNT(DISTINCT user_name) AS distinct_users_from_ip,
    ARRAY_AGG(DISTINCT error_code) AS error_codes
FROM security_ops.dt_enriched_logins
GROUP BY 1, 2, 3, 4, 5, 6;

-- Stage 3: Final brute force detection (5-minute TARGET_LAG for alerting)
CREATE OR REPLACE DYNAMIC TABLE security_ops.dt_brute_force_alerts
  TARGET_LAG = '5 minutes'
  WAREHOUSE = security_warehouse
  REFRESH_MODE = INCREMENTAL
AS
SELECT
    minute_bucket AS detection_time,
    'BRUTE_FORCE' AS detection_type,
    user_name,
    client_ip,
    country,
    failed_attempts,
    total_attempts,
    CASE
        WHEN failed_attempts >= 20 THEN 'CRITICAL'
        WHEN failed_attempts >= 10 THEN 'HIGH'
        WHEN failed_attempts >= 5 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS severity,
    ROUND(failed_attempts::FLOAT / NULLIF(total_attempts, 0), 2) AS failure_rate,
    CASE
        WHEN is_tor THEN 1.5
        WHEN is_vpn THEN 1.2
        ELSE 1.0
    END AS risk_multiplier,
    OBJECT_CONSTRUCT(
        'failed_attempts', failed_attempts,
        'total_attempts', total_attempts,
        'source_country', country,
        'is_anonymized', (is_vpn OR is_tor),
        'error_codes', error_codes
    ) AS evidence
FROM security_ops.dt_login_aggregates
WHERE failed_attempts >= 5
  AND minute_bucket >= DATEADD('hour', -24, CURRENT_TIMESTAMP());
```

### Alert on Dynamic Table Results

```sql
-- Create alert based on Dynamic Table results
CREATE OR REPLACE ALERT security_ops.alert_brute_force
  WAREHOUSE = security_warehouse
  SCHEDULE = '5 MINUTE'
  IF (EXISTS (
    SELECT 1 FROM security_ops.dt_brute_force_alerts
    WHERE severity IN ('CRITICAL', 'HIGH')
      AND detection_time >= DATEADD('minute', -10, CURRENT_TIMESTAMP())
  ))
  THEN
    CALL security_ops.send_security_alert(
      'Brute Force Attack Detected',
      (SELECT ARRAY_AGG(OBJECT_CONSTRUCT(*)) FROM security_ops.dt_brute_force_alerts
       WHERE severity IN ('CRITICAL', 'HIGH')
         AND detection_time >= DATEADD('minute', -10, CURRENT_TIMESTAMP()))
    );

ALTER ALERT security_ops.alert_brute_force RESUME;
```

### Dynamic Tables vs Tasks for Detection

| Criteria | Dynamic Tables | Tasks + Stored Procedures |
|----------|----------------|---------------------------|
| **Best for** | Declarative transformations, aggregations | Procedural logic, conditional flows |
| **Refresh mode** | Automatic incremental/full | Explicit scheduling |
| **State management** | Built-in | Manual (insert/update tracking) |
| **Multi-target output** | One DT = one target | Can write to multiple tables |
| **Side effects** | Cannot call external APIs | Can call UDFs with external access |
| **Minimum latency** | 1 minute | Sub-minute possible |

**Decision:** Use Dynamic Tables for detection aggregations; use Tasks for incident creation with external API calls.

---

## dbt for Security Data Transformation

> **Skill Integration:** Use the `dbt-projects-on-snowflake` skill for detailed dbt project structure, testing, and deployment guidance.

dbt (data build tool) enables version-controlled, tested, documented security data pipelines. Apply software engineering practices to your security analytics.

### Security dbt Project Structure

```
security_dbt/
├── dbt_project.yml
├── packages.yml                    # dbt_utils, dbt_expectations
├── profiles.yml                    # Snowflake connection (gitignored)
├── models/
│   ├── staging/                    # 1:1 with raw tables
│   │   ├── stg_login_history.sql
│   │   ├── stg_query_history.sql
│   │   ├── stg_access_history.sql
│   │   ├── stg_cloudtrail.sql
│   │   └── _stg_schema.yml
│   ├── intermediate/               # Business logic transformations
│   │   ├── int_failed_logins.sql
│   │   ├── int_suspicious_queries.sql
│   │   ├── int_privilege_changes.sql
│   │   └── _int_schema.yml
│   ├── marts/
│   │   ├── security/               # Security-specific marts
│   │   │   ├── fct_security_events.sql
│   │   │   ├── fct_incidents.sql
│   │   │   ├── dim_users.sql
│   │   │   ├── dim_threat_actors.sql
│   │   │   └── _security_schema.yml
│   │   └── compliance/             # Compliance reporting
│   │       ├── rpt_access_reviews.sql
│   │       ├── rpt_privileged_access.sql
│   │       └── _compliance_schema.yml
│   └── detections/                 # Detection-as-Code models
│       ├── det_brute_force.sql
│       ├── det_data_exfiltration.sql
│       ├── det_privilege_escalation.sql
│       └── _detections_schema.yml
├── macros/
│   ├── security_macros.sql         # Reusable security logic
│   ├── threat_scoring.sql          # Risk scoring functions
│   └── mitre_mapping.sql           # MITRE ATT&CK mapping
├── tests/
│   ├── generic/
│   │   └── test_no_pii_in_logs.sql
│   └── singular/
│       └── test_detection_coverage.sql
├── seeds/
│   ├── threat_indicators.csv       # Known IOCs
│   ├── mitre_techniques.csv        # MITRE ATT&CK mapping
│   └── authorized_activities.csv   # Whitelist for false positives
└── snapshots/
    └── snap_user_roles.sql         # Track role changes over time
```

### Example dbt Models for Security

#### Staging Model: `stg_login_history.sql`

```sql
-- models/staging/stg_login_history.sql
{{ config(
    materialized='incremental',
    unique_key='event_id',
    cluster_by=['event_timestamp::DATE']
) }}

WITH source AS (
    SELECT * FROM {{ source('snowflake_account_usage', 'login_history') }}
    {% if is_incremental() %}
    WHERE event_timestamp > (SELECT MAX(event_timestamp) FROM {{ this }})
    {% endif %}
),

renamed AS (
    SELECT
        event_id,
        event_timestamp,
        event_type,
        user_name,
        client_ip,
        reported_client_type,
        reported_client_version,
        first_authentication_factor,
        second_authentication_factor,
        is_success,
        error_code,
        error_message,
        related_event_id,
        connection
    FROM source
)

SELECT * FROM renamed
```

#### Detection Model: `det_brute_force.sql`

```sql
-- models/detections/det_brute_force.sql
{{ config(
    materialized='incremental',
    unique_key='detection_id',
    tags=['detection', 'identity', 'high_priority']
) }}

WITH failed_logins AS (
    SELECT
        DATE_TRUNC('minute', event_timestamp) AS minute_bucket,
        user_name,
        client_ip,
        COUNT(*) AS failed_count
    FROM {{ ref('stg_login_history') }}
    WHERE NOT is_success
      AND error_code = 'INCORRECT_PASSWORD'
      {% if is_incremental() %}
      AND event_timestamp > (SELECT COALESCE(MAX(detected_at), '1900-01-01') FROM {{ this }})
      {% endif %}
    GROUP BY 1, 2, 3
    HAVING COUNT(*) >= {{ var('brute_force_threshold', 5) }}
),

detections AS (
    SELECT
        {{ dbt_utils.generate_surrogate_key(['minute_bucket', 'user_name', 'client_ip']) }} AS detection_id,
        'BRUTE_FORCE_ATTEMPT' AS detection_name,
        minute_bucket AS detected_at,
        user_name AS entity_id,
        'user' AS entity_type,
        client_ip AS source_ip,
        failed_count,
        {{ threat_score('brute_force', 'failed_count') }} AS threat_score,
        CASE
            WHEN failed_count >= 20 THEN 'CRITICAL'
            WHEN failed_count >= 10 THEN 'HIGH'
            ELSE 'MEDIUM'
        END AS severity,
        'T1110' AS mitre_technique,
        'Brute Force: Password Guessing' AS mitre_technique_name
    FROM failed_logins
)

SELECT * FROM detections
```

#### Security Macro: `threat_scoring.sql`

```sql
-- macros/threat_scoring.sql
{% macro threat_score(detection_type, metric_column) %}
    CASE '{{ detection_type }}'
        WHEN 'brute_force' THEN 
            LEAST(1.0, {{ metric_column }}::FLOAT / 50.0)
        WHEN 'data_exfil' THEN
            LEAST(1.0, {{ metric_column }}::FLOAT / 1000000000.0)  -- bytes
        WHEN 'privilege_escalation' THEN
            0.8  -- High base score
        ELSE 0.5
    END
{% endmacro %}

{% macro mitre_tactic(technique_id) %}
    CASE LEFT('{{ technique_id }}', 5)
        WHEN 'T1110' THEN 'Credential Access'
        WHEN 'T1078' THEN 'Defense Evasion'
        WHEN 'T1048' THEN 'Exfiltration'
        WHEN 'T1098' THEN 'Persistence'
        ELSE 'Unknown'
    END
{% endmacro %}
```

### dbt Tests for Security Data Quality

```yaml
# models/detections/_detections_schema.yml
version: 2

models:
  - name: det_brute_force
    description: "Brute force login attempt detection"
    config:
      tags: ['detection', 'identity']
    columns:
      - name: detection_id
        description: "Unique detection identifier"
        tests:
          - unique
          - not_null
      - name: severity
        tests:
          - accepted_values:
              values: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
      - name: threat_score
        tests:
          - dbt_expectations.expect_column_values_to_be_between:
              min_value: 0.0
              max_value: 1.0
      - name: mitre_technique
        tests:
          - relationships:
              to: ref('mitre_techniques')
              field: technique_id
```

### dbt Snapshots for Audit Trail

```sql
-- snapshots/snap_user_roles.sql
{% snapshot snap_user_roles %}

{{
    config(
        target_database='security_db',
        target_schema='snapshots',
        unique_key='user_role_key',
        strategy='check',
        check_cols=['granted_roles', 'default_role', 'owner']
    )
}}

SELECT
    {{ dbt_utils.generate_surrogate_key(['user_name']) }} AS user_role_key,
    user_name,
    granted_roles,
    default_role,
    owner,
    created_on,
    has_password,
    has_mfa
FROM {{ source('snowflake_account_usage', 'users') }}

{% endsnapshot %}
```

### CI/CD for Security dbt

```yaml
# .github/workflows/security_dbt.yml
name: Security dbt CI/CD

on:
  push:
    branches: [main]
    paths:
      - 'security_dbt/**'
  pull_request:
    branches: [main]
    paths:
      - 'security_dbt/**'

jobs:
  dbt-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install dbt
        run: pip install dbt-snowflake
        
      - name: Run dbt deps
        run: dbt deps
        working-directory: security_dbt
        
      - name: Run dbt compile
        run: dbt compile --target ci
        working-directory: security_dbt
        env:
          SNOWFLAKE_ACCOUNT: ${{ secrets.SNOWFLAKE_ACCOUNT }}
          SNOWFLAKE_USER: ${{ secrets.SNOWFLAKE_USER }}
          SNOWFLAKE_PASSWORD: ${{ secrets.SNOWFLAKE_PASSWORD }}
          
      - name: Run dbt test
        run: dbt test --target ci
        working-directory: security_dbt

  dbt-deploy:
    needs: dbt-test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Run dbt run
        run: dbt run --target prod
        working-directory: security_dbt
```

### Combining dbt with Dynamic Tables

Use dbt to develop and test transformation logic, then deploy as Dynamic Tables for production:

```sql
-- models/marts/security/fct_security_events.sql
{{ config(
    materialized='dynamic_table',
    target_lag='5 minutes',
    snowflake_warehouse='security_warehouse'
) }}

SELECT
    {{ dbt_utils.generate_surrogate_key(['source_system', 'event_id']) }} AS event_key,
    event_timestamp,
    source_system,
    event_type,
    user_id,
    entity_type,
    entity_id,
    action,
    outcome,
    risk_score,
    {{ mitre_tactic('mitre_technique') }} AS mitre_tactic
FROM {{ ref('int_unified_events') }}
WHERE event_timestamp >= DATEADD('day', -30, CURRENT_TIMESTAMP())
```

---

## Building Custom Security AI Agents with nanocortex

The **nanocortex** blueprint provides a minimal (~1,600 lines) single-file implementation of a Snowflake Cortex Agent. Use it to build custom AI agents for security operations tasks.

**Repository:** [github.com/sfc-gh-kkeller/nanocortex](https://github.com/sfc-gh-kkeller/nanocortex)

### Why Build Custom Security Agents

| Use Case | Benefit |
|----------|---------|
| **Automated threat hunting** | Natural language queries against security logs |
| **Incident investigation** | AI-assisted evidence gathering and analysis |
| **SOC automation** | Conversational interface for security operations |
| **Custom tooling** | Add security-specific tools the model can use |
| **Offline/air-gapped** | Run in isolated environments with local tools |

### nanocortex Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         nanocortex Architecture                              │
│                                                                              │
│  ┌────────────────┐     ┌──────────────────┐     ┌────────────────────────┐ │
│  │   User Input   │────▶│   CortexAgent    │────▶│ Cortex Agent API       │ │
│  │   (Terminal)   │     │   (Python)       │     │ /api/v2/cortex/agent   │ │
│  └────────────────┘     └────────┬─────────┘     └───────────┬────────────┘ │
│                                  │                           │              │
│                    ┌─────────────┼─────────────┐            │              │
│                    │             │             │            │              │
│                    ▼             ▼             ▼            ▼              │
│            ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐        │
│            │ read/write│ │   bash    │ │ glob/grep │ │web_search │        │
│            │   edit    │ │           │ │           │ │   (API)   │        │
│            └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘        │
│                  │             │             │             │              │
│            CLIENT-SIDE    CLIENT-SIDE   CLIENT-SIDE   SERVER-SIDE        │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    snowflake_sql_execute                                │ │
│  │  ┌──────────────────┐              ┌─────────────────────────────────┐ │ │
│  │  │ snowflake.connector │ (preferred)│ REST API /queries/v1/query     │ │ │
│  │  │ (if installed)      │─────OR─────│ (stdlib fallback)              │ │ │
│  │  └──────────────────┘              └─────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Quick Start

```bash
# Clone and run
git clone https://github.com/sfc-gh-kkeller/nanocortex.git
cd nanocortex

# Using pixi (recommended)
pixi run run -c myconnection

# Or with pip (stdlib only - no external deps!)
python nanocortex.py -c myconnection
```

### Authentication Methods

| Method | Configuration |
|--------|---------------|
| **PAT** | `authenticator = "PROGRAMMATIC_ACCESS_TOKEN"` + `token_file_path` |
| **Private Key** | `private_key_file = "~/.snowflake/rsa_key.p8"` |
| **WIF** | `authenticator = "WIF"` + `wif_provider = "auto"` (GCP/Azure/AWS) |
| **Browser** | `authenticator = "EXTERNALBROWSER"` (default fallback) |

### Adding Custom Security Tools

To add a security-specific tool, modify the `CLIENT_TOOLS` dictionary in `nanocortex.py`:

```python
# Security tool implementations
def query_threat_intel(args: Dict) -> str:
    """Query threat intelligence database for IOC."""
    ioc = args.get("indicator")
    ioc_type = args.get("type", "auto")  # ip, domain, hash, email
    
    # Query your threat intel table
    sql = f"""
    SELECT indicator_value, threat_actor, confidence, source, first_seen, last_seen
    FROM security_ops.threat_indicators
    WHERE indicator_value = '{ioc}'
      AND is_active = TRUE
    """
    return agent.sql_execute(sql)


def analyze_user_activity(args: Dict) -> str:
    """Analyze user activity for anomalies."""
    user = args.get("user_name")
    hours = args.get("lookback_hours", 24)
    
    sql = f"""
    SELECT 
        DATE_TRUNC('hour', event_timestamp) as hour,
        COUNT(*) as query_count,
        COUNT(DISTINCT client_ip) as unique_ips,
        SUM(bytes_scanned) as total_bytes
    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE user_name = '{user}'
      AND start_time >= DATEADD('hour', -{hours}, CURRENT_TIMESTAMP())
    GROUP BY 1
    ORDER BY 1
    """
    return agent.sql_execute(sql)


def check_login_anomalies(args: Dict) -> str:
    """Check for login anomalies for a user."""
    user = args.get("user_name")
    
    sql = f"""
    SELECT 
        event_timestamp,
        client_ip,
        reported_client_type,
        first_authentication_factor,
        error_code,
        error_message
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE user_name = '{user}'
      AND event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
    ORDER BY event_timestamp DESC
    LIMIT 50
    """
    return agent.sql_execute(sql)


def get_data_access_summary(args: Dict) -> str:
    """Get data access summary for investigation."""
    user = args.get("user_name")
    database = args.get("database")
    
    sql = f"""
    SELECT 
        ah.query_start_time,
        ah.user_name,
        bo.value:objectName::STRING as accessed_object,
        bo.value:objectDomain::STRING as object_type,
        ARRAY_SIZE(ah.base_objects_accessed) as objects_accessed_count
    FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY ah,
         LATERAL FLATTEN(input => ah.base_objects_accessed) bo
    WHERE ah.user_name = '{user}'
      AND ah.query_start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
      {f"AND bo.value:objectName::STRING ILIKE '{database}%'" if database else ""}
    ORDER BY ah.query_start_time DESC
    LIMIT 100
    """
    return agent.sql_execute(sql)


# Add to CLIENT_TOOLS dictionary
SECURITY_TOOLS = {
    "query_threat_intel": (
        "Query threat intelligence for an indicator (IP, domain, hash, email)",
        {"indicator": "string", "type": "string?"},
        query_threat_intel
    ),
    "analyze_user_activity": (
        "Analyze user query activity for anomalies",
        {"user_name": "string", "lookback_hours": "number?"},
        analyze_user_activity
    ),
    "check_login_anomalies": (
        "Check user login history for anomalies",
        {"user_name": "string"},
        check_login_anomalies
    ),
    "get_data_access_summary": (
        "Get data access summary for a user",
        {"user_name": "string", "database": "string?"},
        get_data_access_summary
    ),
}

# Merge with existing tools
CLIENT_TOOLS = {**CLIENT_TOOLS, **SECURITY_TOOLS}
```

### Custom System Prompt for Security Agent

Replace the default `SYSTEM_PROMPT` for a security-focused agent:

```python
SECURITY_SYSTEM_PROMPT = """You are a Security Operations AI Assistant with access to these tools:
- bash: Execute shell commands for local analysis
- read/write/edit: Manage investigation notes and reports
- glob/grep: Search local files and logs
- web_search: Search for threat intelligence and CVE information
- snowflake_sql_execute: Query Snowflake security logs and ACCOUNT_USAGE views
- query_threat_intel: Look up indicators of compromise (IOCs)
- analyze_user_activity: Analyze user behavior patterns
- check_login_anomalies: Review login history for suspicious activity
- get_data_access_summary: Review what data a user accessed

Key Snowflake Security Views:
- SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY - Authentication events
- SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY - Query execution logs
- SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY - Data access audit trail
- SNOWFLAKE.ACCOUNT_USAGE.SESSIONS - Active and historical sessions
- SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS - User privileges
- SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES - Role privileges

When investigating security incidents:
1. Start with LOGIN_HISTORY to establish authentication timeline
2. Use QUERY_HISTORY to see what actions were taken
3. Use ACCESS_HISTORY to identify data accessed
4. Cross-reference with your threat intelligence tables
5. Document findings in structured format

Always use fully qualified table names (DATABASE.SCHEMA.TABLE).
Current working directory: {cwd}

{snowflake_context}"""
```

### Example Security Agent Session

```
nanocortex | Snowflake Cortex Agent | Security Operations
Connection: security_conn | Account: myorg-myaccount | User: soc_analyst

Authenticating... ✓
Fetching Snowflake context... ✓
  Role: SECURITY_ANALYST | DB: SECURITY_DB | Schema: SECURITY_OPS
  Warehouse: SECURITY_WH | Reflect: ON

────────────────────────────────────────────────────────────────────────────────
❯ investigate user jsmith for potential data exfiltration in the last 24 hours
────────────────────────────────────────────────────────────────────────────────

⏺ check_login_anomalies(jsmith)
  ⎿  2026-03-21 14:32:00 | 203.0.113.45 | PYTHON_DRIVER | PASSWORD | null...

⏺ analyze_user_activity(jsmith, 24)
  ⎿  2026-03-21 14:00 | 847 queries | 3 unique IPs | 45.2 GB scanned...

⏺ get_data_access_summary(jsmith)
  ⎿  2026-03-21 14:15 | CUSTOMER_DB.PII.CREDIT_CARDS | TABLE | 15 objects...

⏺ snowflake_sql_execute
  ⎿  SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.COPY_HISTORY WHERE user_name = 'JSMITH'...

[reflecting...]

**Investigation Summary: User JSMITH - Potential Data Exfiltration**

**Timeline:**
- 14:32 UTC: Login from unusual IP (203.0.113.45) - first time seen for this user
- 14:15-15:30: Accessed 15 sensitive objects including PII.CREDIT_CARDS
- 15:45: COPY command executed to external stage (s3://unknown-bucket)

**Risk Indicators:**
- New source IP (not in user's historical pattern)
- Accessed PII tables not typically in user's workflow
- Large data export (45.2 GB scanned, 12.3 GB exported)

**Recommended Actions:**
1. Disable user account immediately
2. Revoke external stage access
3. Review copied data for PII exposure
4. Contact user's manager for verification

**MITRE ATT&CK Mapping:** T1048 - Exfiltration Over Alternative Protocol

────────────────────────────────────────────────────────────────────────────────
❯ query the threat intel for IP 203.0.113.45
────────────────────────────────────────────────────────────────────────────────

⏺ query_threat_intel(203.0.113.45, ip)
  ⎿  203.0.113.45 | APT29 | high | AlienVault | 2026-01-15 | 2026-03-20...

This IP is associated with APT29 (Cozy Bear) threat actor with HIGH confidence.
First seen: 2026-01-15, Last seen: 2026-03-20.

**CRITICAL: This appears to be a nation-state attack. Escalate immediately.**
```

### Extending nanocortex for SOC Automation

```python
# Add incident creation capability
def create_incident(args: Dict) -> str:
    """Create a security incident in the incidents table."""
    title = args.get("title")
    severity = args.get("severity", "MEDIUM")
    description = args.get("description")
    entity = args.get("entity")
    mitre_technique = args.get("mitre_technique")
    
    sql = f"""
    INSERT INTO security_ops.incidents (
        incident_id, title, severity, description, 
        affected_entity, mitre_technique, status, created_at, created_by
    )
    SELECT 
        UUID_STRING(),
        '{title}',
        '{severity}',
        '{description}',
        '{entity}',
        '{mitre_technique}',
        'OPEN',
        CURRENT_TIMESTAMP(),
        CURRENT_USER()
    """
    return agent.sql_execute(sql)


def disable_user_account(args: Dict) -> str:
    """Disable a user account (requires SECURITYADMIN)."""
    user = args.get("user_name")
    reason = args.get("reason", "Security investigation")
    
    # First, log the action
    log_sql = f"""
    INSERT INTO security_ops.admin_actions (action_type, target_user, reason, performed_by, performed_at)
    VALUES ('DISABLE_USER', '{user}', '{reason}', CURRENT_USER(), CURRENT_TIMESTAMP())
    """
    agent.sql_execute(log_sql)
    
    # Then disable the user
    disable_sql = f"ALTER USER {user} SET DISABLED = TRUE"
    return agent.sql_execute(disable_sql)
```

### Deployment Options

| Option | Use Case |
|--------|----------|
| **Local CLI** | Interactive SOC analyst workstation |
| **SPCS Container** | Shared team deployment in Snowflake |
| **Scheduled Task** | Automated periodic analysis |
| **Streamlit Frontend** | Web UI for non-technical users |
| **API Service** | Integration with ticketing systems |

### Security Considerations

- **Authentication:** Use PAT or key-pair auth (avoid storing passwords)
- **Role-based access:** Create dedicated roles for security operations
- **Audit logging:** All agent actions go through QUERY_HISTORY
- **Network isolation:** Deploy in SPCS for air-gapped environments
- **Tool restrictions:** Limit tools based on user role

---

## Real-Time Security Infrastructure

### Streamlit in Snowflake for SOC Dashboards

Streamlit in Snowflake provides real-time security dashboards without external infrastructure. Two deployment options:

| Deployment | Use Case | Latency |
|------------|----------|---------|
| **Virtual Warehouse** | Cost-effective, auto-suspend | Seconds (warehouse resume) |
| **SPCS** | Always-on, sub-second, real-time features | Milliseconds |

> **Important:** Most real-time dashboard features require SPCS-powered Streamlit. The VW-based version has limitations on background processes, websockets, and auto-refresh capabilities.

| Feature | VW Streamlit | SPCS Streamlit |
|---------|--------------|----------------|
| `st.fragment(run_every=)` | ❌ Limited | ✅ Full support |
| Background threads | ❌ No | ✅ Yes |
| Websocket connections | ❌ No | ✅ Yes |
| Custom packages | ❌ Allowlist only | ✅ Any pip package |
| Always-on availability | ❌ Cold start delay | ✅ Instant |
| External API calls | ❌ Restricted | ✅ Full network access |
| Long-running processes | ❌ Timeout limits | ✅ No timeout |

**For real-time SOC dashboards, use SPCS Streamlit.**

#### Real-Time Refresh Patterns

```python
import streamlit as st
from snowflake.snowpark.context import get_active_session
import time

session = get_active_session()

# Pattern 1: TTL-based caching with short expiry
@st.cache_data(ttl=30)  # 30-second refresh
def get_active_alerts():
    return session.sql("""
        SELECT * FROM security_ops.dt_active_alerts
        WHERE alert_time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
        ORDER BY severity DESC, alert_time DESC
    """).to_pandas()

# Pattern 2: st.fragment for partial reruns (reduces flicker)
@st.fragment(run_every="30s")
def alert_ticker():
    alerts = session.sql("""
        SELECT alert_type, COUNT(*) as cnt 
        FROM security_ops.dt_active_alerts
        WHERE alert_time > DATEADD('minute', -5, CURRENT_TIMESTAMP())
        GROUP BY 1
    """).to_pandas()
    for _, row in alerts.iterrows():
        st.metric(row['ALERT_TYPE'], row['CNT'])

# Pattern 3: Manual refresh button + auto-refresh
if st.button("🔄 Refresh Now"):
    st.cache_data.clear()
    st.rerun()

# Auto-refresh every 60 seconds
st.markdown("""
<meta http-equiv="refresh" content="60">
""", unsafe_allow_html=True)
```

#### SOC Dashboard Layout

```python
import streamlit as st

st.set_page_config(layout="wide", page_title="Security Operations Center")

# Header with live status
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🚨 Critical Alerts", get_critical_count(), delta=get_critical_delta())
with col2:
    st.metric("⚠️ Active Incidents", get_incident_count())
with col3:
    st.metric("🔍 IOCs Today", get_ioc_count())
with col4:
    st.metric("📊 Events/min", get_event_rate())

# Two-column layout
left, right = st.columns([2, 1])

with left:
    st.subheader("Real-Time Alert Feed")
    # Query Dynamic Table for near-real-time alerts
    alerts_df = session.sql("""
        SELECT * FROM security_ops.dt_brute_force_alerts
        WHERE detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
    """).to_pandas()
    st.dataframe(alerts_df, use_container_width=True)

with right:
    st.subheader("Threat Map")
    # GeoIP visualization
    st.map(get_threat_locations())
```

### Snowflake Postgres for Real-Time Ingestion

Snowflake Postgres (Public Preview Dec 2025) enables real-time security data ingestion with native PostgreSQL:

| Feature | Security Use Case |
|---------|-------------------|
| **pg_vector** | Vector similarity for threat intel matching, RAG for incident response |
| **PostGIS** | Geospatial threat analysis, IP geolocation enrichment |
| **CDC via OpenFlow** | Real-time replication to Snowflake for analytics |
| **Low-latency writes** | High-frequency log ingestion from agents/sensors |

#### Architecture: Real-Time Detection Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Real-Time Security Detection Architecture                      │
│                                                                                   │
│  ┌────────────┐    ┌─────────────────┐    ┌───────────────┐    ┌──────────────┐│
│  │ Security   │───▶│ Snowflake       │───▶│ OpenFlow CDC  │───▶│ Snowflake    ││
│  │ Agents     │    │ Postgres        │    │ (NiFi)        │    │ Tables       ││
│  │ (EDR/SIEM) │    │ (Low latency)   │    │               │    │              ││
│  └────────────┘    └─────────────────┘    └───────────────┘    └──────┬───────┘│
│                                                                        │        │
│                                                                        ▼        │
│                                                              ┌─────────────────┐│
│                                                              │ Dynamic Tables  ││
│                                                              │ (Detection      ││
│                                                              │  Pipeline)      ││
│                                                              └────────┬────────┘│
│                                                                       │         │
│       ┌────────────────────────────────────────────────────────────┬──┘         │
│       │                        │                        │                        │
│       ▼                        ▼                        ▼                        │
│ ┌──────────────┐      ┌──────────────┐      ┌──────────────┐                    │
│ │ Streamlit    │      │ Cortex Agent │      │ Alerting     │                    │
│ │ Dashboard    │      │ (nanocortex) │      │ (Webhooks)   │                    │
│ └──────────────┘      └──────────────┘      └──────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Postgres Setup for Security Ingestion

```sql
-- Create Postgres instance for security logs
CREATE POSTGRES INSTANCE security_ingest
    COMPUTE_FAMILY = STANDARD_M
    STORAGE_SIZE_GB = 100
    AUTHENTICATION_AUTHORITY = POSTGRES
    POSTGRES_VERSION = 17
    HIGH_AVAILABILITY = TRUE
    NETWORK_POLICY = SOC_INGRESS_POLICY
    COMMENT = 'Security log ingestion with HA';

-- In Postgres: Create security tables with replication
CREATE DATABASE security_logs;
CREATE USER soc_ingest WITH PASSWORD 'xxx' REPLICATION;
GRANT ALL PRIVILEGES ON DATABASE security_logs TO soc_ingest;

-- Create tables with pg_vector for threat matching
CREATE TABLE threat_intel (
    id SERIAL PRIMARY KEY,
    indicator TEXT NOT NULL,
    indicator_type VARCHAR(20),
    threat_actor VARCHAR(100),
    confidence FLOAT,
    embedding VECTOR(384),  -- For semantic similarity
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX ON threat_intel USING ivfflat (embedding vector_cosine_ops);
```

### Hybrid Tables for OLTP Security Workloads

Hybrid Tables provide row-level locking for high-concurrency security operations:

| Standard Tables | Hybrid Tables |
|-----------------|---------------|
| Columnar (OLAP optimized) | Row-oriented (OLTP optimized) |
| Partition-level locking | Row-level locking |
| Constraints NOT enforced | PRIMARY/FOREIGN KEY enforced |
| Batch analytics | Point lookups, high concurrency |

#### Security Use Cases for Hybrid Tables

```sql
-- Case management with enforced referential integrity
CREATE OR REPLACE HYBRID TABLE security_ops.incident_cases (
    case_id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    severity INT NOT NULL,
    status VARCHAR(20) DEFAULT 'OPEN',
    assigned_to VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    CONSTRAINT chk_severity CHECK (severity BETWEEN 1 AND 5),
    CONSTRAINT chk_status CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'))
);

-- IOC tracking with fast point lookups
CREATE OR REPLACE HYBRID TABLE security_ops.active_iocs (
    ioc_id VARCHAR(64) PRIMARY KEY,
    indicator_value VARCHAR(500) NOT NULL UNIQUE,
    indicator_type VARCHAR(20),
    threat_score FLOAT,
    last_seen TIMESTAMP,
    hit_count INT DEFAULT 0,
    INDEX idx_indicator_type (indicator_type)
);

-- High-concurrency IOC matching (thousands of parallel workers)
CREATE OR REPLACE HYBRID TABLE security_ops.ioc_match_queue (
    match_id VARCHAR(36) PRIMARY KEY,
    source_log_id VARCHAR(36) NOT NULL,
    matched_ioc_id VARCHAR(64) REFERENCES security_ops.active_iocs(ioc_id),
    match_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    processed BOOLEAN DEFAULT FALSE,
    INDEX idx_unprocessed (processed) WHERE processed = FALSE
);
```

### Interactive Tables & Warehouses for Sub-Second Security Dashboards

Interactive Tables (GA Dec 2025) deliver sub-second query latency for high-concurrency security dashboards — Snowflake's answer to ClickHouse.

**Documentation:**
- [Interactive Tables Overview](https://docs.snowflake.com/en/user-guide/interactive)
- [CREATE INTERACTIVE TABLE](https://docs.snowflake.com/en/sql-reference/sql/create-interactive-table)
- [CREATE INTERACTIVE WAREHOUSE](https://docs.snowflake.com/en/sql-reference/sql/create-interactive-warehouse)

| Feature | Interactive Tables | Standard Tables |
|---------|-------------------|-----------------|
| **Query latency** | Sub-second (5s timeout) | Seconds-minutes |
| **Concurrency** | Optimized for thousands | Standard |
| **Auto-suspend** | 24hr minimum (cache) | 60s minimum |
| **DML support** | INSERT OVERWRITE only | Full CRUD |
| **Clustering** | Required (`CLUSTER BY`) | Optional |
| **Max per warehouse** | 10 tables | Unlimited |

#### Security Use Cases

| Use Case | Why Interactive Tables |
|----------|------------------------|
| **SOC Dashboard** | Sub-second alert feeds, real-time threat maps |
| **Threat Intel Lookups** | Point lookups on IOC tables with Search Optimization |
| **User-facing APIs** | High-concurrency security portals |
| **Live Investigation** | Fast filtering during incident response |

#### Creating Security Interactive Tables

```sql
-- Create interactive table for real-time alerts
CREATE INTERACTIVE TABLE security_ops.it_active_alerts
  CLUSTER BY (alert_time, severity)
  TARGET_LAG = '1 minute'
  WAREHOUSE = security_refresh_wh
AS 
SELECT 
    alert_id,
    alert_time,
    severity,
    detection_type,
    entity_id,
    entity_type,
    mitre_tactic,
    mitre_technique,
    raw_event
FROM security_ops.dt_all_alerts
WHERE alert_time > DATEADD('day', -7, CURRENT_TIMESTAMP());

-- Create interactive table for IOC lookups (with Search Optimization)
CREATE INTERACTIVE TABLE security_ops.it_threat_indicators
  CLUSTER BY (indicator_type, indicator_value)
AS
SELECT * FROM security_ops.threat_indicators
WHERE is_active = TRUE;

-- Add Search Optimization for point lookups
ALTER TABLE security_ops.it_threat_indicators 
  ADD SEARCH OPTIMIZATION ON EQUALITY(indicator_value);
```

#### Creating the SOC Interactive Warehouse

```sql
-- Create interactive warehouse for SOC dashboards
CREATE INTERACTIVE WAREHOUSE soc_dashboard_wh
  TABLES (
    security_ops.it_active_alerts,
    security_ops.it_threat_indicators
  )
  WAREHOUSE_SIZE = 'SMALL'
  AUTO_SUSPEND = 86400  -- 24 hours minimum
  AUTO_RESUME = TRUE;

-- Resume and warm cache
ALTER WAREHOUSE soc_dashboard_wh RESUME;

-- Check cache warm-up status
SHOW WAREHOUSES LIKE 'soc_dashboard_wh';
```

#### Querying from Streamlit Dashboard

```python
import streamlit as st
from snowflake.snowpark.context import get_active_session

session = get_active_session()

# Switch to interactive warehouse for sub-second queries
session.sql("USE WAREHOUSE soc_dashboard_wh").collect()

@st.cache_data(ttl=10)  # Short TTL for real-time feel
def get_critical_alerts():
    return session.sql("""
        SELECT * FROM security_ops.it_active_alerts
        WHERE severity >= 4
          AND alert_time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
        ORDER BY alert_time DESC
        LIMIT 100
    """).to_pandas()

# IOC lookup with sub-second response
def check_ioc(indicator: str):
    return session.sql(f"""
        SELECT * FROM security_ops.it_threat_indicators
        WHERE indicator_value = '{indicator}'
    """).to_pandas()
```

#### Sizing Guide for Security Workloads

| Working Data Set | Warehouse Size | Typical Use Case |
|------------------|----------------|------------------|
| < 500 GB | XSMALL | Single team SOC dashboard |
| 500 GB - 1 TB | SMALL | Multi-team security portal |
| 1 - 2 TB | MEDIUM | Enterprise SOC with drill-downs |
| 2 - 4 TB | LARGE | High-volume SIEM replacement |
| 4+ TB | XLARGE+ | Global security operations |

#### Limitations for Security Use Cases

- **No streams**: Can't trigger alerts directly from interactive tables
- **No DT base**: Can't use interactive tables as Dynamic Table sources
- **5s timeout**: Complex threat hunting queries won't work
- **10 table limit**: Prioritize most-queried security tables

**Workaround Pattern**: Use Dynamic Tables for detection pipelines, then feed results into Interactive Tables for dashboards:

```
Raw Logs → Dynamic Tables (detection) → Interactive Tables (dashboard)
```

### ClickHouse Comparison for Security Analytics

For high-volume security log analytics, understand the tradeoffs:

| Dimension | Snowflake | ClickHouse |
|-----------|-----------|------------|
| **Query latency** | ~100ms-seconds | ~10-100ms |
| **Warehouse suspend** | 60s minimum | N/A (always on) |
| **Clustering** | Async background (costs credits) | ORDER BY at insert (free) |
| **Real-time ingest** | Snowpipe Streaming, Postgres CDC | Native insert performance |
| **Best for** | Mixed OLAP/OLTP, governance | Pure real-time OLAP |
| **Compression** | ~3-4x | ~4-10x (with codecs) |

#### When to Use Each

- **Snowflake**: Unified governance, mixed workloads, dbt pipelines, ML integration
- **ClickHouse**: Sub-100ms dashboards, log search at scale, cost-sensitive high-volume

#### Hybrid Architecture Pattern

```sql
-- Use Snowflake for:
-- 1. Long-term retention with governance
-- 2. Complex joins across security domains
-- 3. ML-based detection with Cortex

-- Use ClickHouse for:
-- 1. Real-time log search (<100ms)
-- 2. High-cardinality metrics
-- 3. User-facing dashboards

-- Bridge with Snowflake's federated query:
SELECT * FROM TABLE(
    EXTERNAL_TABLE_QUERY(
        'clickhouse_integration',
        'SELECT * FROM security_logs WHERE timestamp > now() - INTERVAL 1 HOUR'
    )
);
```

### Dynamic Tables 2025 Enhancements for Security

New Dynamic Table features (2025) optimize security detection pipelines:

| Feature | Status | Security Benefit |
|---------|--------|------------------|
| **Filter by Current Time** | GA | Process only recent events, reduce costs |
| **Immutability** | Coming Soon | Preserve historical detections even if source deleted |
| **Insert-Only Inputs** | Private Preview | Faster ingestion, ignore deletes for append-only logs |
| **Backfill** | GA Soon | Seed with historical data without reprocessing |

#### Example: Optimized Detection Pipeline

```sql
-- Use current_timestamp filtering to minimize processing
CREATE OR REPLACE DYNAMIC TABLE security_ops.dt_recent_alerts
    TARGET_LAG = '1 minute'
    WAREHOUSE = security_warehouse
AS
SELECT *
FROM security_ops.raw_events
WHERE event_time >= DATEADD('hour', -2, CURRENT_TIMESTAMP())  -- Only process recent
  AND threat_score > 0.7;

-- Immutable region for compliance (coming soon)
CREATE OR REPLACE DYNAMIC TABLE security_ops.dt_audit_trail
    TARGET_LAG = '5 minutes'
    WAREHOUSE = security_warehouse
    IMMUTABLE WHERE (event_date < DATEADD('day', -1, CURRENT_DATE()))  -- Lock historical
AS
SELECT * FROM security_ops.audit_events;

-- Insert-only for append-only security logs (private preview)
CREATE OR REPLACE DYNAMIC TABLE security_ops.dt_syslog_processed
    TARGET_LAG = '30 seconds'
    WAREHOUSE = security_warehouse
    INSERT_ONLY = TRUE  -- Ignore deletes/updates from source
AS
SELECT * FROM security_ops.raw_syslog;
```

---

## External Resources

### Security Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversary tactics and techniques
- [OWASP Top 10](https://owasp.org/Top10/) — Web application security risks
- [NIST CSF](https://www.nist.gov/cyberframework) — Cybersecurity framework
- [CVE Database](https://cve.mitre.org/) — Vulnerability database
- [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories) — US government security advisories

### Log Schemas & Standards
- [OCSF](https://ocsf.io/) — Open Cybersecurity Schema Framework
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) — Threat intelligence sharing standards
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) — ECS log format

### Snowflake Security
- [Snowflake Sentry](https://snowflake-labs.github.io/Sentry/) — Snowflake security monitoring
- [Trust Center Extensions](https://docs.snowflake.com/en/user-guide/trust-center/trust-center-extensions) — Custom scanner development
- [Openflow ListenOTLP](https://docs.snowflake.com/en/user-guide/data-integration/openflow/processors/listenotlp) — Native OTel ingestion
- [nanocortex](https://github.com/sfc-gh-kkeller/nanocortex) — Minimal Cortex Agent blueprint for custom security agents

### Observability & Log Ingestion
- [OpenTelemetry](https://opentelemetry.io/) — Vendor-neutral observability framework
- [Snowflake OTel Receiver](https://github.com/KellerKev/snowflake-opentelemetry-receiver) — Custom OTLP receiver for Snowflake
- [Fluentd Snowflake Quickstart](https://www.snowflake.com/en/developers/guides/integrating-fluentd-with-snowflake/) — Log ingestion via Fluentd
- [Vector.dev](https://vector.dev/) — High-performance log pipeline
- [Datadog Observability Pipelines](https://docs.datadoghq.com/observability_pipelines/) — Dual-ship and transform logs

### Detection Engineering
- [Detection Engineering Framework](https://github.com/CiscoCXSecurity/Detection-Engineering-Framework) — Detection as Code practices

### Blog References
- [OpenTelemetry into Snowflake](https://kevinkeller.org/posts/opentelemetry-snowflake-observability-datalake/) — OTel observability data lake
- [Snowflake SIEM/XDR Automation](https://kevinkeller.org/posts/snowflake-siem-xdr-automated-security-incidents/) — Automated incident raising
