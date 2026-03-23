# Security Operations AI Skill for Cortex Code

A comprehensive cybersecurity AI agent skill that transforms Snowflake into a modern Security Data Lake with automated threat detection, incident response, and real-time SOC dashboards.

## What This Skill Does

This skill enables Cortex Code to act as an AI-powered security analyst that can:

- **Detect threats** using Dynamic Table pipelines with sub-minute latency
- **Hunt for anomalies** across access logs, query history, and network data
- **Investigate incidents** with natural language queries against security logs
- **Build SOC dashboards** with sub-second response times
- **Automate responses** via webhooks, Slack, and ticketing integrations

## Business Outcomes

| Outcome | How It's Achieved |
|---------|-------------------|
| **Reduce MTTD** (Mean Time to Detect) | Dynamic Tables with 1-5 minute TARGET_LAG for continuous detection |
| **Reduce MTTR** (Mean Time to Respond) | AI-assisted investigation with natural language threat hunting |
| **Lower SIEM costs** | Replace expensive SIEM with Snowflake's consumption-based pricing |
| **Consolidate tools** | Single platform for logs, detection, dashboards, and ML |
| **Enable Detection-as-Code** | Version-controlled detections with dbt and CI/CD |
| **Real-time visibility** | Interactive Tables + SPCS Streamlit for sub-second dashboards |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         Security Data Lake Architecture                          │
│                                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐     │
│  │ Cloud Logs   │   │ EDR/XDR      │   │ Identity     │   │ Network      │     │
│  │ (AWS/GCP/Az) │   │ (CrowdStrike)│   │ (Okta/Entra) │   │ (Firewall)   │     │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘     │
│         │                  │                  │                  │              │
│         └──────────────────┼──────────────────┼──────────────────┘              │
│                            ▼                                                     │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                         INGESTION LAYER                                     │ │
│  │  Snowpipe Streaming │ OpenFlow (NiFi) │ Kafka Connector │ REST API   │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                            │                                                     │
│                            ▼                                                     │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                      PROCESSING LAYER (Dynamic Tables)                      │ │
│  │                                                                              │ │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │ │
│  │  │ Stage 1     │───▶│ Stage 2     │───▶│ Stage 3     │───▶│ Alerts      │  │ │
│  │  │ Normalize   │    │ Enrich      │    │ Detect      │    │ & Actions   │  │ │
│  │  │ (1 min lag) │    │ (2 min lag) │    │ (5 min lag) │    │             │  │ │
│  │  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                            │                                                     │
│         ┌──────────────────┼──────────────────┬──────────────────┐              │
│         ▼                  ▼                  ▼                  ▼              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐         │
│  │ Interactive │   │ Cortex      │   │ Streamlit   │   │ Webhooks    │         │
│  │ Tables      │   │ Agent       │   │ Dashboard   │   │ (PagerDuty) │         │
│  │ (Dashboard) │   │ (nanocortex)│   │ (SPCS)      │   │             │         │
│  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Demo: End-to-End Security Operations Pipeline

The `demo/` folder contains a complete, working security operations environment you can deploy in 15 minutes. Run the scripts in order to build a fully functional threat detection system.

### What You'll Build

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           DEMO ARCHITECTURE                                      │
│                                                                                  │
│  📊 5,000+ Normal Events     🔴 Injected Attack Patterns                        │
│      └─────────────────────────────┬───────────────────────────────┘            │
│                                    ▼                                             │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ RAW TABLES                                                                  │ │
│  │   • LOGIN_EVENTS (auth attempts)     • QUERY_EVENTS (SQL activity)         │ │
│  │   • NETWORK_EVENTS (firewall logs)                                          │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                             │
│                         Dynamic Table Pipeline                                   │
│                                    ▼                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────────┐  │
│  │ STAGE 1      │    │ STAGE 2      │    │ STAGE 3: DETECTIONS              │  │
│  │ Normalize    │───▶│ Enrich with  │───▶│  • Brute Force Alerts            │  │
│  │ (1 min lag)  │    │ Threat Intel │    │  • Credential Stuffing Alerts    │  │
│  │              │    │ (2 min lag)  │    │  • Impossible Travel Alerts      │  │
│  └──────────────┘    └──────────────┘    │  • Data Exfiltration Alerts      │  │
│                                          │  • Privilege Escalation Alerts   │  │
│                                          └──────────────────────────────────┘  │
│                                    │                                             │
│                                    ▼                                             │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ 📺 STREAMLIT SOC DASHBOARD                                                  │ │
│  │   Real-time metrics │ Alert table │ Severity charts │ Auto-refresh         │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Demo Scripts Overview

| Script | What It Does | Objects Created | Time |
|--------|--------------|-----------------|------|
| **01_setup_security_schema.sql** | Creates database, schemas, tables, and roles | 1 database, 5 schemas, 6 tables, 2 roles | 1 min |
| **02_generate_demo_data.sql** | Populates tables with realistic events + attack patterns | 10,000+ events with 5 attack types | 2 min |
| **03_detection_pipeline.sql** | Builds 3-stage Dynamic Table detection pipeline | 9 Dynamic Tables, 5 detection rules | 3 min |
| **04_interactive_tables.sql** | Creates high-performance tables for dashboards | 2 Interactive Tables, 1 Hybrid Table | 2 min |
| **05_streamlit_dashboard.py** | Real-time SOC dashboard with auto-refresh | Streamlit app (SPCS or local) | 5 min |

---

### Script 1: Setup Security Schema

**File:** `demo/01_setup_security_schema.sql`

**What it creates:**

```
SECURITY_OPS (Database)
├── RAW                  ← Landing zone for ingested logs
│   ├── LOGIN_EVENTS     (auth attempts with geo-location)
│   ├── QUERY_EVENTS     (SQL queries with metadata)
│   └── NETWORK_EVENTS   (firewall/flow logs)
├── STAGING              ← Normalized, cleaned data
├── ENRICHED             ← Enriched with threat intel context
├── DETECTIONS           ← Alert outputs from detection rules
└── REFERENCE            ← Lookup tables
    ├── THREAT_INDICATORS (IOCs: malicious IPs, domains)
    └── KNOWN_GOOD_IPS    (allowlist for VPN, corporate)
```

**Roles created:**
- `SECURITY_ANALYST` — Read access to all security data
- `SECURITY_ADMIN` — Full control over security infrastructure

---

### Script 2: Generate Demo Data

**File:** `demo/02_generate_demo_data.sql`

**What it generates:**

| Data Type | Volume | Description |
|-----------|--------|-------------|
| Normal logins | 5,000 | Successful logins from US corporate IPs |
| Failed logins | 500 | Random failed attempts (typos, expired passwords) |
| Normal queries | 3,000 | Typical SELECT/INSERT/UPDATE patterns |
| Threat indicators | 100 | Known malicious IPs, domains, hashes |

**Injected Attack Patterns (for detection testing):**

| Attack | Pattern | What It Looks Like |
|--------|---------|-------------------|
| 🔴 **Brute Force** | 50 failed logins in 3 minutes from single IP | `185.220.101.42` → `USER_042` with `INCORRECT_PASSWORD` |
| 🔴 **Credential Stuffing** | 1 IP targeting 25 different users | `45.227.255.99` rotating through usernames |
| 🔴 **Impossible Travel** | Login from NYC, then Moscow 30 min later | `USER_017` crosses 7,500 km impossibly fast |
| 🔴 **Data Exfiltration** | 200 GB scanned in 1 hour | `USER_031` bulk-downloading from `CUSTOMER_DB` |
| 🔴 **Privilege Escalation** | GRANT ACCOUNTADMIN to suspicious user | `GRANT ROLE ACCOUNTADMIN TO USER compromised_user` |

---

### Script 3: Detection Pipeline

**File:** `demo/03_detection_pipeline.sql`

**3-Stage Dynamic Table Architecture:**

```
STAGE 1: NORMALIZATION (1 min lag)
┌─────────────────────────────────────────────────────────┐
│ DT_NORMALIZED_LOGINS                                    │
│   • Standardize timestamps                              │
│   • Add time buckets (minute, hour, day)                │
│   • Filter to 7-day rolling window                      │
├─────────────────────────────────────────────────────────┤
│ DT_NORMALIZED_QUERIES                                   │
│   • Calculate GB scanned                                │
│   • Extract query metadata                              │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
STAGE 2: ENRICHMENT (2 min lag)
┌─────────────────────────────────────────────────────────┐
│ DT_ENRICHED_LOGINS                                      │
│   • JOIN with THREAT_INDICATORS (is_known_threat_ip)    │
│   • JOIN with KNOWN_GOOD_IPS (is_corporate_ip)          │
│   • Add threat_actor, threat_type, confidence_score     │
├─────────────────────────────────────────────────────────┤
│ DT_ENRICHED_QUERIES                                     │
│   • Flag queries from threat IPs                        │
│   • Tag sensitive data access                           │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
STAGE 3: DETECTION (5 min lag)
┌─────────────────────────────────────────────────────────┐
│ DT_BRUTE_FORCE_ALERTS                                   │
│   • Trigger: >5 failed logins per user per minute       │
│   • Severity: 3-5 based on attempt count                │
│   • MITRE: T1110 (Brute Force)                          │
├─────────────────────────────────────────────────────────┤
│ DT_CREDENTIAL_STUFFING_ALERTS                           │
│   • Trigger: 1 IP targeting 5+ unique users             │
│   • Severity: 3-5 based on user count                   │
│   • MITRE: T1110.004 (Credential Stuffing)              │
├─────────────────────────────────────────────────────────┤
│ DT_IMPOSSIBLE_TRAVEL_ALERTS                             │
│   • Trigger: >500km travel in <2 hours                  │
│   • Uses Haversine formula for distance                 │
│   • Filters: requires >800 km/h (faster than planes)    │
│   • MITRE: T1078 (Valid Accounts)                       │
├─────────────────────────────────────────────────────────┤
│ DT_DATA_EXFILTRATION_ALERTS                             │
│   • Trigger: >50 GB scanned in 1 hour                   │
│   • Severity boost if from known threat IP              │
│   • MITRE: T1567 (Exfiltration Over Web Service)        │
├─────────────────────────────────────────────────────────┤
│ DT_PRIVILEGE_ESCALATION_ALERTS                          │
│   • Trigger: GRANT to ACCOUNTADMIN/SECURITYADMIN        │
│   • Always severity 5 (critical)                        │
│   • MITRE: T1078.004 (Cloud Accounts)                   │
└─────────────────────────────────────────────────────────┘
```

**Sample Alert Output:**

```sql
SELECT * FROM DETECTIONS.DT_BRUTE_FORCE_ALERTS LIMIT 1;
```

| alert_id | alert_time | detection_name | severity | entity_id | description |
|----------|------------|----------------|----------|-----------|-------------|
| `abc-123` | `2024-01-15 14:32:00` | `BRUTE_FORCE_ATTEMPT` | `5` | `USER_042` | Detected 50 failed login attempts for user USER_042 from IP 185.220.101.42 (Russia) |

---

### Script 4: Interactive Tables

**File:** `demo/04_interactive_tables.sql`

**What it creates:**

| Table | Type | Purpose | Query Latency |
|-------|------|---------|---------------|
| `IT_ALERT_SUMMARY` | Interactive Table | Real-time alert counts by severity | <100ms |
| `IT_USER_RISK_SCORES` | Interactive Table | Live risk scores per user | <100ms |
| `HT_CASE_MANAGEMENT` | Hybrid Table | Track investigation cases with row-level updates | <50ms |

**Interactive Tables enable:**
- Sub-second dashboard queries (vs 2-5 seconds with regular tables)
- 24-hour minimum auto-suspend warehouse (dedicated compute)
- CLUSTER BY for optimized point lookups

**Hybrid Tables enable:**
- Row-level UPDATE/DELETE for case management
- Enforced PRIMARY KEY constraints
- OLTP-style workloads alongside analytics

---

### Script 5: Streamlit SOC Dashboard

**File:** `demo/05_streamlit_dashboard.py`

**What you see:**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  🔒 Security Operations Center                              Auto-refresh: 30s   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │  🔴 CRITICAL │  │  🟠 HIGH    │  │  🟡 MEDIUM  │  │  🟢 LOW     │        │
│  │      3       │  │      7      │  │     12      │  │     25      │        │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘        │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        ALERTS BY TYPE (24h)                              │   │
│  │  ████████████████████████  Brute Force (15)                             │   │
│  │  ████████████████         Credential Stuffing (12)                      │   │
│  │  ██████████               Impossible Travel (8)                         │   │
│  │  ████████                 Data Exfiltration (6)                         │   │
│  │  ████                     Privilege Escalation (3)                      │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  RECENT ALERTS                                                    [▼]    │   │
│  ├──────────┬────────────────────────┬──────────┬─────────────────────────┤   │
│  │ Severity │ Detection              │ Entity   │ Description             │   │
│  ├──────────┼────────────────────────┼──────────┼─────────────────────────┤   │
│  │ 🔴 5     │ IMPOSSIBLE_TRAVEL      │ USER_017 │ NYC → Moscow in 30 min  │   │
│  │ 🔴 5     │ PRIVILEGE_ESCALATION   │ USER_099 │ GRANT ACCOUNTADMIN      │   │
│  │ 🟠 4     │ BRUTE_FORCE_ATTEMPT    │ USER_042 │ 50 failed logins        │   │
│  │ 🟠 4     │ DATA_EXFILTRATION      │ USER_031 │ 200 GB scanned          │   │
│  │ 🟡 3     │ CREDENTIAL_STUFFING    │ 45.227.* │ 25 users targeted       │   │
│  └──────────┴────────────────────────┴──────────┴─────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  TOP RISKY USERS                                                         │   │
│  │  USER_042 ████████████████████████████████████████ Risk: 95             │   │
│  │  USER_017 ██████████████████████████████          Risk: 78             │   │
│  │  USER_031 ████████████████████████                Risk: 65             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Dashboard features:**
- **Auto-refresh** every 30 seconds using `st.fragment(run_every=30)` (SPCS required)
- **Severity metrics** with color-coded KPI cards
- **Alert breakdown** by detection type
- **Drill-down** to alert details with full evidence JSON
- **Risk scores** per user aggregated from all detections

---

### Running the Demo

**Step 1: Execute SQL Scripts**

```sql
-- Run in Snowflake worksheet (in order)
-- 1. Setup (run as ACCOUNTADMIN)
!source demo/01_setup_security_schema.sql

-- 2. Generate data
!source demo/02_generate_demo_data.sql

-- 3. Create detection pipeline
!source demo/03_detection_pipeline.sql

-- 4. Create Interactive Tables (optional, Enterprise+ required)
!source demo/04_interactive_tables.sql
```

**Step 2: Verify Alerts Generated**

```sql
-- Check that attacks were detected
SELECT detection_name, COUNT(*), MAX(severity) 
FROM SECURITY_OPS.DETECTIONS.DT_BRUTE_FORCE_ALERTS
GROUP BY detection_name
UNION ALL
SELECT detection_name, COUNT(*), MAX(severity) 
FROM SECURITY_OPS.DETECTIONS.DT_CREDENTIAL_STUFFING_ALERTS
GROUP BY detection_name
UNION ALL
SELECT detection_name, COUNT(*), MAX(severity) 
FROM SECURITY_OPS.DETECTIONS.DT_IMPOSSIBLE_TRAVEL_ALERTS
GROUP BY detection_name;
```

**Expected output:**

| detection_name | count | max_severity |
|----------------|-------|--------------|
| BRUTE_FORCE_ATTEMPT | 3 | 5 |
| CREDENTIAL_STUFFING | 2 | 4 |
| IMPOSSIBLE_TRAVEL | 1 | 5 |

**Step 3: Launch Dashboard**

```bash
# Local development
cd demo
streamlit run 05_streamlit_dashboard.py

# Or deploy to SPCS for production with auto-refresh
```

---

## Key Capabilities

### Threat Detection Patterns

| Detection | Technique | MITRE ATT&CK |
|-----------|-----------|--------------|
| Brute Force | Failed logins > threshold per minute | T1110 |
| Credential Stuffing | Multiple users from same IP | T1110.004 |
| Impossible Travel | Logins from distant locations | T1078 |
| Privilege Escalation | Role grants to sensitive roles | T1078.004 |
| Data Exfiltration | Unusual data export volumes | T1567 |
| Anomalous Queries | Deviation from baseline behavior | T1213 |

### Real-Time Infrastructure Options

| Component | Use Case | Latency |
|-----------|----------|---------|
| **Dynamic Tables** | Detection pipelines | 1-5 minutes |
| **Interactive Tables** | Dashboard queries | Sub-second |
| **Hybrid Tables** | Case management, IOC tracking | Milliseconds |
| **Kafka Connector** | High-frequency log ingestion | Milliseconds |
| **SPCS Streamlit** | Real-time SOC dashboards | Sub-second |

### Integration Options

- **SIEM**: Splunk (DB Connect), Sentinel, Chronicle
- **SOAR**: Tines, Torq, Palo Alto XSOAR
- **Ticketing**: ServiceNow, Jira, PagerDuty
- **Communication**: Slack, Teams, Email
- **Threat Intel**: MISP, VirusTotal, AbuseIPDB

## File Structure

```
security_ops_skill/
├── README.md                 # This file
├── SKILL.md                  # Full skill knowledge base (~3600 lines)
└── demo/
    ├── 01_setup_security_schema.sql    # Database, schemas, tables, roles
    ├── 02_generate_demo_data.sql       # 10,000+ events with attack patterns
    ├── 03_detection_pipeline.sql       # 9 Dynamic Tables, 5 detections
    ├── 04_interactive_tables.sql       # Sub-second query tables
    └── 05_streamlit_dashboard.py       # Real-time SOC dashboard
```

## Requirements

- Snowflake Enterprise Edition or higher
- ACCOUNTADMIN or SECURITYADMIN role for setup
- Access to SNOWFLAKE.ACCOUNT_USAGE schema
- Cortex Code for AI-assisted analysis

## Resources

- [Dynamic Tables Documentation](https://docs.snowflake.com/en/user-guide/dynamic-tables-about)
- [Interactive Tables Documentation](https://docs.snowflake.com/en/user-guide/interactive)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [nanocortex - Custom Cortex Agent](https://github.com/sfc-gh-kkeller/nanocortex)

## License

MIT License - See LICENSE file for details.

---

**AI-Powered Security Operations** | Powered by Cortex Code
