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
│  │  Snowpipe Streaming │ OpenFlow (NiFi) │ Snowflake Postgres CDC │ Kafka    │ │
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

## Quick Start

### 1. Set Up the Security Schema

```sql
-- Run the demo setup script
-- See: demo/01_setup_security_schema.sql
```

### 2. Generate Demo Data

```sql
-- Populate with realistic security events
-- See: demo/02_generate_demo_data.sql
```

### 3. Create Detection Pipeline

```sql
-- Build Dynamic Table detection pipeline
-- See: demo/03_detection_pipeline.sql
```

### 4. Query with Cortex Code

Open Cortex Code and ask:

```
"Show me failed login attempts in the last hour grouped by user"

"Are there any brute force attacks happening right now?"

"Which users have the most privilege escalation events?"

"Create a detection for impossible travel based on login locations"
```

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
| **Snowflake Postgres** | High-frequency log ingestion | Milliseconds |
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
├── SKILL.md                  # Full skill knowledge base
└── demo/
    ├── 01_setup_security_schema.sql
    ├── 02_generate_demo_data.sql
    ├── 03_detection_pipeline.sql
    ├── 04_interactive_tables.sql
    └── 05_streamlit_dashboard.py
```

## Sample Queries

### Threat Hunting

```sql
-- Find users with anomalous query patterns
SELECT 
    user_name,
    COUNT(*) as query_count,
    COUNT(DISTINCT warehouse_name) as warehouses_used,
    SUM(bytes_scanned) / 1e9 as gb_scanned
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
GROUP BY user_name
HAVING gb_scanned > 100
ORDER BY gb_scanned DESC;
```

### Access Analysis

```sql
-- Users with failed logins followed by success (potential compromise)
WITH login_sequences AS (
    SELECT 
        user_name,
        event_timestamp,
        is_success,
        LAG(is_success) OVER (PARTITION BY user_name ORDER BY event_timestamp) as prev_success
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE event_timestamp > DATEADD('day', -1, CURRENT_TIMESTAMP())
)
SELECT DISTINCT user_name
FROM login_sequences
WHERE is_success = TRUE AND prev_success = FALSE;
```

### Privilege Monitoring

```sql
-- Recent privilege escalations
SELECT 
    query_start_time,
    user_name,
    role_name,
    query_text
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GRANT'
  AND query_text ILIKE '%ACCOUNTADMIN%'
  AND query_start_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY query_start_time DESC;
```

## Requirements

- Snowflake Enterprise Edition or higher
- ACCOUNTADMIN or SECURITYADMIN role for setup
- Access to SNOWFLAKE.ACCOUNT_USAGE schema
- Cortex Code for AI-assisted analysis

## Resources

- [Snowflake Security Best Practices](https://docs.snowflake.com/en/user-guide/security-best-practices)
- [Dynamic Tables Documentation](https://docs.snowflake.com/en/user-guide/dynamic-tables-about)
- [Interactive Tables Documentation](https://docs.snowflake.com/en/user-guide/interactive)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [nanocortex - Custom Cortex Agent](https://github.com/sfc-gh-kkeller/nanocortex)

## License

MIT License - See LICENSE file for details.

---

**Built for Snowflake Security Operations** | Powered by Cortex Code
