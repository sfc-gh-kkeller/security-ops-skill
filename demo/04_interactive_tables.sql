/*
=============================================================================
Interactive Tables for SOC Dashboard
=============================================================================
Creates Interactive Tables optimized for sub-second dashboard queries.
Requires Interactive Warehouse for optimal performance.
=============================================================================
*/

USE DATABASE SECURITY_OPS;
USE WAREHOUSE SECURITY_WH;

-- =============================================================================
-- INTERACTIVE TABLES FOR DASHBOARDS
-- =============================================================================

-- Interactive Table: Active Alerts (last 24 hours)
CREATE OR REPLACE INTERACTIVE TABLE DETECTIONS.IT_ACTIVE_ALERTS
    CLUSTER BY (alert_time, severity)
    TARGET_LAG = '1 minute'
    WAREHOUSE = SECURITY_WH
AS
SELECT
    alert_id,
    created_at,
    alert_time,
    detection_name,
    detection_type,
    severity,
    entity_type,
    entity_id,
    description,
    mitre_tactic,
    mitre_technique,
    evidence
FROM DETECTIONS.V_ALL_ALERTS
WHERE alert_time > DATEADD('day', -1, CURRENT_TIMESTAMP());

-- Add Search Optimization for fast entity lookups
ALTER TABLE DETECTIONS.IT_ACTIVE_ALERTS 
    ADD SEARCH OPTIMIZATION ON EQUALITY(entity_id, detection_name);


-- Interactive Table: Threat Indicators for IOC Lookups
CREATE OR REPLACE INTERACTIVE TABLE REFERENCE.IT_THREAT_INDICATORS
    CLUSTER BY (indicator_type, indicator_value)
AS
SELECT
    indicator_id,
    indicator_value,
    indicator_type,
    threat_type,
    threat_actor,
    confidence_score,
    severity,
    source,
    first_seen,
    last_seen,
    is_active,
    tags
FROM REFERENCE.THREAT_INDICATORS
WHERE is_active = TRUE;

-- Add Search Optimization for IOC lookups
ALTER TABLE REFERENCE.IT_THREAT_INDICATORS 
    ADD SEARCH OPTIMIZATION ON EQUALITY(indicator_value);


-- Interactive Table: Login Activity Summary
CREATE OR REPLACE INTERACTIVE TABLE ENRICHED.IT_LOGIN_SUMMARY
    CLUSTER BY (hour_bucket, user_name)
    TARGET_LAG = '2 minutes'
    WAREHOUSE = SECURITY_WH
AS
SELECT
    hour_bucket,
    user_name,
    COUNT(*) AS total_logins,
    SUM(CASE WHEN is_success THEN 1 ELSE 0 END) AS successful_logins,
    SUM(CASE WHEN NOT is_success THEN 1 ELSE 0 END) AS failed_logins,
    COUNT(DISTINCT client_ip) AS unique_ips,
    COUNT(DISTINCT geo_country) AS unique_countries,
    ARRAY_AGG(DISTINCT geo_country) AS countries,
    MAX(CASE WHEN is_known_threat_ip THEN TRUE ELSE FALSE END) AS has_threat_ip
FROM ENRICHED.DT_ENRICHED_LOGINS
WHERE hour_bucket > DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY 1, 2;


-- =============================================================================
-- INTERACTIVE WAREHOUSE FOR SOC DASHBOARD
-- =============================================================================

-- Create Interactive Warehouse (run with ACCOUNTADMIN)
CREATE OR REPLACE INTERACTIVE WAREHOUSE SOC_DASHBOARD_WH
    TABLES (
        DETECTIONS.IT_ACTIVE_ALERTS,
        REFERENCE.IT_THREAT_INDICATORS,
        ENRICHED.IT_LOGIN_SUMMARY
    )
    WAREHOUSE_SIZE = 'SMALL'
    AUTO_SUSPEND = 86400  -- 24 hours minimum
    AUTO_RESUME = TRUE;

-- Resume the warehouse to warm cache
ALTER WAREHOUSE SOC_DASHBOARD_WH RESUME;

-- =============================================================================
-- SAMPLE DASHBOARD QUERIES (run with SOC_DASHBOARD_WH)
-- =============================================================================

-- Switch to interactive warehouse
USE WAREHOUSE SOC_DASHBOARD_WH;

-- Query 1: Alert summary by severity (sub-second)
SELECT 
    severity,
    COUNT(*) AS alert_count,
    COUNT(DISTINCT entity_id) AS unique_entities
FROM DETECTIONS.IT_ACTIVE_ALERTS
WHERE alert_time > DATEADD('hour', -6, CURRENT_TIMESTAMP())
GROUP BY severity
ORDER BY severity DESC;

-- Query 2: Critical alerts feed (sub-second)
SELECT 
    alert_time,
    detection_name,
    entity_id,
    description
FROM DETECTIONS.IT_ACTIVE_ALERTS
WHERE severity >= 4
  AND alert_time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
ORDER BY alert_time DESC
LIMIT 50;

-- Query 3: IOC lookup (sub-second with Search Optimization)
SELECT * 
FROM REFERENCE.IT_THREAT_INDICATORS
WHERE indicator_value = '185.220.101.42';

-- Query 4: User with most alerts (sub-second)
SELECT 
    entity_id AS user_name,
    COUNT(*) AS alert_count,
    ARRAY_AGG(DISTINCT detection_name) AS detection_types
FROM DETECTIONS.IT_ACTIVE_ALERTS
WHERE entity_type = 'user'
GROUP BY entity_id
ORDER BY alert_count DESC
LIMIT 10;

-- Query 5: Login anomalies (sub-second)
SELECT 
    user_name,
    SUM(failed_logins) AS total_failed,
    SUM(successful_logins) AS total_success,
    MAX(unique_countries) AS max_countries,
    MAX(has_threat_ip) AS threat_ip_detected
FROM ENRICHED.IT_LOGIN_SUMMARY
WHERE hour_bucket > DATEADD('hour', -24, CURRENT_TIMESTAMP())
GROUP BY user_name
HAVING SUM(failed_logins) > 5 OR MAX(has_threat_ip) = TRUE
ORDER BY total_failed DESC;

-- =============================================================================
-- HYBRID TABLE FOR CASE MANAGEMENT
-- =============================================================================

-- Switch back to standard warehouse for Hybrid Table creation
USE WAREHOUSE SECURITY_WH;

-- Create Hybrid Table for incident case management (OLTP workload)
CREATE OR REPLACE HYBRID TABLE DETECTIONS.INCIDENT_CASES (
    case_id VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    title VARCHAR(500) NOT NULL,
    description VARCHAR(5000),
    severity INT NOT NULL,
    status VARCHAR(20) DEFAULT 'OPEN',
    assigned_to VARCHAR(255),
    related_alert_ids ARRAY,
    affected_users ARRAY,
    timeline VARIANT,
    resolution_notes VARCHAR(5000),
    resolved_at TIMESTAMP_NTZ,
    CONSTRAINT chk_severity CHECK (severity BETWEEN 1 AND 5),
    CONSTRAINT chk_status CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'))
);

-- Create Hybrid Table for IOC match queue (high-concurrency writes)
CREATE OR REPLACE HYBRID TABLE DETECTIONS.IOC_MATCH_QUEUE (
    match_id VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    matched_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    source_event_id VARCHAR(36) NOT NULL,
    source_table VARCHAR(200),
    matched_indicator VARCHAR(500) NOT NULL,
    indicator_type VARCHAR(50),
    threat_actor VARCHAR(200),
    confidence_score FLOAT,
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMP_NTZ,
    alert_id VARCHAR(36),
    INDEX idx_unprocessed (processed) WHERE processed = FALSE
);

-- =============================================================================
-- SAMPLE CASE MANAGEMENT OPERATIONS
-- =============================================================================

-- Insert a new case from alert
INSERT INTO DETECTIONS.INCIDENT_CASES (
    title, 
    description, 
    severity, 
    assigned_to,
    related_alert_ids
)
SELECT
    'Potential Compromise: ' || entity_id AS title,
    description,
    severity,
    'soc-analyst@company.com' AS assigned_to,
    ARRAY_AGG(alert_id) AS related_alert_ids
FROM DETECTIONS.IT_ACTIVE_ALERTS
WHERE severity >= 4
  AND entity_id = 'USER_042'
GROUP BY entity_id, description, severity;

-- Update case status (fast with Hybrid Table)
UPDATE DETECTIONS.INCIDENT_CASES
SET 
    status = 'IN_PROGRESS',
    updated_at = CURRENT_TIMESTAMP()
WHERE case_id = (SELECT MAX(case_id) FROM DETECTIONS.INCIDENT_CASES);

-- View open cases
SELECT 
    case_id,
    title,
    severity,
    status,
    assigned_to,
    created_at
FROM DETECTIONS.INCIDENT_CASES
WHERE status IN ('OPEN', 'IN_PROGRESS')
ORDER BY severity DESC, created_at;

SELECT 'Interactive tables and case management setup complete!' AS status;
