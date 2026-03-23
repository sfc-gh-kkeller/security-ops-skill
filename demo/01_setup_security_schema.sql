/*
=============================================================================
Security Operations Schema Setup
=============================================================================
Creates the foundational schema, tables, and objects for a Security Data Lake.
Run with ACCOUNTADMIN or SECURITYADMIN role.
=============================================================================
*/

-- Use appropriate role and warehouse
USE ROLE ACCOUNTADMIN;
CREATE WAREHOUSE IF NOT EXISTS SECURITY_WH 
    WAREHOUSE_SIZE = 'SMALL' 
    AUTO_SUSPEND = 60 
    AUTO_RESUME = TRUE;
USE WAREHOUSE SECURITY_WH;

-- Create security database and schemas
CREATE DATABASE IF NOT EXISTS SECURITY_OPS;
USE DATABASE SECURITY_OPS;

CREATE SCHEMA IF NOT EXISTS RAW;           -- Raw ingested logs
CREATE SCHEMA IF NOT EXISTS STAGING;       -- Normalized/cleaned data
CREATE SCHEMA IF NOT EXISTS ENRICHED;      -- Enriched with context
CREATE SCHEMA IF NOT EXISTS DETECTIONS;    -- Detection outputs
CREATE SCHEMA IF NOT EXISTS REFERENCE;     -- Lookup tables, threat intel

-- =============================================================================
-- RAW TABLES - Landing zone for ingested logs
-- =============================================================================

CREATE OR REPLACE TABLE RAW.LOGIN_EVENTS (
    event_id VARCHAR(36) DEFAULT UUID_STRING(),
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    event_timestamp TIMESTAMP_NTZ,
    user_name VARCHAR(255),
    client_ip VARCHAR(45),
    client_type VARCHAR(100),
    authentication_method VARCHAR(50),
    is_success BOOLEAN,
    error_code VARCHAR(50),
    error_message VARCHAR(1000),
    user_agent VARCHAR(500),
    geo_country VARCHAR(100),
    geo_city VARCHAR(100),
    geo_lat FLOAT,
    geo_lon FLOAT,
    raw_event VARIANT
);

CREATE OR REPLACE TABLE RAW.QUERY_EVENTS (
    event_id VARCHAR(36) DEFAULT UUID_STRING(),
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    query_id VARCHAR(36),
    query_start_time TIMESTAMP_NTZ,
    query_end_time TIMESTAMP_NTZ,
    user_name VARCHAR(255),
    role_name VARCHAR(255),
    warehouse_name VARCHAR(255),
    database_name VARCHAR(255),
    schema_name VARCHAR(255),
    query_type VARCHAR(50),
    query_text VARCHAR(100000),
    rows_produced NUMBER,
    bytes_scanned NUMBER,
    execution_status VARCHAR(50),
    error_code VARCHAR(50),
    error_message VARCHAR(1000),
    client_ip VARCHAR(45)
);

CREATE OR REPLACE TABLE RAW.ACCESS_EVENTS (
    event_id VARCHAR(36) DEFAULT UUID_STRING(),
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    event_timestamp TIMESTAMP_NTZ,
    user_name VARCHAR(255),
    role_name VARCHAR(255),
    action_type VARCHAR(50),
    object_type VARCHAR(50),
    object_name VARCHAR(500),
    database_name VARCHAR(255),
    schema_name VARCHAR(255),
    columns_accessed ARRAY,
    rows_accessed NUMBER,
    client_ip VARCHAR(45)
);

-- =============================================================================
-- REFERENCE TABLES - Threat intel and lookups
-- =============================================================================

CREATE OR REPLACE TABLE REFERENCE.THREAT_INDICATORS (
    indicator_id VARCHAR(36) DEFAULT UUID_STRING(),
    indicator_value VARCHAR(500) NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,  -- ip, domain, hash, email, user
    threat_type VARCHAR(100),
    threat_actor VARCHAR(200),
    confidence_score FLOAT,
    severity VARCHAR(20),
    source VARCHAR(200),
    first_seen TIMESTAMP_NTZ,
    last_seen TIMESTAMP_NTZ,
    is_active BOOLEAN DEFAULT TRUE,
    tags ARRAY,
    metadata VARIANT,
    created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE OR REPLACE TABLE REFERENCE.SENSITIVE_ROLES (
    role_name VARCHAR(255) PRIMARY KEY,
    sensitivity_level VARCHAR(20),  -- CRITICAL, HIGH, MEDIUM, LOW
    description VARCHAR(1000),
    requires_approval BOOLEAN DEFAULT FALSE
);

INSERT INTO REFERENCE.SENSITIVE_ROLES VALUES
    ('ACCOUNTADMIN', 'CRITICAL', 'Full account administration privileges', TRUE),
    ('SECURITYADMIN', 'CRITICAL', 'Security and access control management', TRUE),
    ('SYSADMIN', 'HIGH', 'System administration and object management', TRUE),
    ('USERADMIN', 'HIGH', 'User and role management', TRUE),
    ('ORGADMIN', 'CRITICAL', 'Organization-level administration', TRUE);

CREATE OR REPLACE TABLE REFERENCE.KNOWN_GOOD_IPS (
    ip_address VARCHAR(45) PRIMARY KEY,
    description VARCHAR(500),
    owner VARCHAR(200),
    added_by VARCHAR(255),
    added_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE OR REPLACE TABLE REFERENCE.MITRE_TECHNIQUES (
    technique_id VARCHAR(20) PRIMARY KEY,
    technique_name VARCHAR(200),
    tactic VARCHAR(100),
    description VARCHAR(2000),
    detection_notes VARCHAR(2000),
    url VARCHAR(500)
);

INSERT INTO REFERENCE.MITRE_TECHNIQUES VALUES
    ('T1110', 'Brute Force', 'Credential Access', 'Adversaries may use brute force techniques to gain access to accounts', 'Monitor for multiple failed authentication attempts', 'https://attack.mitre.org/techniques/T1110/'),
    ('T1110.001', 'Password Guessing', 'Credential Access', 'Adversaries may guess passwords to attempt access', 'Monitor for failed logins with common passwords', 'https://attack.mitre.org/techniques/T1110/001/'),
    ('T1110.003', 'Password Spraying', 'Credential Access', 'Adversaries may spray passwords across many accounts', 'Monitor for single password across multiple users', 'https://attack.mitre.org/techniques/T1110/003/'),
    ('T1078', 'Valid Accounts', 'Defense Evasion', 'Adversaries may use compromised credentials', 'Monitor for anomalous account usage', 'https://attack.mitre.org/techniques/T1078/'),
    ('T1078.004', 'Cloud Accounts', 'Defense Evasion', 'Adversaries may use compromised cloud accounts', 'Monitor for unusual cloud account activity', 'https://attack.mitre.org/techniques/T1078/004/'),
    ('T1567', 'Exfiltration Over Web Service', 'Exfiltration', 'Adversaries may exfiltrate data over web services', 'Monitor for unusual data transfer volumes', 'https://attack.mitre.org/techniques/T1567/'),
    ('T1213', 'Data from Information Repositories', 'Collection', 'Adversaries may collect data from repositories', 'Monitor for bulk data access patterns', 'https://attack.mitre.org/techniques/T1213/');

-- =============================================================================
-- DETECTION OUTPUT TABLES
-- =============================================================================

CREATE OR REPLACE TABLE DETECTIONS.ALERTS (
    alert_id VARCHAR(36) DEFAULT UUID_STRING(),
    created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    alert_time TIMESTAMP_NTZ,
    detection_name VARCHAR(200),
    detection_type VARCHAR(100),
    severity INT,  -- 1-5 (1=info, 5=critical)
    entity_type VARCHAR(50),
    entity_id VARCHAR(500),
    description VARCHAR(2000),
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(20),
    evidence VARIANT,
    status VARCHAR(50) DEFAULT 'NEW',
    assigned_to VARCHAR(255),
    resolved_at TIMESTAMP_NTZ,
    resolution_notes VARCHAR(2000)
);

CREATE OR REPLACE TABLE DETECTIONS.INCIDENTS (
    incident_id VARCHAR(36) DEFAULT UUID_STRING(),
    created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    title VARCHAR(500),
    description VARCHAR(5000),
    severity INT,
    status VARCHAR(50) DEFAULT 'OPEN',
    assigned_to VARCHAR(255),
    related_alerts ARRAY,
    affected_users ARRAY,
    affected_systems ARRAY,
    timeline VARIANT,
    root_cause VARCHAR(2000),
    remediation_steps VARCHAR(5000),
    resolved_at TIMESTAMP_NTZ,
    lessons_learned VARCHAR(5000)
);

-- =============================================================================
-- GRANTS - Set up security roles
-- =============================================================================

CREATE ROLE IF NOT EXISTS SECURITY_ANALYST;
CREATE ROLE IF NOT EXISTS SECURITY_ENGINEER;
CREATE ROLE IF NOT EXISTS SOC_VIEWER;

-- Analyst can read and investigate
GRANT USAGE ON DATABASE SECURITY_OPS TO ROLE SECURITY_ANALYST;
GRANT USAGE ON ALL SCHEMAS IN DATABASE SECURITY_OPS TO ROLE SECURITY_ANALYST;
GRANT SELECT ON ALL TABLES IN DATABASE SECURITY_OPS TO ROLE SECURITY_ANALYST;
GRANT SELECT ON FUTURE TABLES IN DATABASE SECURITY_OPS TO ROLE SECURITY_ANALYST;

-- Engineer can create detections and modify reference data
GRANT ROLE SECURITY_ANALYST TO ROLE SECURITY_ENGINEER;
GRANT CREATE TABLE ON SCHEMA SECURITY_OPS.DETECTIONS TO ROLE SECURITY_ENGINEER;
GRANT CREATE DYNAMIC TABLE ON SCHEMA SECURITY_OPS.DETECTIONS TO ROLE SECURITY_ENGINEER;
GRANT INSERT, UPDATE ON ALL TABLES IN SCHEMA SECURITY_OPS.REFERENCE TO ROLE SECURITY_ENGINEER;

-- SOC Viewer - read-only for dashboards
GRANT USAGE ON DATABASE SECURITY_OPS TO ROLE SOC_VIEWER;
GRANT USAGE ON SCHEMA SECURITY_OPS.DETECTIONS TO ROLE SOC_VIEWER;
GRANT SELECT ON ALL TABLES IN SCHEMA SECURITY_OPS.DETECTIONS TO ROLE SOC_VIEWER;

SELECT 'Security schema setup complete!' AS status;
