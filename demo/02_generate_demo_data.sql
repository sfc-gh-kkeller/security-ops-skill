/*
=============================================================================
Generate Demo Security Data
=============================================================================
Creates realistic security event data for testing detection pipelines.
Includes normal activity and injected attack patterns.
=============================================================================
*/

USE DATABASE SECURITY_OPS;
USE SCHEMA RAW;

-- =============================================================================
-- GENERATE LOGIN EVENTS (7 days of data)
-- =============================================================================

-- Normal successful logins
INSERT INTO LOGIN_EVENTS (
    event_timestamp, user_name, client_ip, client_type,
    authentication_method, is_success, error_code, error_message,
    geo_country, geo_city, geo_lat, geo_lon
)
SELECT
    DATEADD('minute', -UNIFORM(1, 10080, RANDOM()), CURRENT_TIMESTAMP()) AS event_timestamp,
    'USER_' || LPAD(UNIFORM(1, 50, RANDOM())::VARCHAR, 3, '0') AS user_name,
    '10.0.' || UNIFORM(1, 255, RANDOM()) || '.' || UNIFORM(1, 255, RANDOM()) AS client_ip,
    CASE UNIFORM(1, 4, RANDOM())
        WHEN 1 THEN 'SNOWFLAKE_UI'
        WHEN 2 THEN 'PYTHON_DRIVER'
        WHEN 3 THEN 'JDBC_DRIVER'
        ELSE 'ODBC_DRIVER'
    END AS client_type,
    CASE UNIFORM(1, 3, RANDOM())
        WHEN 1 THEN 'PASSWORD'
        WHEN 2 THEN 'OAUTH'
        ELSE 'KEY_PAIR'
    END AS authentication_method,
    TRUE AS is_success,
    NULL AS error_code,
    NULL AS error_message,
    'United States' AS geo_country,
    CASE UNIFORM(1, 5, RANDOM())
        WHEN 1 THEN 'San Francisco'
        WHEN 2 THEN 'New York'
        WHEN 3 THEN 'Chicago'
        WHEN 4 THEN 'Seattle'
        ELSE 'Austin'
    END AS geo_city,
    37.7749 + (RANDOM() * 10 - 5) AS geo_lat,
    -122.4194 + (RANDOM() * 20 - 10) AS geo_lon
FROM TABLE(GENERATOR(ROWCOUNT => 5000));

-- Inject BRUTE FORCE attack pattern (many failed logins from same IP)
INSERT INTO LOGIN_EVENTS (
    event_timestamp, user_name, client_ip, client_type,
    authentication_method, is_success, error_code, error_message,
    geo_country, geo_city, geo_lat, geo_lon
)
SELECT
    DATEADD('second', seq4() * 3, DATEADD('hour', -2, CURRENT_TIMESTAMP())) AS event_timestamp,
    'USER_042' AS user_name,  -- Target user
    '185.220.101.42' AS client_ip,  -- Attacker IP (Tor exit node pattern)
    'PYTHON_DRIVER' AS client_type,
    'PASSWORD' AS authentication_method,
    FALSE AS is_success,
    'INCORRECT_PASSWORD' AS error_code,
    'Incorrect username or password was specified.' AS error_message,
    'Russia' AS geo_country,
    'Moscow' AS geo_city,
    55.7558 AS geo_lat,
    37.6173 AS geo_lon
FROM TABLE(GENERATOR(ROWCOUNT => 50));

-- Successful login after brute force (compromise indicator)
INSERT INTO LOGIN_EVENTS (
    event_timestamp, user_name, client_ip, client_type,
    authentication_method, is_success, error_code, error_message,
    geo_country, geo_city, geo_lat, geo_lon
)
VALUES (
    DATEADD('minute', -90, CURRENT_TIMESTAMP()),
    'USER_042',
    '185.220.101.42',
    'PYTHON_DRIVER',
    'PASSWORD',
    TRUE,
    NULL,
    NULL,
    'Russia',
    'Moscow',
    55.7558,
    37.6173
);

-- Inject CREDENTIAL STUFFING pattern (same IP, multiple users)
INSERT INTO LOGIN_EVENTS (
    event_timestamp, user_name, client_ip, client_type,
    authentication_method, is_success, error_code, error_message,
    geo_country, geo_city, geo_lat, geo_lon
)
SELECT
    DATEADD('second', seq4() * 5, DATEADD('hour', -4, CURRENT_TIMESTAMP())) AS event_timestamp,
    'USER_' || LPAD((seq4() % 30 + 1)::VARCHAR, 3, '0') AS user_name,
    '45.33.32.156' AS client_ip,  -- Single attacker IP
    'PYTHON_DRIVER' AS client_type,
    'PASSWORD' AS authentication_method,
    CASE WHEN RANDOM() > 0.9 THEN TRUE ELSE FALSE END AS is_success,
    CASE WHEN RANDOM() > 0.9 THEN NULL ELSE 'INCORRECT_PASSWORD' END AS error_code,
    CASE WHEN RANDOM() > 0.9 THEN NULL ELSE 'Incorrect username or password was specified.' END AS error_message,
    'Netherlands' AS geo_country,
    'Amsterdam' AS geo_city,
    52.3676 AS geo_lat,
    4.9041 AS geo_lon
FROM TABLE(GENERATOR(ROWCOUNT => 60));

-- Inject IMPOSSIBLE TRAVEL pattern
INSERT INTO LOGIN_EVENTS (
    event_timestamp, user_name, client_ip, client_type,
    authentication_method, is_success, error_code, error_message,
    geo_country, geo_city, geo_lat, geo_lon
)
VALUES
    -- Login from NYC
    (DATEADD('hour', -3, CURRENT_TIMESTAMP()), 'USER_015', '72.21.198.66', 'SNOWFLAKE_UI', 'PASSWORD', TRUE, NULL, NULL, 'United States', 'New York', 40.7128, -74.0060),
    -- Login from Tokyo 2 hours later (impossible!)
    (DATEADD('hour', -1, CURRENT_TIMESTAMP()), 'USER_015', '103.5.140.99', 'SNOWFLAKE_UI', 'PASSWORD', TRUE, NULL, NULL, 'Japan', 'Tokyo', 35.6762, 139.6503);

-- =============================================================================
-- GENERATE QUERY EVENTS
-- =============================================================================

-- Normal query activity
INSERT INTO QUERY_EVENTS (
    query_id, query_start_time, query_end_time, user_name, role_name,
    warehouse_name, database_name, schema_name, query_type, query_text,
    rows_produced, bytes_scanned, execution_status, client_ip
)
SELECT
    UUID_STRING() AS query_id,
    ts AS query_start_time,
    DATEADD('second', UNIFORM(1, 60, RANDOM()), ts) AS query_end_time,
    'USER_' || LPAD(UNIFORM(1, 50, RANDOM())::VARCHAR, 3, '0') AS user_name,
    CASE UNIFORM(1, 5, RANDOM())
        WHEN 1 THEN 'ANALYST_ROLE'
        WHEN 2 THEN 'DATA_ENGINEER'
        WHEN 3 THEN 'DEVELOPER'
        WHEN 4 THEN 'VIEWER'
        ELSE 'PUBLIC'
    END AS role_name,
    'COMPUTE_WH' AS warehouse_name,
    'ANALYTICS_DB' AS database_name,
    'PUBLIC' AS schema_name,
    CASE UNIFORM(1, 5, RANDOM())
        WHEN 1 THEN 'SELECT'
        WHEN 2 THEN 'INSERT'
        WHEN 3 THEN 'UPDATE'
        WHEN 4 THEN 'CREATE_TABLE'
        ELSE 'DESCRIBE'
    END AS query_type,
    'SELECT * FROM sample_table LIMIT 100' AS query_text,
    UNIFORM(1, 10000, RANDOM()) AS rows_produced,
    UNIFORM(1000000, 100000000, RANDOM()) AS bytes_scanned,
    'SUCCESS' AS execution_status,
    '10.0.' || UNIFORM(1, 255, RANDOM()) || '.' || UNIFORM(1, 255, RANDOM()) AS client_ip
FROM (
    SELECT DATEADD('minute', -UNIFORM(1, 10080, RANDOM()), CURRENT_TIMESTAMP()) AS ts
    FROM TABLE(GENERATOR(ROWCOUNT => 3000))
);

-- Inject DATA EXFILTRATION pattern (large data export)
INSERT INTO QUERY_EVENTS (
    query_id, query_start_time, query_end_time, user_name, role_name,
    warehouse_name, database_name, schema_name, query_type, query_text,
    rows_produced, bytes_scanned, execution_status, client_ip
)
SELECT
    UUID_STRING() AS query_id,
    DATEADD('minute', seq4() * 2, DATEADD('hour', -6, CURRENT_TIMESTAMP())) AS query_start_time,
    DATEADD('minute', seq4() * 2 + 5, DATEADD('hour', -6, CURRENT_TIMESTAMP())) AS query_end_time,
    'USER_042' AS user_name,  -- Compromised user
    'DATA_ENGINEER' AS role_name,
    'COMPUTE_WH' AS warehouse_name,
    'CUSTOMER_DB' AS database_name,
    'PII' AS schema_name,
    'SELECT' AS query_type,
    'COPY INTO @external_stage/customers_' || seq4() || '.csv FROM CUSTOMER_DB.PII.CUSTOMERS' AS query_text,
    5000000 AS rows_produced,
    50000000000 AS bytes_scanned,  -- 50GB per query
    'SUCCESS' AS execution_status,
    '185.220.101.42' AS client_ip  -- Same attacker IP
FROM TABLE(GENERATOR(ROWCOUNT => 10));

-- Inject PRIVILEGE ESCALATION pattern
INSERT INTO QUERY_EVENTS (
    query_id, query_start_time, query_end_time, user_name, role_name,
    warehouse_name, database_name, schema_name, query_type, query_text,
    rows_produced, bytes_scanned, execution_status, client_ip
)
VALUES
    (UUID_STRING(), DATEADD('hour', -5, CURRENT_TIMESTAMP()), DATEADD('hour', -5, CURRENT_TIMESTAMP()), 'USER_042', 'USERADMIN', 'COMPUTE_WH', NULL, NULL, 'GRANT', 'GRANT ROLE ACCOUNTADMIN TO USER USER_042', 0, 0, 'SUCCESS', '185.220.101.42'),
    (UUID_STRING(), DATEADD('hour', -4, CURRENT_TIMESTAMP()), DATEADD('hour', -4, CURRENT_TIMESTAMP()), 'USER_042', 'ACCOUNTADMIN', 'COMPUTE_WH', NULL, NULL, 'GRANT', 'GRANT ALL PRIVILEGES ON DATABASE CUSTOMER_DB TO ROLE PUBLIC', 0, 0, 'SUCCESS', '185.220.101.42');

-- =============================================================================
-- GENERATE ACCESS EVENTS
-- =============================================================================

INSERT INTO ACCESS_EVENTS (
    event_timestamp, user_name, role_name, action_type, object_type,
    object_name, database_name, schema_name, columns_accessed, rows_accessed, client_ip
)
SELECT
    DATEADD('minute', -UNIFORM(1, 10080, RANDOM()), CURRENT_TIMESTAMP()) AS event_timestamp,
    'USER_' || LPAD(UNIFORM(1, 50, RANDOM())::VARCHAR, 3, '0') AS user_name,
    CASE UNIFORM(1, 4, RANDOM())
        WHEN 1 THEN 'ANALYST_ROLE'
        WHEN 2 THEN 'DATA_ENGINEER'
        WHEN 3 THEN 'DEVELOPER'
        ELSE 'VIEWER'
    END AS role_name,
    'SELECT' AS action_type,
    'TABLE' AS object_type,
    'SAMPLE_TABLE_' || UNIFORM(1, 10, RANDOM()) AS object_name,
    'ANALYTICS_DB' AS database_name,
    'PUBLIC' AS schema_name,
    ARRAY_CONSTRUCT('col1', 'col2', 'col3') AS columns_accessed,
    UNIFORM(100, 100000, RANDOM()) AS rows_accessed,
    '10.0.' || UNIFORM(1, 255, RANDOM()) || '.' || UNIFORM(1, 255, RANDOM()) AS client_ip
FROM TABLE(GENERATOR(ROWCOUNT => 2000));

-- Inject PII ACCESS pattern (sensitive column access)
INSERT INTO ACCESS_EVENTS (
    event_timestamp, user_name, role_name, action_type, object_type,
    object_name, database_name, schema_name, columns_accessed, rows_accessed, client_ip
)
SELECT
    DATEADD('minute', seq4() * 5, DATEADD('hour', -6, CURRENT_TIMESTAMP())) AS event_timestamp,
    'USER_042' AS user_name,
    'DATA_ENGINEER' AS role_name,
    'SELECT' AS action_type,
    'TABLE' AS object_type,
    'CUSTOMERS' AS object_name,
    'CUSTOMER_DB' AS database_name,
    'PII' AS schema_name,
    ARRAY_CONSTRUCT('SSN', 'CREDIT_CARD', 'EMAIL', 'PHONE', 'ADDRESS') AS columns_accessed,
    5000000 AS rows_accessed,
    '185.220.101.42' AS client_ip
FROM TABLE(GENERATOR(ROWCOUNT => 10));

-- =============================================================================
-- ADD THREAT INDICATORS
-- =============================================================================

INSERT INTO REFERENCE.THREAT_INDICATORS (
    indicator_value, indicator_type, threat_type, threat_actor,
    confidence_score, severity, source, first_seen, last_seen, tags
)
VALUES
    ('185.220.101.42', 'ip', 'C2', 'APT29', 0.95, 'CRITICAL', 'Threat Intel Feed', DATEADD('day', -30, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP(), ARRAY_CONSTRUCT('tor', 'apt', 'russia')),
    ('45.33.32.156', 'ip', 'Scanner', 'Unknown', 0.80, 'HIGH', 'Abuse DB', DATEADD('day', -7, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP(), ARRAY_CONSTRUCT('scanner', 'brute-force')),
    ('malware-domain.evil', 'domain', 'Malware', 'Emotet', 0.90, 'CRITICAL', 'VirusTotal', DATEADD('day', -14, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP(), ARRAY_CONSTRUCT('malware', 'emotet')),
    ('a1b2c3d4e5f6', 'hash', 'Malware', 'Cobalt Strike', 0.85, 'HIGH', 'MISP', DATEADD('day', -21, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP(), ARRAY_CONSTRUCT('cobalt-strike', 'beacon'));

-- =============================================================================
-- SUMMARY
-- =============================================================================

SELECT 'Demo data generation complete!' AS status;

SELECT 'LOGIN_EVENTS' AS table_name, COUNT(*) AS row_count FROM RAW.LOGIN_EVENTS
UNION ALL
SELECT 'QUERY_EVENTS', COUNT(*) FROM RAW.QUERY_EVENTS
UNION ALL
SELECT 'ACCESS_EVENTS', COUNT(*) FROM RAW.ACCESS_EVENTS
UNION ALL
SELECT 'THREAT_INDICATORS', COUNT(*) FROM REFERENCE.THREAT_INDICATORS;
