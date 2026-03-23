/*
=============================================================================
Security Detection Pipeline with Dynamic Tables
=============================================================================
Creates a 3-stage detection pipeline using Dynamic Tables for continuous
threat detection with configurable latency.
=============================================================================
*/

USE DATABASE SECURITY_OPS;
USE WAREHOUSE SECURITY_WH;

-- =============================================================================
-- STAGE 1: NORMALIZATION (1-minute lag)
-- Normalize raw events into consistent format
-- =============================================================================

CREATE OR REPLACE DYNAMIC TABLE STAGING.DT_NORMALIZED_LOGINS
    TARGET_LAG = '1 minute'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
SELECT
    event_id,
    event_timestamp,
    user_name,
    client_ip,
    client_type,
    authentication_method,
    is_success,
    error_code,
    geo_country,
    geo_city,
    geo_lat,
    geo_lon,
    -- Calculated fields
    DATE_TRUNC('minute', event_timestamp) AS minute_bucket,
    DATE_TRUNC('hour', event_timestamp) AS hour_bucket,
    DATE(event_timestamp) AS event_date
FROM RAW.LOGIN_EVENTS
WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP());


CREATE OR REPLACE DYNAMIC TABLE STAGING.DT_NORMALIZED_QUERIES
    TARGET_LAG = '1 minute'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
SELECT
    event_id,
    query_id,
    query_start_time,
    query_end_time,
    user_name,
    role_name,
    warehouse_name,
    database_name,
    schema_name,
    query_type,
    query_text,
    rows_produced,
    bytes_scanned,
    bytes_scanned / 1e9 AS gb_scanned,
    execution_status,
    client_ip,
    DATE_TRUNC('minute', query_start_time) AS minute_bucket,
    DATE_TRUNC('hour', query_start_time) AS hour_bucket
FROM RAW.QUERY_EVENTS
WHERE query_start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP());

-- =============================================================================
-- STAGE 2: ENRICHMENT (2-minute lag)
-- Enrich with threat intel and context
-- =============================================================================

CREATE OR REPLACE DYNAMIC TABLE ENRICHED.DT_ENRICHED_LOGINS
    TARGET_LAG = '2 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
SELECT
    l.*,
    -- Threat intel enrichment
    ti.threat_type,
    ti.threat_actor,
    ti.confidence_score AS threat_confidence,
    ti.severity AS threat_severity,
    CASE WHEN ti.indicator_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_known_threat_ip,
    -- Known good IP check
    CASE WHEN kg.ip_address IS NOT NULL THEN TRUE ELSE FALSE END AS is_known_good_ip
FROM STAGING.DT_NORMALIZED_LOGINS l
LEFT JOIN REFERENCE.THREAT_INDICATORS ti 
    ON l.client_ip = ti.indicator_value 
    AND ti.indicator_type = 'ip' 
    AND ti.is_active = TRUE
LEFT JOIN REFERENCE.KNOWN_GOOD_IPS kg 
    ON l.client_ip = kg.ip_address;


CREATE OR REPLACE DYNAMIC TABLE ENRICHED.DT_ENRICHED_QUERIES
    TARGET_LAG = '2 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
SELECT
    q.*,
    -- Sensitive role check
    sr.sensitivity_level AS role_sensitivity,
    CASE WHEN sr.role_name IS NOT NULL THEN TRUE ELSE FALSE END AS is_sensitive_role,
    -- Threat intel enrichment
    ti.threat_type,
    ti.threat_actor,
    CASE WHEN ti.indicator_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_known_threat_ip
FROM STAGING.DT_NORMALIZED_QUERIES q
LEFT JOIN REFERENCE.SENSITIVE_ROLES sr ON q.role_name = sr.role_name
LEFT JOIN REFERENCE.THREAT_INDICATORS ti 
    ON q.client_ip = ti.indicator_value 
    AND ti.indicator_type = 'ip' 
    AND ti.is_active = TRUE;

-- =============================================================================
-- STAGE 3: DETECTION (5-minute lag)
-- Generate alerts from detected patterns
-- =============================================================================

-- Detection: Brute Force Attack
CREATE OR REPLACE DYNAMIC TABLE DETECTIONS.DT_BRUTE_FORCE_ALERTS
    TARGET_LAG = '5 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
WITH failed_login_counts AS (
    SELECT
        minute_bucket,
        user_name,
        client_ip,
        geo_country,
        geo_city,
        COUNT(*) AS failed_count,
        COUNT(DISTINCT error_code) AS unique_errors
    FROM ENRICHED.DT_ENRICHED_LOGINS
    WHERE is_success = FALSE
      AND minute_bucket >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
    GROUP BY 1, 2, 3, 4, 5
    HAVING COUNT(*) >= 5  -- Threshold: 5+ failures per minute
)
SELECT
    UUID_STRING() AS alert_id,
    CURRENT_TIMESTAMP() AS created_at,
    minute_bucket AS alert_time,
    'BRUTE_FORCE_ATTEMPT' AS detection_name,
    'Identity' AS detection_type,
    CASE 
        WHEN failed_count >= 20 THEN 5
        WHEN failed_count >= 10 THEN 4
        ELSE 3
    END AS severity,
    'user' AS entity_type,
    user_name AS entity_id,
    'Detected ' || failed_count || ' failed login attempts for user ' || user_name || 
    ' from IP ' || client_ip || ' (' || geo_country || ')' AS description,
    'Credential Access' AS mitre_tactic,
    'T1110' AS mitre_technique,
    OBJECT_CONSTRUCT(
        'failed_count', failed_count,
        'client_ip', client_ip,
        'geo_country', geo_country,
        'geo_city', geo_city,
        'time_window', minute_bucket
    ) AS evidence
FROM failed_login_counts;


-- Detection: Credential Stuffing
CREATE OR REPLACE DYNAMIC TABLE DETECTIONS.DT_CREDENTIAL_STUFFING_ALERTS
    TARGET_LAG = '5 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
WITH ip_user_patterns AS (
    SELECT
        hour_bucket,
        client_ip,
        geo_country,
        COUNT(DISTINCT user_name) AS unique_users_targeted,
        COUNT(*) AS total_attempts,
        SUM(CASE WHEN is_success THEN 1 ELSE 0 END) AS successful_logins,
        SUM(CASE WHEN NOT is_success THEN 1 ELSE 0 END) AS failed_logins
    FROM ENRICHED.DT_ENRICHED_LOGINS
    WHERE hour_bucket >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
    GROUP BY 1, 2, 3
    HAVING COUNT(DISTINCT user_name) >= 5  -- 5+ unique users from same IP
       AND SUM(CASE WHEN NOT is_success THEN 1 ELSE 0 END) >= 10
)
SELECT
    UUID_STRING() AS alert_id,
    CURRENT_TIMESTAMP() AS created_at,
    hour_bucket AS alert_time,
    'CREDENTIAL_STUFFING' AS detection_name,
    'Identity' AS detection_type,
    CASE 
        WHEN unique_users_targeted >= 20 THEN 5
        WHEN unique_users_targeted >= 10 THEN 4
        ELSE 3
    END AS severity,
    'ip' AS entity_type,
    client_ip AS entity_id,
    'Detected credential stuffing from IP ' || client_ip || ' targeting ' || 
    unique_users_targeted || ' unique users with ' || failed_logins || ' failed attempts' AS description,
    'Credential Access' AS mitre_tactic,
    'T1110.004' AS mitre_technique,
    OBJECT_CONSTRUCT(
        'unique_users_targeted', unique_users_targeted,
        'total_attempts', total_attempts,
        'successful_logins', successful_logins,
        'failed_logins', failed_logins,
        'geo_country', geo_country
    ) AS evidence
FROM ip_user_patterns;


-- Detection: Impossible Travel
CREATE OR REPLACE DYNAMIC TABLE DETECTIONS.DT_IMPOSSIBLE_TRAVEL_ALERTS
    TARGET_LAG = '5 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
WITH login_sequences AS (
    SELECT
        user_name,
        event_timestamp,
        client_ip,
        geo_country,
        geo_city,
        geo_lat,
        geo_lon,
        LAG(event_timestamp) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_timestamp,
        LAG(geo_lat) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_lat,
        LAG(geo_lon) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_lon,
        LAG(geo_city) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_city,
        LAG(geo_country) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_country
    FROM ENRICHED.DT_ENRICHED_LOGINS
    WHERE is_success = TRUE
      AND event_timestamp >= DATEADD('day', -1, CURRENT_TIMESTAMP())
),
travel_analysis AS (
    SELECT
        *,
        -- Haversine distance calculation (km)
        6371 * 2 * ASIN(SQRT(
            POWER(SIN(RADIANS(geo_lat - prev_lat) / 2), 2) +
            COS(RADIANS(prev_lat)) * COS(RADIANS(geo_lat)) *
            POWER(SIN(RADIANS(geo_lon - prev_lon) / 2), 2)
        )) AS distance_km,
        DATEDIFF('minute', prev_timestamp, event_timestamp) AS time_diff_minutes
    FROM login_sequences
    WHERE prev_timestamp IS NOT NULL
)
SELECT
    UUID_STRING() AS alert_id,
    CURRENT_TIMESTAMP() AS created_at,
    event_timestamp AS alert_time,
    'IMPOSSIBLE_TRAVEL' AS detection_name,
    'Identity' AS detection_type,
    5 AS severity,  -- Always critical
    'user' AS entity_type,
    user_name AS entity_id,
    'User ' || user_name || ' logged in from ' || geo_city || ', ' || geo_country ||
    ' only ' || time_diff_minutes || ' minutes after logging in from ' || 
    prev_city || ', ' || prev_country || ' (' || ROUND(distance_km, 0) || ' km apart)' AS description,
    'Defense Evasion' AS mitre_tactic,
    'T1078' AS mitre_technique,
    OBJECT_CONSTRUCT(
        'current_location', OBJECT_CONSTRUCT('city', geo_city, 'country', geo_country, 'lat', geo_lat, 'lon', geo_lon),
        'previous_location', OBJECT_CONSTRUCT('city', prev_city, 'country', prev_country, 'lat', prev_lat, 'lon', prev_lon),
        'distance_km', ROUND(distance_km, 2),
        'time_diff_minutes', time_diff_minutes,
        'required_speed_kmh', ROUND(distance_km / (time_diff_minutes / 60), 0)
    ) AS evidence
FROM travel_analysis
WHERE distance_km > 500  -- More than 500km
  AND time_diff_minutes < 120  -- Less than 2 hours
  AND (distance_km / (time_diff_minutes / 60)) > 800;  -- > 800 km/h (faster than commercial flight)


-- Detection: Data Exfiltration
CREATE OR REPLACE DYNAMIC TABLE DETECTIONS.DT_DATA_EXFILTRATION_ALERTS
    TARGET_LAG = '5 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
WITH user_data_volumes AS (
    SELECT
        hour_bucket,
        user_name,
        client_ip,
        role_name,
        is_known_threat_ip,
        threat_actor,
        SUM(gb_scanned) AS total_gb_scanned,
        COUNT(*) AS query_count,
        COUNT(DISTINCT database_name) AS databases_accessed
    FROM ENRICHED.DT_ENRICHED_QUERIES
    WHERE hour_bucket >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
      AND query_type = 'SELECT'
    GROUP BY 1, 2, 3, 4, 5, 6
    HAVING SUM(gb_scanned) > 50  -- More than 50GB in an hour
)
SELECT
    UUID_STRING() AS alert_id,
    CURRENT_TIMESTAMP() AS created_at,
    hour_bucket AS alert_time,
    'DATA_EXFILTRATION' AS detection_name,
    'Exfiltration' AS detection_type,
    CASE 
        WHEN is_known_threat_ip THEN 5
        WHEN total_gb_scanned > 500 THEN 5
        WHEN total_gb_scanned > 100 THEN 4
        ELSE 3
    END AS severity,
    'user' AS entity_type,
    user_name AS entity_id,
    'User ' || user_name || ' scanned ' || ROUND(total_gb_scanned, 1) || ' GB of data in 1 hour via ' ||
    query_count || ' queries from IP ' || client_ip ||
    CASE WHEN is_known_threat_ip THEN ' (KNOWN THREAT IP: ' || threat_actor || ')' ELSE '' END AS description,
    'Exfiltration' AS mitre_tactic,
    'T1567' AS mitre_technique,
    OBJECT_CONSTRUCT(
        'total_gb_scanned', ROUND(total_gb_scanned, 2),
        'query_count', query_count,
        'databases_accessed', databases_accessed,
        'client_ip', client_ip,
        'role_name', role_name,
        'is_known_threat_ip', is_known_threat_ip,
        'threat_actor', threat_actor
    ) AS evidence
FROM user_data_volumes;


-- Detection: Privilege Escalation
CREATE OR REPLACE DYNAMIC TABLE DETECTIONS.DT_PRIVILEGE_ESCALATION_ALERTS
    TARGET_LAG = '5 minutes'
    WAREHOUSE = SECURITY_WH
    REFRESH_MODE = INCREMENTAL
AS
SELECT
    UUID_STRING() AS alert_id,
    CURRENT_TIMESTAMP() AS created_at,
    query_start_time AS alert_time,
    'PRIVILEGE_ESCALATION' AS detection_name,
    'Privilege Escalation' AS detection_type,
    5 AS severity,  -- Always critical for sensitive role grants
    'user' AS entity_type,
    user_name AS entity_id,
    'User ' || user_name || ' executed privilege escalation: ' || query_text AS description,
    'Privilege Escalation' AS mitre_tactic,
    'T1078.004' AS mitre_technique,
    OBJECT_CONSTRUCT(
        'query_id', query_id,
        'query_text', query_text,
        'client_ip', client_ip,
        'role_used', role_name,
        'is_known_threat_ip', is_known_threat_ip
    ) AS evidence
FROM ENRICHED.DT_ENRICHED_QUERIES
WHERE query_type = 'GRANT'
  AND (
    query_text ILIKE '%ACCOUNTADMIN%'
    OR query_text ILIKE '%SECURITYADMIN%'
    OR query_text ILIKE '%SYSADMIN%'
    OR query_text ILIKE '%ALL PRIVILEGES%'
  )
  AND query_start_time >= DATEADD('day', -1, CURRENT_TIMESTAMP());

-- =============================================================================
-- UNIFIED ALERT VIEW
-- =============================================================================

CREATE OR REPLACE VIEW DETECTIONS.V_ALL_ALERTS AS
SELECT * FROM DETECTIONS.DT_BRUTE_FORCE_ALERTS
UNION ALL
SELECT * FROM DETECTIONS.DT_CREDENTIAL_STUFFING_ALERTS
UNION ALL
SELECT * FROM DETECTIONS.DT_IMPOSSIBLE_TRAVEL_ALERTS
UNION ALL
SELECT * FROM DETECTIONS.DT_DATA_EXFILTRATION_ALERTS
UNION ALL
SELECT * FROM DETECTIONS.DT_PRIVILEGE_ESCALATION_ALERTS;

-- =============================================================================
-- VERIFY PIPELINE
-- =============================================================================

-- Check Dynamic Table status
SHOW DYNAMIC TABLES IN SCHEMA DETECTIONS;

-- View recent alerts
SELECT 
    detection_name,
    severity,
    entity_id,
    description,
    alert_time
FROM DETECTIONS.V_ALL_ALERTS
ORDER BY alert_time DESC
LIMIT 20;

SELECT 'Detection pipeline created successfully!' AS status;
