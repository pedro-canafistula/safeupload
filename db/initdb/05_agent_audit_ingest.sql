-- Apply to the existing app database before deploying the intake route.
-- Existing MySQL volumes do not automatically rerun initdb scripts.
USE app;
CREATE TABLE IF NOT EXISTS agent_audit_ingest (
    record_key VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    event_id VARCHAR(36) NOT NULL,
    endpoint_id VARCHAR(255) NOT NULL,
    occurred_at_utc TIMESTAMP(6) NOT NULL,
    received_at_utc TIMESTAMP(6) NOT NULL,
    schema_version INT NOT NULL,
    sender_hostname VARCHAR(255),
    agent_version VARCHAR(200),
    payload LONGTEXT NOT NULL,
    INDEX idx_agent_audit_event (event_id),
    INDEX idx_agent_audit_endpoint_time (endpoint_id, occurred_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
