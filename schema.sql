-- VATA MCP Security Platform Database Schema

CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT true
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES organizations(id),
    server_url VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL, -- 'rate_limit', 'path_traversal', 'cors', 'auth', 'input_validation'
    status VARCHAR(50) DEFAULT 'pending', -- pending, running, completed, failed
    result JSONB,
    severity VARCHAR(50), -- CRITICAL, HIGH, MEDIUM, LOW
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    INDEX idx_org_id (org_id),
    INDEX idx_status (status)
);

CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES organizations(id),
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    server_url VARCHAR(255) NOT NULL,
    vector_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    cvss_score FLOAT,
    remediation TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_org_id (org_id),
    INDEX idx_severity (severity)
);

CREATE TABLE compliance_reports (
    id SERIAL PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES organizations(id),
    framework VARCHAR(100) NOT NULL, -- SOC2, HIPAA, NIST
    servers_scanned INTEGER,
    vulnerabilities_found INTEGER,
    compliance_score FLOAT,
    report_json JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_org_id (org_id)
);

CREATE TABLE api_audit_log (
    id SERIAL PRIMARY KEY,
    org_id INTEGER,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_org_id (org_id),
    INDEX idx_timestamp (timestamp)
);
