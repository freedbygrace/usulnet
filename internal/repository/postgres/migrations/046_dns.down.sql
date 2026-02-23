-- 046_dns: Rollback DNS server tables
DROP TABLE IF EXISTS dns_audit_log;
DROP TABLE IF EXISTS dns_tsig_keys;
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS dns_zones;
