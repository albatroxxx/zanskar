-- A pinned RDP or WinRM certificate is never replaced by a probe (ADR 0012):
-- a different certificate is held here, awaiting an administrator's
-- confirmation, while the pinned one stays in tls_fingerprint /
-- winrm_tls_fingerprint and keeps refusing the new certificate.
ALTER TABLE targets ADD COLUMN tls_fingerprint_pending TEXT;
ALTER TABLE targets ADD COLUMN winrm_tls_fingerprint_pending TEXT;
