-- Windows sessions on autoscaling instances (ADR 0024). RDP and WinRM are
-- pinned per instance, the way a static target's certificates are: an
-- instance keeps the certificate first seen on it, and a later change makes
-- it unhealthy rather than silently trusting the new one.
ALTER TABLE asg_instances ADD COLUMN tls_fingerprint TEXT;
ALTER TABLE asg_instances ADD COLUMN winrm_tls_fingerprint TEXT;
