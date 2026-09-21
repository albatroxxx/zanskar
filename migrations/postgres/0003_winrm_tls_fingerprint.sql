-- A Windows host presents different certificates on its RDP and WinRM listeners,
-- so WinRM gets its own pinned fingerprint (tls_fingerprint stays the RDP one).
ALTER TABLE targets ADD COLUMN winrm_tls_fingerprint TEXT;
