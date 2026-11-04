-- The security contact setting is withdrawn (2026-11-04, the owner's
-- decision): the gateway no longer publishes /.well-known/security.txt, so
-- the address an administrator stored for it goes. A gateway that never set
-- one has no row, and this changes nothing there.
DELETE FROM settings WHERE key = 'security.contact';
