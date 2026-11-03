-- An administrator holds what an auditor and a user hold, so beside admin
-- those roles say nothing more; roles are kept with admin alone
-- (user.NormalizeRoles, 2026-11-03). Accounts given all three before keep
-- admin and lose the two that repeated it.
DELETE FROM user_roles
WHERE role IN ('auditor', 'user')
  AND user_id IN (SELECT user_id FROM user_roles WHERE role = 'admin');
