-- An application's dependencies (2026-11-03, ADR 0037 amended): where its
-- pages may load scripts, styles, fonts, images and APIs from beside its
-- origins. 'public' lets the session's relay reach any public address on
-- port 80 or 443 for them; 'origins' keeps the relay to the upstream and the
-- endpoints, as every session was before. Applications already enrolled
-- take 'public', the owner's choice, so they work whole; a host or a
-- database holds nothing here.
ALTER TABLE targets ADD COLUMN app_dependencies TEXT;
UPDATE targets SET app_dependencies = 'public' WHERE app_upstream IS NOT NULL;
