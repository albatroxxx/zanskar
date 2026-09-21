-- Where an autoscaling instance's pinned host key came from: the serial
-- console (verified out of band) or trust on first use (residual risk).
ALTER TABLE asg_instances ADD COLUMN host_key_source TEXT;
