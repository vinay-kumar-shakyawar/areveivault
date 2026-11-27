-- Browser-extension sessions stay signed in until the user signs out or the device is
-- removed, instead of ending after SESSION_IDLE_SECS / SESSION_ABSOLUTE_SECS.
ALTER TABLE sessions ADD COLUMN persistent boolean NOT NULL DEFAULT false;

-- Extensions that are already signed in keep their session.
UPDATE sessions s SET persistent = true
FROM devices d
WHERE d.id = s.device_id AND d.name LIKE 'Arevei Vault extension (%';
