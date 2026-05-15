-- Add key_last4 to api_keys: the last 4 chars of the raw live key, stored at
-- creation so the dashboard can identify a key after the raw value is gone.
-- Nullable — existing keys have no recoverable raw value.
ALTER TABLE api_keys ADD COLUMN key_last4 TEXT;
