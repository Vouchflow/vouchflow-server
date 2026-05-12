-- Add completionResponse field to store idempotent ceremony responses
ALTER TABLE verifications ADD COLUMN completion_response JSONB;

CREATE INDEX idx_verifications_completion_response ON verifications(session_id, state) 
WHERE completion_response IS NOT NULL;

COMMENT ON COLUMN verifications.completion_response IS 
'Stores the successful completion response for idempotency. When a ceremony is completed, the response is stored here. Subsequent calls to /complete on a COMPLETED session return this cached response instead of failing.';
