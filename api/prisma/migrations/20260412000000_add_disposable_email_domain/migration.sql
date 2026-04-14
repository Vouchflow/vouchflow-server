-- Add disposable_email_domain flag to verifications.
-- Computed at fallback initiation from the plaintext email (which is not persisted);
-- read back at OTP completion to populate fallback_signals.

ALTER TABLE "verifications" ADD COLUMN "disposable_email_domain" BOOLEAN;
