-- Webhook retry scheduling (BullMQ replacement, see services/webhooks.ts).
--
-- We used to enqueue every delivery into a BullMQ `webhooks` queue and let the
-- worker process do its own exponential backoff in memory. With BullMQ ripped
-- out (idle polling was ~half our Upstash command bill on a product with
-- effectively zero webhook traffic), the retry schedule lives in Postgres now:
-- on failure we set next_retry_at to (now + §7 delay table), and a 30-second
-- tick on each api-server instance picks up due rows.
--
-- pending  → still being attempted (initial state, or between retries)
-- delivered → 2xx received
-- failed    → reserved (transient): use webhook_failed for the terminal state
-- webhook_failed → all §7 retries exhausted; we will not retry again
ALTER TABLE "webhook_deliveries"
  ADD COLUMN "next_retry_at" TIMESTAMP(3);

-- Hot path for the retry tick: cheap index covering only rows the scheduler
-- actually has to inspect. Partial index keeps it tiny since the vast majority
-- of deliveries end up "delivered" and become invisible to this query.
CREATE INDEX "webhook_deliveries_next_retry_at_idx"
  ON "webhook_deliveries" ("next_retry_at")
  WHERE status = 'pending' AND next_retry_at IS NOT NULL;
