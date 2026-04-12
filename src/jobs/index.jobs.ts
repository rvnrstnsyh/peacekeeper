/**
 * Background Job Queue
 *
 * Register scheduled and async background jobs here (e.g., email sending,
 * PDF generation, data exports). Use BullMQ or node-cron backed by Redis.
 *
 * Example pattern:
 *   emailQueue.process('send-verification', sendVerificationEmailWorker)
 *   cron.schedule('0 3 * * *', cleanExpiredSessionsWorker)
 */
