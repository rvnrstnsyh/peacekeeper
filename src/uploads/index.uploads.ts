/**
 * File Upload Handlers
 *
 * Register file upload middleware and storage adapters here.
 * Supports local disk storage and cloud providers (S3, GCS, etc.).
 * Max file size and allowed MIME types are configured via environment
 * variables: MAX_FILE_SIZE, ALLOWED_FILE_TYPES, UPLOAD_DIR.
 *
 * Example pattern:
 *   export const avatarUpload = createMultipartHandler({ field: 'avatar', maxSize: 2_097_152 })
 */
