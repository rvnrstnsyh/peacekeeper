import Handlebars from 'handlebars'
import nodemailer from 'nodemailer'

import type { Transporter, SendMailOptions, SentMessageInfo } from 'nodemailer'

import { resolve } from 'node:path'
import { readFileSync } from 'node:fs'
import { env } from '@/configs/environment.configs'
import { logEmail, logError } from '@/configs/logger.configs'

// ============================================================================
// Types
// ============================================================================

interface MailPayload {
  to: string
  subject: string
  html: string
  text: string
}

type CompiledTemplate = (context: Record<string, unknown>) => string

// ============================================================================
// Template engine (lazy-compiled, cached per filename)
// ============================================================================

const TEMPLATES_DIR: string = resolve(process.cwd(), 'src', 'shared', 'utils', 'email.utils', 'templates')

const _templateCache: Map<string, CompiledTemplate> = new Map<string, CompiledTemplate>()

function getTemplate(filename: string): CompiledTemplate {
  const cached: CompiledTemplate | undefined = _templateCache.get(filename)
  if (cached) return cached

  const src: string = readFileSync(resolve(TEMPLATES_DIR, filename), 'utf-8')
  const compiled: CompiledTemplate = Handlebars.compile(src) as CompiledTemplate
  _templateCache.set(filename, compiled)
  return compiled
}

function renderEmail(name: string, context: Record<string, unknown>): { html: string; text: string } {
  const sharedCtx: Record<string, unknown> = { appName: env.SMTP_NAME, year: new Date().getFullYear(), ...context }
  const body: string = getTemplate(`${name}.hbs`)(sharedCtx)
  const html: string = getTemplate('_layout.hbs')({ ...sharedCtx, body })
  const text: string = getTemplate(`${name}.txt.hbs`)(sharedCtx)
  return { html, text }
}

// ============================================================================
// Transporter (lazy-initialized, reused across calls)
// ============================================================================

let _transporter: Transporter | null = null

function getTransporter(): Transporter {
  if (_transporter) return _transporter

  _transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_SECURE,
    auth:
      env.SMTP_USER && env.SMTP_PASSWORD
        ? {
            user: env.SMTP_USER,
            pass: env.SMTP_PASSWORD
          }
        : undefined
  })

  return _transporter
}

// ============================================================================
// Core send function
// ============================================================================

/**
 * Send an email.
 *
 * Development: writes subject + plain-text body to the logger (no actual send).
 * Production:  delivers via SMTP when SMTP_HOST / SMTP_PORT / SMTP_FROM are set.
 *
 * Failures are always caught and logged — email errors must not crash the request.
 */
async function sendMail(event: 'verification' | 'password_reset', payload: MailPayload): Promise<void> {
  const from: string = `"${env.SMTP_NAME}" <${env.SMTP_FROM ?? 'noreply@localhost'}>`

  if (!env.isProduction) {
    // In development: log the link/content instead of sending a real email
    logEmail(event, payload.to, false, {
      mode: 'dev_only',
      subject: payload.subject,
      body: payload.text
    })
    return
  }

  if (!env.isEmailConfigured) {
    logEmail(event, payload.to, false, {
      mode: 'skipped',
      reason: 'SMTP not fully configured'
    })
    return
  }

  const options: SendMailOptions = {
    from,
    to: payload.to,
    subject: payload.subject,
    html: payload.html,
    text: payload.text
  }

  try {
    const info: SentMessageInfo = await getTransporter().sendMail(options)
    logEmail(event, payload.to, true, { messageId: info.messageId })
  } catch (error) {
    logError(error as Error, { service: 'EmailService', event, to: payload.to, subject: payload.subject })
    throw error
  }
}

// ============================================================================
// Email service — public API
// ============================================================================

export const EmailService = {
  /**
   * Send email verification link to a newly registered user.
   *
   * @param email - Recipient address
   * @param token - JWT email verification token
   */
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verifyUrl: string = `${env.APP_CLIENT_HOSTNAME}/verify-email?token=${encodeURIComponent(token)}`
    const { html, text }: { html: string; text: string } = renderEmail('verification', { verifyUrl })
    await sendMail('verification', { to: email, subject: 'Verify your email address', html, text })
  },

  /**
   * Send password reset link (forgot-password flow).
   * The reset token is included in the URL; the client forwards it to
   * the reset-password/alpha endpoint in the body.
   *
   * @param email - Recipient address
   * @param token - JWT password reset token (1-hour expiry)
   */
  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl: string = `${env.APP_CLIENT_HOSTNAME}/reset-password?token=${encodeURIComponent(token)}`
    const { html, text }: { html: string; text: string } = renderEmail('password-reset', { resetUrl })
    await sendMail('password_reset', { to: email, subject: 'Reset your password', html, text })
  }
}
