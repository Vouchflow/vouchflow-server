// Static blocklist of known disposable / throwaway email domain providers.
//
// Intentionally embedded rather than pulled from a third-party npm package to avoid
// an extra dependency with potential ESM-compatibility issues, and to keep the list
// under our control. Add new entries as they are encountered.
//
// Coverage: the most common services account for the overwhelming majority of abuse;
// completeness here is less important than correctness — false positives (blocking
// a legitimate user) are worse than false negatives (missing a disposable address).
// This flag is informational only; it does not block the verification.

const DISPOSABLE_DOMAINS = new Set<string>([
  // Guerrilla Mail family
  'guerrillamail.com',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamail.biz',
  'guerrillamail.de',
  'guerrillamail.info',
  'guerrillamailblock.com',
  'grr.la',
  'sharklasers.com',
  'spam4.me',
  // Mailinator family
  'mailinator.com',
  'mailinator2.com',
  'tradermail.info',
  'suremail.info',
  'mailinater.com',
  'spam.la',
  'gawab.com',
  // Yopmail family
  'yopmail.com',
  'yopmail.fr',
  'cool.fr.nf',
  'jetable.fr.nf',
  'nospam.ze.tc',
  'nomail.xl.cx',
  'mega.zik.dj',
  'speed.1s.fr',
  'courriel.fr.nf',
  'moncourrier.fr.nf',
  'monemail.fr.nf',
  'monmail.fr.nf',
  // 10 Minute Mail
  '10minutemail.com',
  '10minutemail.net',
  '10minutemail.org',
  '10minutemail.de',
  '10minutemail.ru',
  // Temp Mail / TempMail
  'temp-mail.org',
  'tempmail.com',
  'tempmail.net',
  'temp-mail.io',
  'tmpmail.net',
  'tmpmail.org',
  'tmpeml.com',
  // Throwam / generic throwaways
  'throwam.com',
  'throwam.net',
  'discard.email',
  'trashmail.com',
  'trashmail.net',
  'trashmail.org',
  'trashmail.at',
  'trashmail.io',
  'trashmail.me',
  'trashmail.xyz',
  // Maildrop
  'maildrop.cc',
  // Mailnesia
  'mailnesia.com',
  // Mailnull
  'mailnull.com',
  // Spam Gourmet
  'spamgourmet.com',
  'spamgourmet.net',
  'spamgourmet.org',
  // Fake Inbox
  'fakeinbox.com',
  'fakeinbox.net',
  // GishPuppy
  'gishpuppy.com',
  // Mohmal
  'mohmal.com',
  // Filz Mail
  'filzmail.com',
  // Dispostable
  'dispostable.com',
  // Spamex
  'spamex.com',
  // Burner Mail
  'burnermail.io',
  // Nada
  'getnada.com',
  // AnonBox
  'anonbox.net',
  // Crazymailing
  'crazymailing.com',
  // Tempr
  'tempr.email',
  // Clrmail
  'clrmail.com',
  // 0-mail
  '0-mail.com',
  // Mailmetrash
  'mailmetrash.com',
  // SpamSalad
  'spamsalad.in',
  // Spamoff
  'spamoff.de',
  // Inoutmail
  'inoutmail.de',
  'inoutmail.eu',
  'inoutmail.info',
  'inoutmail.net',
  // Wegwerfmail
  'wegwerfmail.de',
  'wegwerfmail.net',
  'wegwerfmail.org',
  // Mailexpire
  'mailexpire.com',
  // Throwam aliases
  'weg-werf-email.de',
  // YOL / Temp addresses
  'sofimail.com',
  'spamfree24.org',
  'spamfree24.de',
  'spamfree24.eu',
  'spamfree24.info',
  'spamfree24.net',
])

/**
 * Returns true if the email address uses a known disposable / throwaway domain.
 *
 * The check is informational — it does not block the verification. Callers should
 * treat `true` as a risk signal, not a hard rejection.
 */
export function isDisposableEmailDomain(email: string): boolean {
  const atIdx = email.lastIndexOf('@')
  if (atIdx === -1) return false
  const domain = email.slice(atIdx + 1).toLowerCase().trim()
  return DISPOSABLE_DOMAINS.has(domain)
}
