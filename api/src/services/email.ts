import { Resend } from 'resend'
import { config } from '../config.js'

const resend = new Resend(config.resendApiKey)

export async function sendMagicLink(email: string, token: string): Promise<void> {
  const url = `${config.webBaseUrl}/auth/verify?token=${token}`

  await resend.emails.send({
    from: 'Vouchflow <noreply@vouchflow.dev>',
    to: email,
    subject: 'Your Vouchflow login link',
    text: [
      'Click the link below to sign in to Vouchflow.',
      '',
      'This link expires in 15 minutes and can only be used once.',
      '',
      url,
      '',
      "If you didn't request this, you can safely ignore this email.",
      '',
      '— Vouchflow',
    ].join('\n'),
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#F4F4F1;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #E4E4DF;">
        <tr>
          <td style="background:#111111;padding:24px 32px;">
            <span style="font-size:16px;font-weight:500;color:#ffffff;letter-spacing:-0.3px;">vouchflow</span>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 32px 28px;">
            <p style="font-size:22px;font-weight:300;color:#111;letter-spacing:-0.4px;margin:0 0 12px;">Sign in to Vouchflow</p>
            <p style="font-size:14px;color:#555;font-weight:300;line-height:1.6;margin:0 0 28px;">
              Click the button below to sign in. This link expires in 15 minutes and can only be used once.
            </p>
            <a href="${url}" style="display:inline-block;background:#111111;color:#ffffff;font-size:14px;font-weight:500;text-decoration:none;padding:12px 24px;border-radius:7px;">
              Sign in to Vouchflow →
            </a>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 32px;border-top:1px solid #E4E4DF;">
            <p style="font-size:12px;color:#999;margin:0;font-weight:300;">
              If you didn't request this link, you can safely ignore this email. The link expires in 15 minutes.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  })
}
