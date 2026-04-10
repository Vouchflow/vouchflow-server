import { Device } from '@prisma/client'

// §7 Confidence scoring table
export function computeConfidence(params: {
  device: Device
  biometricUsed: boolean
  fallbackUsed: boolean
}): 'high' | 'medium' | 'low' {
  const { device, biometricUsed, fallbackUsed } = params

  if (fallbackUsed) return 'low'
  if (!device.attestationVerified) return 'low'

  const deviceAgeMs = Date.now() - device.enrolledAt.getTime()
  const deviceAgeDays = deviceAgeMs / (1000 * 60 * 60 * 24)

  // high: attestation verified + biometric + persistent keychain + device age > 30 days
  if (biometricUsed && device.confidenceCeiling === 'high' && deviceAgeDays > 30) {
    return 'high'
  }

  // medium: attestation verified + PIN fallback, or device age < 30 days
  return 'medium'
}
