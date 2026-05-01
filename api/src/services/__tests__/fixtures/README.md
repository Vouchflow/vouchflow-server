# Test fixtures

## `cert0..cert3.pem`

A real Android Keystore Attestation certificate chain for an EC P-256 key
generated with `setAttestationChallenge("abc".getBytes())` on a StrongBox-
backed device. Sourced verbatim from
[google/android-key-attestation](https://github.com/google/android-key-attestation/tree/main/src/test/resources/pem/algorithm_EC_SecurityLevel_StrongBox).

- `cert0.pem` is the leaf, signed by `cert1`.
- `cert3.pem` is the self-signed Google Hardware Attestation Root CA.

The leaf's `KeyDescription` extension (OID `1.3.6.1.4.1.11129.2.1.17`)
contains:
- `attestationSecurityLevel`: StrongBox (2)
- `attestationChallenge`: `"abc"`
- `softwareEnforced.attestationApplicationId.signatureDigests`:
  `301aa3cb081134501c45f1422abc66c24224fd5ded5fdc8f17e697176fd866aa`
- `softwareEnforced.attestationApplicationId.packageNames`: contains
  `"com.android.keychain"`, `"android"`, and several other Android
  system packages.

These values are the expected inputs for `validateKeystoreAttestation`
in the golden-vector test suite.
