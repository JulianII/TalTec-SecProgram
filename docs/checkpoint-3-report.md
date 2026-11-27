# Checkpoint 3 Report Draft — Password Manager

## Introduction

PWM is a Windows-focused, single-user command-line password manager developed as a Secure Programming course project. Its purpose is to generate and store account passwords in a local vault, protect stored passwords with authenticated encryption, and make retrieved passwords available through the Windows clipboard without displaying them in the terminal.

Checkpoint 3 brings the project to a near-final course state. This draft summarizes the implemented workflows, input and memory protections, tests, and remaining limitations. PWM is a prototype and has not been independently security-audited.

## Implementation

### Vault and credential handling

The CLI supports vault initialization, automatic get-or-create, explicit password creation and retrieval, replacement, deletion, and vault removal. A credential operation prompts for the master password, loads the vault, performs one operation, and locks the vault again. The vault API rejects record operations while locked.

At initialization, PWM generates a random 32-byte vault key and a per-vault salt. PBKDF2-HMAC-SHA-256 with 200,000 iterations derives a wrapping key from the master password. AES-256-GCM encrypts the vault key and each credential password. Credential records use fresh nonces, and a keyed HMAC-SHA-256 authenticates the credential file and its metadata. Versioned formats, parser bounds, timestamp checks, atomic replacement, and migration from the supported legacy credential format protect persistence and compatibility.

### Input validation and memory handling

Account names are limited to 256 UTF-8 bytes for new records. Invalid UTF-8, empty or overlong names, leading/trailing spaces, and unsafe control or bidirectional formatting characters are rejected. Master and stored passwords must be non-empty, no longer than 4,096 bytes, and contain no NUL byte; their other bytes are preserved without normalization. Hidden terminal input is bounded to the same maximum. Input is rejected rather than silently sanitized.

Sensitive strings and byte buffers use `SecureString` and `SecureBuffer`, backed by allocators that cleanse storage before release. Clearing a container also cleanses its active contents. The CLI, vault, and credential APIs pass secret views instead of making ordinary `std::string` copies. Derived keys, the vault key, decrypted password buffers, and legacy plaintext migration data use zeroizing storage or explicit cleansing.

### Logging, errors, and per-user access

The CLI emits structured JSON event lines to standard error for successful vault and credential events, clipboard warnings, and command failures. Events use fixed names and omit passwords, master passwords, account names, and secret values. Exceptions are reported to the user; failures do not produce success-shaped results. Vault memory is cleared during normal locking and object destruction.

The Windows deployment is for one user. Data is kept beneath that user's `%LOCALAPPDATA%\pwm` directory and relies on the Windows profile's inherited ACL. The master password is also required for each credential command. PWM does not implement a separate multi-user account or role system; the access boundary is the Windows user profile and its operating-system permissions.

### Tests

The CTest suite passes all four registered tests. Coverage includes persistence round trips and CRUD, file tampering and truncation, legacy migration, wrong-password and failed-unlock behavior, validation edge cases, locked-vault record access, zeroization checks, and rejected CLI inputs/options.

## Security Analysis

### Protections implemented

- AES-256-GCM provides confidentiality and authentication for password values and the wrapped vault key.
- The credential-file HMAC detects modifications to records and metadata.
- OpenSSL's cryptographic random generator supplies vault keys, salts, nonces, and password-generation bytes. Password characters are selected without modulo bias.
- Bounded input and file parsing reject malformed or excessive values before persistence or use.
- Zeroizing containers reduce the lifetime of application-owned plaintext and key material; failure paths clear sensitive state.
- The Windows profile directory and inherited ACL provide the intended per-user storage boundary. CLI record operations require an unlocked vault.
- Structured logs exclude secrets and user-controlled account identifiers.

### Remaining limitations and risks

- Memory cleansing is best effort. PWM does not lock pages against paging; operating-system dumps, hibernation, debuggers, privileged malware, caller-owned buffers, and cryptographic-library internals are outside this protection.
- Clipboard data is available to other applications. Clearing it after 15 seconds is conditional on the clipboard remaining unchanged and is not guaranteed if the helper cannot run.
- PBKDF2-HMAC-SHA-256 is used instead of the originally considered Argon2id, with a fixed iteration count. The project has not established that these parameters are appropriate for long-term production use.
- Account names remain visible in plaintext. File deletion does not securely overwrite disks and cannot remove historical copies from backups, snapshots, journals, or storage-device internals.
- Per-user isolation relies on Windows profile ACLs. This is not a defense against an attacker with access to the same Windows account or equivalent system privileges.
- Linux is not a supported application target because its clipboard backend and full build/run path are incomplete.
- No independent security audit has reviewed the cryptographic design, file formats, migration behavior, Windows deployment permissions, or operational error paths.

These constraints mean PWM should be used only as a course prototype and not to protect real account credentials.

## Conclusion

The Checkpoint 3 implementation provides the requested near-final course features: vault and password workflows, bounded validation, zeroizing secret storage, structured non-secret event logging, per-user Windows profile storage, and a passing test suite. The README documents build/use instructions and known limitations, and this report draft records the implementation and security analysis.

The work should be considered complete for the stated Windows single-user course scope, not as evidence of production readiness. An independent security review, platform-specific ACL verification on the intended deployment systems, and a documented decision about KDF parameters would be required before any broader use.
