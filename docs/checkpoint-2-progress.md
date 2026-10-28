# Checkpoint 2 progress

## Delivered

PWM stores a local vault and supports credential create, retrieve, update, and delete operations. The master password derives a wrapping key with PBKDF2-HMAC-SHA-256 (200,000 iterations); AES-256-GCM protects the vault key and each credential password at rest. Credential files use a bounded, versioned format, a whole-file HMAC, and atomic replacement. Legacy length-prefixed credential files are migrated when loaded. OpenSSL `RAND_bytes` supplies cryptographic random values. Passwords are never printed: credential commands copy them to the clipboard, and the obsolete `--show-pw` option is rejected.

The README documents the Windows CMake, Visual Studio, vcpkg build and run process. Automated tests cover credential CRUD and persistence, authenticated-file tampering, truncated files, legacy migration, vault reopening and tampering, unlock failure, and rejection of `--show-pw`.

## Checkpoint status

The core requirements are implemented and committed in the current branch. The development-environment build and CTest suite passed (2/2 tests) using MinGW and OpenSSL 3.5.2 from MSYS2. The documented clean-machine Visual Studio/vcpkg path has not been run in this environment because Visual Studio and vcpkg are unavailable.

This remains a course prototype, not a production-ready password manager. It has not received an independent security audit; account names remain visible, secure-memory clearing is best-effort, and the clipboard is outside the vault's encryption boundary. PBKDF2 is used instead of the initially planned Argon2id.
