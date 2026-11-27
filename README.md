# PWM — Local Password Manager

PWM is a Windows-focused, single-user command-line password manager written in C++20 for a Secure Programming course.

> **Checkpoint 3 status:** The CLI, vault operations, input checks, zeroizing secret storage, structured event logs, persistence tests, and draft report are implemented. The project is a course prototype, not an independently audited or production-ready password manager.

## Features

- Initialize a local vault and create, retrieve, replace, or delete generated account passwords.
- Require the master password for each CLI operation that accesses the vault. The vault is locked and sensitive keys are cleared when the operation finishes.
- Encrypt the random vault key with AES-256-GCM. Derive its wrapping key with PBKDF2-HMAC-SHA-256 (200,000 iterations) and a per-vault random salt.
- Encrypt each stored password with AES-256-GCM and a fresh per-record nonce. Authenticate credential-file metadata with a keyed HMAC-SHA-256.
- Serialize credentials in a versioned, bounded file format; atomically replace data files and migrate the supported legacy credential format.
- Copy generated or retrieved passwords to the Windows clipboard. A helper process attempts to clear PWM's clipboard value after 15 seconds only if the clipboard has not changed.
- Emit structured JSON event records to standard error. Log events contain no passwords, master passwords, account names, or secret values.

Passwords are never printed to the terminal. The obsolete `--show-pw` option is rejected.

## Input validation

Inputs are validated and rejected rather than silently trimmed or transformed:

- Account names must be valid UTF-8, between 1 and 256 bytes, must not start or end with a space, and cannot contain control characters, terminal line separators, or bidirectional override controls.
- Master passwords and stored passwords must be non-empty, no longer than 4,096 bytes, and contain no NUL byte. Password bytes are otherwise preserved exactly; PWM does not normalize or rewrite them.
- Terminal password input is hidden and capped at 4,096 bytes. An over-limit input is drained to the end of the line and rejected.
- Credential files have size, record-count, field-length, duplicate-name, timestamp, version, and authentication checks. Historical records can contain account names up to the file-format limit of 4,096 bytes; new names use the stricter 256-byte limit.
- Unknown command-line options and unexpected positional arguments are rejected.

## Secure memory, logging, and errors

`SecureString` and `SecureBuffer` use zeroizing allocators. Their active contents are cleansed when cleared, and allocated storage is cleansed again before deallocation. They are used for hidden terminal input, generated and decrypted passwords, the vault key, derived keys, and the credential-file authentication key. Password APIs use non-owning views to avoid making additional standard-string copies. Temporary legacy plaintext is cleansed during migration, including error paths.

This is best-effort process-memory protection, not a guarantee against operating-system or hardware-level capture. Secret pages are not locked against paging; crash dumps, hibernation, debuggers, OpenSSL internals, and caller-owned input buffers are outside the zeroizing containers. The clipboard is outside the vault's memory boundary and may be read by other applications. Automatic clipboard clearing is best effort.

Operational events are emitted as one JSON object per line, for example:

```json
{"timestamp":"2026-11-27T08:00:00Z","level":"info","event":"credential.created"}
```

Events use fixed names and do not include user-controlled values or secrets. Errors are reported to the user and produce a generic structured failure event; error details are not copied into logs.

## Per-user storage and access

PWM is installed and run for one Windows user. Its files are stored under that user's `%LOCALAPPDATA%\pwm` directory and use the Windows profile's inherited access-control list. Each CLI credential operation also requires the master password before using the vault. Vault record methods reject calls while locked.

This is an OS-profile boundary, not a multi-user application authorization system. PWM does not define separate users, roles, or shared-vault ownership. Anyone who can access the same Windows account and its profile can access that account's files; administrators and malware running with equivalent privileges are outside this boundary. Do not weaken the directory's Windows ACL.

## Commands

| Command | Description |
| --- | --- |
| `pwm --init` | Create the vault and set/confirm the master password. |
| `pwm "youtube"` | Retrieve the existing password, or create one if the account is new. |
| `pwm --create-pw "youtube"` or `pwm -new "youtube"` | Generate and store a password. |
| `pwm --get-pw "youtube"` or `pwm -get "youtube"` | Retrieve a password. |
| `pwm --update-pw "youtube"` | Generate and store a replacement password. |
| `pwm --delete-pw "youtube"` | Delete a credential. |
| `pwm --uninstall` | Verify the master password and require typing `DELETE` before removing vault files. |

Unlocking and locking are internal to each credential command. There are no persistent unlocked sessions or public `--unlock` / `--lock` commands. File removal is not secure disk erasure.

## Build on Windows

Requirements: CMake 3.20+, a C++20 compiler (Visual Studio 2022 or Build Tools with the C++ workload), and OpenSSL Crypto. The vcpkg manifest declares OpenSSL.

Install and bootstrap vcpkg, then set its location:

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
& C:\vcpkg\bootstrap-vcpkg.bat
$env:VCPKG_ROOT = "C:\vcpkg"
```

Configure, build, and test:

```powershell
git clone https://github.com/JulianII/TalTec-SecProgram.git
Set-Location .\TalTec-SecProgram
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Run from a normal interactive console:

```powershell
.\build\Release\pwm.exe --init
.\build\Release\pwm.exe --create-pw "youtube"
```

Account names must reach the program as UTF-8 bytes. If using a legacy Windows console code page, switch it to UTF-8 (for example, `chcp 65001`) before entering non-ASCII account names.

The documented clean-machine Visual Studio/vcpkg setup has not been independently verified. The current development build and tests have been run with the available Windows toolchain.

## Tests

The CTest suite includes:

- Credential create/read/update/delete and save/load round trips.
- Authenticated-file tampering, truncated-file rejection, legacy migration, and vault reopening.
- Wrong-master-password handling, failed-unlock cleanup, and vault-file tamper/truncation rejection.
- Account/password validation edge cases: empty, overlong, control-character, malformed UTF-8, and embedded-NUL inputs.
- Locked-vault rejection for reads, writes, updates, deletes, existence checks, and account listing.
- Zeroization primitive and secure-container clear checks.
- CLI rejection of `--show-pw`, empty account names, and unsupported options.

Run with `ctest --test-dir build --output-on-failure` (or add `-C Release` for a Visual Studio multi-configuration build).

## Data location and format

On Windows, the application data directory is `%LOCALAPPDATA%\pwm`. It contains `vault.bin` (the encrypted vault-key envelope) and `credentials.dat` (encrypted records and integrity data). Do not edit these files manually. Keep an independent backup if needed; a backup does not bypass the master password.

Linux terminal-input and data-directory code exists, but Linux is not a supported application target: the Windows clipboard backend is not available there, and a complete Linux build/run path has not been implemented or tested.

## Security limitations

- PWM uses PBKDF2-HMAC-SHA-256 with a fixed 200,000 iterations; the initially considered Argon2id KDF is not implemented, and KDF parameters are not user-configurable.
- Account names are visible in plaintext in the credential file. Passwords are encrypted.
- The project has not received an independent security audit. The file format, migration paths, Windows ACL deployment assumptions, and cryptographic design have only been tested within the course project.
- Clipboard access is shared with other desktop applications. Cleanup is conditional and best effort.
- Removing files does not overwrite storage and cannot guarantee erasure from SSDs, backups, journals, snapshots, or filesystem caches.
- A forgotten master password cannot be recovered.

See the [Checkpoint 3 report draft](./docs/checkpoint-3-report.md) for the implementation summary and security analysis.

## Repository layout

```text
include/                 Public declarations, validation, logging, and secure-memory helpers
src/
  main.cpp               CLI parsing, workflows, and event logging
  vault.cpp              Master-key derivation, vault lifecycle, and access checks
  credential.cpp         Password encryption, validation, and persistence
  clipboard.cpp          Windows clipboard implementation
  platform/              Platform-specific hidden input and data-directory helpers
tests/                   Persistence, validation, memory, and access-control checks
docs/                    Checkpoint notes and report draft
```
