# PWM — Local Password Manager

PWM is a single-user command-line password manager written in C++20 for a Secure Programming course. It is intended to keep a user's generated passwords in a local vault and require the master password for each operation that accesses stored credentials.

> **Project status: Checkpoint 2 core requirements implemented.** The CLI and vault workflows are implemented and tested in the development environment. The documented clean-machine Windows build has not yet been independently verified, and this project has not been security-audited. It is not ready for production use. See [Security status and limitations](#security-status-and-limitations).

## Scope

### In scope

- Initialize or explicitly remove a local vault.
- Generate, store, retrieve, replace, and delete account passwords.
- Require a master password when an operation accesses the vault.
- Lock the vault internally after each operation; there are no persistent unlocked sessions or public `--unlock` / `--lock` commands.
- Copy retrieved and generated passwords to the Windows clipboard; passwords are never printed to the terminal.
- Keep account names searchable while encrypting password values.

### Out of scope

- Multiple users, registration, or shared vaults.
- Persistent unlocked sessions, background services, or daemons.
- Cloud synchronization, remote storage, or a web service.
- Recovery of a forgotten master password. Losing it means losing access to the vault.

## Current implementation

### Core functionality implemented

- `--init` creates a local vault and prompts for a master password and confirmation.
- Credential operations prompt for the master password, unlock the vault for that invocation, perform the operation, and lock it again.
- The master password is used with PBKDF2-HMAC-SHA-256 (200,000 iterations) and a per-vault salt to derive a wrapping key.
- A randomly generated 32-byte vault key is encrypted in the vault file with AES-256-GCM.
- Each credential password is encrypted with AES-256-GCM and a per-record nonce. The authentication tag is stored with the ciphertext and checked during decryption.
- `--uninstall` requires the master password and the literal confirmation `DELETE` before removing the vault files.
- The build uses CMake and C++20.

### Checkpoint 2 deliverables

| Requirement | Status |
| --- | --- |
| Basic vault storage | Implemented; vaults and credentials persist locally and can be reopened. |
| Credentials encrypted at rest | Implemented with AES-256-GCM; credential records also have a whole-file HMAC. |
| Master-password authentication | Implemented; a wrong password prevents unlocking. |
| Usable interface without cleartext password output | Implemented; passwords are copied to the clipboard and not printed. |
| Clean-machine build and run instructions | Documented below for Windows with CMake, Visual Studio, and vcpkg; this exact clean-machine setup has not been run in the development environment. |
| Short progress note | Included in [the Checkpoint 2 progress note](./docs/checkpoint-2-progress.md). |
| Incremental commit history | Earlier incremental commits are present. Current uncommitted changes must be committed to include this work in the history. |

### Implementation notes and limitations

- The current key derivation is **PBKDF2, not Argon2id**. Argon2id was part of the initial design, but has not been implemented.
- OpenSSL's `RAND_bytes` supplies salts, keys, nonces, temporary-file names, and unbiased generated-password characters.
- Credential storage uses a versioned format with bounded parsing, a whole-file HMAC, and atomic replacement. Account names remain visible in plaintext; the older length-prefixed file format is imported and migrated when loaded.
- Clipboard contents remain available until another application replaces them or the user clears them. Automatic clipboard expiration is not currently implemented.
- Secure-memory handling is partial. Standard C++ strings and vectors can make copies, and not every sensitive temporary buffer is guaranteed to be zeroized.
- Automated persistence tests cover credential save/load, authenticated-file tampering, truncated files, legacy migration, vault reopening, vault-file tampering, and unlock failure cleanup.
- Linux support is incomplete: terminal input and data-directory code exist, but clipboard integration is currently implemented for Windows only and the current build does not provide a Linux clipboard backend.
- The uninstall operation removes vault files; it does not securely overwrite storage. Filesystem, SSD, backup, and journal behavior can retain recoverable data.

## Commands

| Command | Description |
| --- | --- |
| `pwm --init` | Create a vault and set the master password. |
| `pwm "youtube"` | Retrieve the account password if it exists; otherwise generate, store, and copy a new password to the clipboard. |
| `pwm --create-pw "youtube"` or `pwm -new "youtube"` | Generate and store a password, then copy it to the clipboard. |
| `pwm --get-pw "youtube"` or `pwm -get "youtube"` | Retrieve a password and copy it to the clipboard. |
| `pwm --update-pw "youtube"` | Generate and store a replacement password. |
| `pwm --delete-pw "youtube"` | Delete a credential. |
| `pwm --uninstall` | Permanently remove the vault after master-password and `DELETE` confirmation. |

The commands above are the implemented CLI surface. Unlocking and locking are internal parts of each credential command, not separate CLI commands.
The `--show-pw` option is rejected; PWM never prints passwords in cleartext.

## Build

### Requirements

- CMake 3.20 or newer.
- A C++20 compiler.
- OpenSSL development headers and libraries (the implementation uses OpenSSL Crypto APIs).

The project requires OpenSSL Crypto; CMake locates it with `find_package(OpenSSL REQUIRED COMPONENTS Crypto)`. The repository includes a vcpkg manifest declaring OpenSSL.

### Windows (PowerShell)

Install Git, CMake, and Visual Studio 2022 (or Build Tools with the C++ workload). Install and bootstrap vcpkg, then set `VCPKG_ROOT` to its installation directory. For example, from PowerShell:

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
& C:\vcpkg\bootstrap-vcpkg.bat
$env:VCPKG_ROOT = "C:\vcpkg"
```

Clone this project and configure it from a PowerShell session:

```powershell
git clone https://github.com/JulianII/TalTec-SecProgram.git
Set-Location .\TalTec-SecProgram
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

In manifest mode, vcpkg installs the declared OpenSSL dependency during CMake configuration. If OpenSSL is already installed outside vcpkg, configure CMake with its installation prefix instead:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="C:\path\to\OpenSSL"
cmake --build build
```

Run the executable:

```powershell
.\build\Release\pwm.exe
```

The Windows clipboard implementation is built into the executable. A normal interactive console is required for hidden master-password input.

### Tests

Configure and build as above, then run the persistence tests with:

```powershell
ctest --test-dir build --output-on-failure
```

The current tests cover credential create/read/update/delete persistence, authenticated-file tampering, truncated files, legacy migration, vault reopening/tampering, unlock failure cleanup, and rejection of the obsolete cleartext-output option.

### Linux

CMake contains Linux terminal-input and data-directory code, but Linux is **not currently a complete supported build target**: the clipboard backend is missing and the current executable references clipboard operations. A Linux clipboard backend and build validation are required before documenting Linux as supported.

## Data location

The vault is stored in the current user's application-data directory:

- **Windows:** `%LOCALAPPDATA%\pwm`
- **Linux:** `~/.local/share/pwm`

The implementation stores the vault key envelope in `vault.bin` and credential records in `credentials.dat`. These are application data files; do not edit them manually. Keep an independent backup if needed, noting that restoring files does not bypass the master password.

## Typical use

Initialize once:

```text
pwm --init
```

Use the account name by itself for the automatic behavior:

```text
pwm youtube
```

PWM prompts for the master password, then retrieves the existing `youtube` password to the clipboard. If the account is not in the vault, PWM creates and stores a new password, then copies it to the clipboard. Passwords are never printed.

Create a generated password:

```text
pwm --create-pw "youtube"
# Short alias:
pwm -new "youtube"
```

Retrieve it to the clipboard:

```text
pwm --get-pw "youtube"
# Short alias:
pwm -get "youtube"
```

Passwords are never printed to the terminal. The old `--show-pw` option is rejected; retrieved and generated values are copied to the clipboard.

Remove the local vault:

```text
pwm --uninstall
```

Uninstall asks for the master password and then requires typing `DELETE`. It removes vault files only; it does not uninstall the executable or securely erase disk sectors.

## Security status and limitations

This is a course project and an implementation under development, not an audited password manager. **Do not use it to protect real accounts or valuable secrets.**

Important current limitations:

1. The current design has not been independently security-audited. Although OpenSSL's cryptographic RNG is now used, the overall system still requires review.
2. PBKDF2-HMAC-SHA-256 is implemented instead of the planned Argon2id. The iteration count and KDF parameters are currently fixed in code.
3. Per-password AES-GCM authenticates each encrypted password, while a whole-file HMAC protects credential-file records and metadata against modification. Account names remain visible in plaintext. The vault-key file is versioned and its envelope authenticated with AES-GCM.
4. The credential parser has size and structural checks, but the file format and migration logic still need broader testing and review.
5. Key and plaintext zeroization is best-effort only with standard C++ containers. The clipboard is outside the vault's encryption boundary and may be visible to other applications.
6. Deleting files is not equivalent to secure erasure and may leave recoverable copies in backups or filesystem/drive internals.

### Remaining work beyond Checkpoint 2

1. Decide whether to implement Argon2id with persisted KDF parameters or retain PBKDF2 with a documented security rationale.
2. Independently review the cryptographic design, file formats, migration path, and error handling before considering use beyond a course prototype.
3. Improve secure-memory handling and consider clipboard expiration that is safe and reliable after the CLI process exits.
4. Complete and validate platform support, or explicitly restrict supported platforms to Windows until Linux clipboard behavior is implemented.
5. Verify the documented Visual Studio/vcpkg build on a clean Windows machine and commit the completed Checkpoint 2 changes.

See [the short Checkpoint 2 progress note](./docs/checkpoint-2-progress.md) for the current deliverable summary.

## Repository layout

```text
include/                 Public declarations, secure-memory, and cryptographic-random helpers
src/
  main.cpp               CLI parsing and command workflows
  vault.cpp              Vault initialization, key derivation, wrapping, and lifecycle
  credential.cpp         Credential encryption and file persistence
  clipboard.cpp          Windows clipboard implementation
  platform/              Platform-specific password input and data-directory helpers
tests/                   Automated persistence tests
```
