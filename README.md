# PWM — Local Password Manager

PWM is a single-user command-line password manager written in C++20 for a Secure Programming course. It is intended to keep a user's generated passwords in a local vault and require the master password for each operation that accesses stored credentials.

> **Project status: core prototype in progress.** The CLI and basic vault workflows are implemented, but this project has not been security-audited and is not ready for production use. See [Security status and limitations](#security-status-and-limitations) before storing real credentials.

## Scope

### In scope

- Initialize or explicitly remove a local vault.
- Generate, store, retrieve, replace, and delete account passwords.
- Require a master password when an operation accesses the vault.
- Lock the vault internally after each operation; there are no persistent unlocked sessions or public `--unlock` / `--lock` commands.
- Copy retrieved passwords to the Windows clipboard by default, with an option to print them instead.
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

### Not yet complete

- The current key derivation is **PBKDF2, not Argon2id**. Argon2id was part of the initial design, but has not been implemented.
- Random bytes and generated passwords currently use `std::random_device` together with `std::mt19937`. This is not a suitable cryptographic random-number generation design and must be replaced with a cryptographic RNG supplied by the crypto library.
- The on-disk credential format has no robust versioned container, strict size limits, or atomic/transactional writes. Account names and record metadata are not encrypted or authenticated as a complete file.
- The password-generator implementation and clipboard timeout logic need security hardening. In particular, clipboard clearing must not remove clipboard content that another application has since replaced.
- Secure-memory handling is partial. Standard C++ strings and vectors can make copies, and not every sensitive temporary buffer is guaranteed to be zeroized.
- The CLI does not yet have automated unit or integration tests.
- Linux support is incomplete: terminal input and data-directory code exist, but clipboard integration is currently implemented for Windows only and the current build does not provide a Linux clipboard backend.
- The uninstall operation removes vault files; it does not securely overwrite storage. Filesystem, SSD, backup, and journal behavior can retain recoverable data.

## Commands

| Command | Description |
| --- | --- |
| `pwm --init` | Create a vault and set the master password. |
| `pwm "youtube"` | Retrieve the account password if it exists; otherwise generate, store, and copy a new password to the clipboard. |
| `pwm --create-pw "youtube"` or `pwm -new "youtube"` | Generate and store a password, then copy it to the clipboard. |
| `pwm --get-pw "youtube"` or `pwm -get "youtube"` | Retrieve a password and copy it to the clipboard. |
| `pwm --get-pw "youtube" --show-pw` or `pwm -get "youtube" --show-pw` | Print the retrieved password in the terminal instead of copying it. |
| `pwm --update-pw "youtube"` | Generate and store a replacement password. |
| `pwm --delete-pw "youtube"` | Delete a credential. |
| `pwm --uninstall` | Permanently remove the vault after master-password and `DELETE` confirmation. |

The commands above are the implemented CLI surface. Unlocking and locking are internal parts of each credential command, not separate CLI commands.

## Build

### Requirements

- CMake 3.20 or newer.
- A C++20 compiler.
- OpenSSL development headers and libraries (the implementation uses OpenSSL EVP APIs).

The current CMake configuration first checks for libsodium, but the source code currently depends on OpenSSL APIs. OpenSSL must therefore be available when building.

### Windows (PowerShell)

From the repository root:

```powershell
cmake -S . -B build
cmake --build build
```

If OpenSSL is installed in a non-standard location, configure CMake with its installation prefix, for example:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="C:\path\to\OpenSSL"
cmake --build build
```

Run the executable:

```powershell
.\build\pwm.exe
```

The Windows clipboard implementation is built into the executable. A normal interactive console is required for hidden master-password input.

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

PWM prompts for the master password, then retrieves the existing `youtube` password to the clipboard. If the account is not in the vault, PWM creates and stores a new password, then copies it to the clipboard. Neither path prints the password unless `--show-pw` is explicitly provided for retrieval.

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

Or explicitly display it in the terminal:

```text
pwm --get-pw "youtube" --show-pw
```

`--show-pw` is an explicit opt-in that writes the retrieved password in cleartext to the terminal. Avoid it where terminal output may be recorded or visible to others.

Remove the local vault:

```text
pwm --uninstall
```

Uninstall asks for the master password and then requires typing `DELETE`. It removes vault files only; it does not uninstall the executable or securely erase disk sectors.

## Security status and limitations

This is a course project and an implementation under development, not an audited password manager. **Do not use it to protect real accounts or valuable secrets.**

Important current limitations:

1. The random-number generation is not yet based on a cryptographic RNG. This affects salts/nonces, vault-key generation, and generated passwords and is a blocker for trustworthy security.
2. PBKDF2-HMAC-SHA-256 is implemented instead of the planned Argon2id. The iteration count and KDF parameters are currently fixed in code.
3. Per-password AES-GCM authenticates the encrypted password, but the credential file as a whole is not protected against record deletion, reordering, or metadata changes. Account names are visible in plaintext.
4. File writes are not atomic, and malformed input handling and resource limits need further hardening.
5. Key and plaintext zeroization is best-effort only with standard C++ containers. The clipboard is outside the vault's encryption boundary and may be visible to other applications.
6. Deleting files is not equivalent to secure erasure and may leave recoverable copies in backups or filesystem/drive internals.

### Recommended core implementation priorities

1. Replace `std::mt19937`-based randomness with OpenSSL's cryptographic random-byte API.
2. Implement Argon2id with versioned, persisted KDF parameters, or explicitly revise the security design and document a justified PBKDF2 configuration.
3. Define a versioned vault/credential file format with strict parsing, size limits, authenticated metadata, and atomic writes.
4. Add automated tests for initialization, correct and incorrect master passwords, tampering, malformed files, and every credential operation.
5. Improve secure-memory handling and make clipboard clearing conditional on the clipboard still containing the exact value PWM placed there.
6. Complete and validate platform support, or explicitly restrict supported platforms to Windows until Linux clipboard behavior is implemented.

## Repository layout

```text
include/                 Public declarations for vault, credentials, and secure-memory helpers
src/
  main.cpp               CLI parsing and command workflows
  vault.cpp              Vault initialization, key derivation, wrapping, and lifecycle
  credential.cpp         Credential encryption and file persistence
  clipboard.cpp          Windows clipboard implementation
  platform/              Platform-specific password input and data-directory helpers
tests/                   Reserved for automated tests (not yet populated)
```
