# Password Manager (PWM)

A local, single-user command-line password manager developed in C/C++ for the Secure Programming course.

This project was developed during the autumn semester of 2026 as part of the “Secure Programming” course by Julian Lorenz, an Erasmus exchange student from Germany. 

## Scope

The PWM stores credentials in a local encrypted vault. It uses Argon2id to derive a vault key from the user's master password and authenticated encryption to protect credentials.

### Planned features

* Initialize and manage a local vault
* Generate, store, retrieve, update and delete credentials
* Validate the master password using an encrypted vault check
* Encrypt credentials individually while keeping account identifiers searchable
* Copy retrieved passwords to the clipboard by default, with an option to display them in the terminal
* Clear the clipboard after x seconds when it has not changed
* Minimize sensitive data in memory and zeroize sensitive buffers after use

### Out of scope

* Multiple users or account registration
* Persistent unlocked sessions
* Cloud synchronization or any sort of remote storage

## Planned Commands

| Command                                      | Description                                         |
| -------------------------------------------- | --------------------------------------------------- |
| `pwm --init`                                 | Initialize a new vault and set the master password. |
| `pwm --create-pw --account "youtube"`        | Generate and store a password for an account.       |
| `pwm --get-pw --account "youtube"`           | Retrieve a password and copy it to the clipboard.   |
| `pwm --get-pw --account "youtube" --show-pw` | Display the retrieved password in the terminal.     |
| `pwm --update-pw --account "youtube"`        | Generate and store a replacement password.          |
| `pwm --delete-pw --account "youtube"`        | Delete a credential.                                |

*Commands are planned and may change during implementation.*

## Build and Run

### Requirements

An C++ compiler and CMake

### Build

```bash
git clone https://github.com/JulianII/TalTec-SecProgram.git
cd https://github.com/JulianII/TalTec-SecProgram.git

cmake -S . -B build
cmake --build build
```

### Run

Current state does not allow for any command execution (only an Hello World!)

```bash
./build/pwm 
```

On Windows, run the generated executable from the build directory.

*Build instructions will be finalized once the project structure, dependencies and build configuration are implemented.*
