#include "clipboard.hpp"
#include "crypto_random.hpp"
#include "input_validation.hpp"
#include "platform/platform.hpp"
#include "secure_memory.hpp"
#include "structured_log.hpp"
#include "vault.hpp"

#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct Command {
    std::string name;
    std::map<std::string, std::string> options;
    std::vector<std::string> positional;
};

Command parseArguments(int argc, char* argv[]) {
    Command cmd;
    if (argc < 2) {
        return cmd;
    }

    cmd.name = argv[1];
    if (cmd.name == "-new") {
        cmd.name = "--create-pw";
    } else if (cmd.name == "-get") {
        cmd.name = "--get-pw";
    } else if (!cmd.name.empty() && cmd.name.front() != '-') {
        cmd.positional.push_back(cmd.name);
        cmd.name = "--auto";
    }

    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument.size() > 2 && argument.compare(0, 2, "--") == 0) {
            const std::string optionName = argument.substr(2);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                cmd.options[optionName] = argv[++i];
            } else {
                cmd.options[optionName] = "";
            }
        } else if (argument.size() > 1 && argument.front() == '-') {
            cmd.options[argument.substr(1)] = "";
        } else {
            cmd.positional.push_back(argument);
        }
    }
    return cmd;
}

void printUsage() {
    std::cout << "Usage: pwm <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  --init                          Initialize a new vault and set the master password\n";
    std::cout << "  --uninstall                     Delete the vault and all stored credentials\n";
    std::cout << "  pwm <account>                   Retrieve an existing password or create a new one\n";
    std::cout << "  --create-pw, -new <account>    Generate and store a password for an account\n";
    std::cout << "  --get-pw, -get <account>       Retrieve a password and copy it to the clipboard\n";
    std::cout << "  --update-pw <account>          Generate and store a replacement password\n";
    std::cout << "  --delete-pw <account>          Delete a credential\n";
}

pwm::SecureString generateRandomPassword(size_t length = 16) {
    constexpr std::string_view characters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    if (length == 0 || length > pwm::maxSecretBytes) {
        throw std::invalid_argument("Generated password length is invalid");
    }

    pwm::SecureString password;
    const size_t acceptedByteLimit = 256 - (256 % characters.size());
    auto random = pwm::crypto::randomSecureBytes(length);
    size_t randomOffset = 0;

    while (password.size() < length) {
        if (randomOffset == random.size()) {
            random = pwm::crypto::randomSecureBytes(length - password.size());
            randomOffset = 0;
        }
        const unsigned char value = random[randomOffset++];
        if (value >= acceptedByteLimit) {
            continue;
        }
        password.append(characters[value % characters.size()]);
    }
    return password;
}

void copyPasswordToClipboard(std::string_view password) {
    const auto sequenceNumber = pwm::Clipboard::copyToClipboard(password);
    try {
        pwm::Clipboard::scheduleClearAfterDelay(sequenceNumber);
        std::cout << "Clipboard cleanup is scheduled in "
                  << pwm::Clipboard::cleanupDelaySeconds << " seconds.\n";
        pwm::logEvent("info", "clipboard.cleanup_scheduled");
    } catch (const std::exception& error) {
        pwm::logEvent("warning", "clipboard.cleanup_schedule_failed");
        std::cerr << "Warning: Password was copied, but automatic clipboard cleanup "
                     "could not be scheduled: "
                  << error.what() << "\n";
    }
}

pwm::SecureString requestMasterPassword(pwm::Vault& vault) {
    if (vault.isUnlocked()) {
        throw std::logic_error("Vault is already unlocked");
    }
    std::cout << "Vault is locked. Enter master password to unlock: ";
    std::cout.flush();
    auto password = platform::readHiddenPassword();
    std::cout << "\n";
    vault.unlock(password.view());
    pwm::logEvent("info", "vault.unlock_succeeded");
    return password;
}

void handleInit(pwm::Vault& vault) {
    if (vault.isInitialized()) {
        throw std::runtime_error("Vault is already initialized");
    }

    std::cout << "Enter master password: ";
    std::cout.flush();
    auto password = platform::readHiddenPassword();
    std::cout << "\n";
    std::cout << "Confirm master password: ";
    std::cout.flush();
    auto confirmation = platform::readHiddenPassword();
    std::cout << "\n";

    if (password.view() != confirmation.view()) {
        throw std::invalid_argument("Master passwords do not match");
    }
    vault.initialize(password.view());
    pwm::logEvent("info", "vault.initialized");
    std::cout << "Vault initialized successfully.\n";
    std::cout << "Vault location: " << vault.getVaultPath() << "\n";
}

void handleUninstall(pwm::Vault& vault) {
    if (!vault.isInitialized()) {
        throw std::runtime_error("No vault is initialized");
    }

    std::cout << "Enter master password to confirm vault deletion: ";
    std::cout.flush();
    auto password = platform::readHiddenPassword();
    std::cout << "\n";

    std::cout << "This permanently deletes the vault and all stored credentials.\n";
    std::cout << "Type DELETE to continue: ";
    std::cout.flush();
    std::string confirmation;
    char character = 0;
    while (std::cin.get(character) && character != '\n') {
        if (confirmation.size() == 6) {
            while (std::cin.get(character) && character != '\n') {}
            throw std::invalid_argument("Deletion confirmation is too long");
        }
        confirmation.push_back(character);
    }
    if (!std::cin && !std::cin.eof()) {
        throw std::runtime_error("Could not read deletion confirmation");
    }
    if (confirmation != "DELETE") {
        pwm::logEvent("info", "vault.deletion_cancelled");
        std::cout << "Deletion cancelled.\n";
        return;
    }

    vault.deleteVault(password.view());
    pwm::logEvent("info", "vault.deleted");
    std::cout << "Vault deleted successfully.\n";
}

void handleCreatePassword(pwm::Vault& vault, const std::string& account) {
    std::cout << "Generating password for account: " << account << "\n";
    auto password = generateRandomPassword();
    vault.storeCredential(account, password.view());
    pwm::logEvent("info", "credential.created");
    try {
        copyPasswordToClipboard(password.view());
        std::cout << "Password stored and copied to clipboard.\n";
    } catch (const std::exception& error) {
        pwm::logEvent("warning", "clipboard.copy_failed");
        std::cerr << "Warning: Password was stored, but could not be copied to clipboard: "
                  << error.what() << "\n";
    }
}

void handleGetPassword(pwm::Vault& vault, const std::string& account) {
    auto password = vault.retrieveCredential(account);
    try {
        copyPasswordToClipboard(password.view());
        std::cout << "Password for " << account << " copied to clipboard.\n";
        pwm::logEvent("info", "credential.retrieved");
    } catch (const std::exception& error) {
        pwm::logEvent("warning", "clipboard.copy_failed");
        std::cerr << "Warning: Could not copy password to clipboard: "
                  << error.what() << "\n";
    }
}

void handleUpdatePassword(pwm::Vault& vault, const std::string& account) {
    std::cout << "Generating new password for account: " << account << "\n";
    auto password = generateRandomPassword();
    vault.updateCredential(account, password.view());
    pwm::logEvent("info", "credential.updated");
    try {
        copyPasswordToClipboard(password.view());
        std::cout << "Password updated and copied to clipboard.\n";
    } catch (const std::exception& error) {
        pwm::logEvent("warning", "clipboard.copy_failed");
        std::cerr << "Warning: Password was updated, but could not be copied to clipboard: "
                  << error.what() << "\n";
    }
}

void handleDeletePassword(pwm::Vault& vault, const std::string& account) {
    vault.deleteCredential(account);
    pwm::logEvent("info", "credential.deleted");
    std::cout << "Credential for " << account << " deleted successfully.\n";
}

int runCommand(int argc, char* argv[]) {
    if (argc == 1) {
        printUsage();
        return 2;
    }

    Command command = parseArguments(argc, argv);
    if (command.options.find("show-pw") != command.options.end()) {
        throw std::invalid_argument(
            "--show-pw is not supported; passwords are never printed to the terminal");
    }
    if (!command.options.empty()) {
        throw std::invalid_argument("Unsupported command-line option");
    }

    pwm::Vault vault;
    if (command.name == "--init") {
        if (!command.positional.empty()) {
            throw std::invalid_argument("--init does not accept an account name");
        }
        handleInit(vault);
        return 0;
    }
    if (command.name == "--uninstall") {
        if (!command.positional.empty()) {
            throw std::invalid_argument("--uninstall does not accept an account name");
        }
        handleUninstall(vault);
        return 0;
    }

    const bool isCredentialCommand =
        command.name == "--auto" || command.name == "--create-pw" ||
        command.name == "--get-pw" || command.name == "--update-pw" ||
        command.name == "--delete-pw";
    if (!isCredentialCommand) {
        throw std::invalid_argument("Unknown command");
    }
    if (command.positional.size() != 1) {
        throw std::invalid_argument("Expected exactly one account name");
    }

    const std::string& account = command.positional.front();
    pwm::validateAccountName(account);
    if (!vault.isInitialized()) {
        throw std::runtime_error("Vault not initialized. Run 'pwm --init' first");
    }
    if (!vault.isUnlocked()) {
        auto masterPassword = requestMasterPassword(vault);
    }

    if (command.name == "--auto") {
        if (vault.credentialExists(account)) {
            handleGetPassword(vault, account);
        } else {
            handleCreatePassword(vault, account);
        }
    } else if (command.name == "--create-pw") {
        handleCreatePassword(vault, account);
    } else if (command.name == "--get-pw") {
        handleGetPassword(vault, account);
    } else if (command.name == "--update-pw") {
        handleUpdatePassword(vault, account);
    } else {
        handleDeletePassword(vault, account);
    }

    vault.lock();
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
#ifdef _WIN32
    if (argc == 2 && std::string(argv[1]) == "--internal-clear-clipboard") {
        return pwm::Clipboard::runCleanupProcess();
    }
#endif

    try {
        return runCommand(argc, argv);
    } catch (const std::exception& error) {
        pwm::logEvent("error", "cli.command_failed");
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
