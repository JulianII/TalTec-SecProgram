#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <utility>
#include "vault.hpp"
#include "crypto_random.hpp"
#include "platform/platform.hpp"
#include "clipboard.hpp"
#include "secure_memory.hpp"

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
    } else if (!cmd.name.empty() && cmd.name[0] != '-') {
        cmd.positional.push_back(cmd.name);
        cmd.name = "--auto";
    }

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.size() > 2 && arg.substr(0, 2) == "--") {
            const std::string optionName = arg.substr(2);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                cmd.options[optionName] = argv[++i];
            } else {
                cmd.options[optionName] = "";
            }
        } else if (arg.size() > 1 && arg[0] == '-') {
            cmd.options[arg.substr(1)] = "";
        } else {
            cmd.positional.push_back(arg);
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
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    std::string password;
    password.reserve(length);
    const size_t acceptedByteLimit = 256 - (256 % chars.size());
    auto random = pwm::crypto::randomBytes(length);
    size_t randomOffset = 0;

    while (password.size() < length) {
        if (randomOffset == random.size()) {
            random = pwm::crypto::randomBytes(length - password.size());
            randomOffset = 0;
        }
        const unsigned char value = random[randomOffset++];
        if (value >= acceptedByteLimit) {
            continue;
        }
        password += chars[value % chars.size()];
    }
    return pwm::SecureString(std::move(password));
}

bool ensureVaultUnlocked(pwm::Vault& vault) {
    if (vault.isUnlocked()) {
        return true;
    }
    
    std::cout << "Vault is locked. Enter master password to unlock: ";
    pwm::SecureString password;
    password = platform::readHiddenPassword();
    std::cout << "\n";
    
    try {
        vault.unlock(password.get());
        password.clear();
        return true;
    } catch (const std::exception& e) {
        password.clear();
        std::cerr << "Error unlocking vault: " << e.what() << "\n";
        return false;
    }
}

void handleInit(pwm::Vault& vault) {
    if (vault.isInitialized()) {
        std::cerr << "Error: Vault already initialized.\n";
        std::cerr << "Vault location: " << vault.getVaultPath() << "\n";
        exit(1);
    }
    
    std::cout << "Enter master password: ";
    pwm::SecureString password;
    password = platform::readHiddenPassword();
    std::cout << "\n";
    
    std::cout << "Confirm master password: ";
    pwm::SecureString confirm;
    confirm = platform::readHiddenPassword();
    std::cout << "\n";
    
    if (password.get() != confirm.get()) {
        password.clear();
        confirm.clear();
        std::cerr << "Error: Passwords do not match.\n";
        exit(1);
    }
    
    if (password.get().empty()) {
        password.clear();
        confirm.clear();
        std::cerr << "Error: Password cannot be empty.\n";
        exit(1);
    }
    
    try {
        vault.initialize(password.get());
        password.clear();
        confirm.clear();
        std::cout << "Vault initialized successfully.\n";
        std::cout << "Vault location: " << vault.getVaultPath() << "\n";
    } catch (const std::exception& e) {
        password.clear();
        confirm.clear();
        std::cerr << "Error: " << e.what() << "\n";
        exit(1);
    }
}

void handleUninstall(pwm::Vault& vault) {
    if (!vault.isInitialized()) {
        std::cerr << "Error: No vault is initialized.\n";
        exit(1);
    }

    std::cout << "Enter master password to confirm vault deletion: ";
    pwm::SecureString password;
    password = platform::readHiddenPassword();
    std::cout << "\n";

    std::cout << "This permanently deletes the vault and all stored credentials.\n";
    std::cout << "Type DELETE to continue: ";
    std::string confirmation;
    std::getline(std::cin, confirmation);
    if (confirmation != "DELETE") {
        std::cout << "Deletion cancelled.\n";
        return;
    }

    try {
        vault.deleteVault(password.get());
        password.clear();
        std::cout << "Vault deleted successfully.\n";
    } catch (const std::exception& e) {
        password.clear();
        std::cerr << "Error deleting vault: " << e.what() << "\n";
        exit(1);
    }
}

void handleCreatePassword(pwm::Vault& vault, const std::string& account) {
    if (!ensureVaultUnlocked(vault)) {
        exit(1);
    }
    
    std::cout << "Generating password for account: " << account << "\n";
    pwm::SecureString password;
    try {
        password = generateRandomPassword();
        vault.storeCredential(account, password.get());
        try {
            pwm::Clipboard::copyToClipboard(password.get());
            std::cout << "Password stored and copied to clipboard.\n";
        } catch (const std::exception& e) {
            std::cerr << "Warning: Password was stored, but could not be copied to clipboard: "
                      << e.what() << "\n";
        }
        password.clear();
    } catch (const std::exception& e) {
        password.clear();
        std::cerr << "Error: " << e.what() << "\n";
        exit(1);
    }
}

void handleGetPassword(pwm::Vault& vault, const std::string& account) {
    if (!ensureVaultUnlocked(vault)) {
        exit(1);
    }
    
    try {
        pwm::SecureString password;
        password = vault.retrieveCredential(account);
        try {
            pwm::Clipboard::copyToClipboard(password.get());
            std::cout << "Password for " << account << " copied to clipboard.\n";
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not copy password to clipboard: " << e.what() << "\n";
        }
        
        password.clear();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        exit(1);
    }
}

void handleUpdatePassword(pwm::Vault& vault, const std::string& account) {
    if (!ensureVaultUnlocked(vault)) {
        exit(1);
    }
    
    std::cout << "Generating new password for account: " << account << "\n";
    pwm::SecureString password;
    try {
        password = generateRandomPassword();
        vault.updateCredential(account, password.get());
        try {
            pwm::Clipboard::copyToClipboard(password.get());
            std::cout << "Password updated and copied to clipboard.\n";
        } catch (const std::exception& e) {
            std::cerr << "Warning: Password was updated, but could not be copied to clipboard: "
                      << e.what() << "\n";
        }
        password.clear();
    } catch (const std::exception& e) {
        password.clear();
        std::cerr << "Error: " << e.what() << "\n";
        exit(1);
    }
}

void handleDeletePassword(pwm::Vault& vault, const std::string& account) {
    if (!ensureVaultUnlocked(vault)) {
        exit(1);
    }
    
    try {
        vault.deleteCredential(account);
        std::cout << "Credential for " << account << " deleted successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        printUsage();
        return 1;
    }
    
    Command cmd = parseArguments(argc, argv);
    pwm::Vault vault;
    
    if (cmd.name == "--init") {
        handleInit(vault);
        return 0;
    }

    if (cmd.name == "--uninstall") {
        handleUninstall(vault);
        return 0;
    }

    if (cmd.name != "--auto" && cmd.name != "--create-pw" && cmd.name != "--get-pw" &&
        cmd.name != "--update-pw" && cmd.name != "--delete-pw") {
        std::cerr << "Unknown command: " << cmd.name << "\n\n";
        printUsage();
        return 1;
    }

    if (cmd.options.find("show-pw") != cmd.options.end()) {
        std::cerr << "Error: --show-pw is not supported; passwords are never printed to the terminal.\n";
        return 1;
    }

    // Each credential command operates on exactly one account.
    if (cmd.positional.size() != 1) {
        std::cerr << "Error: Expected exactly one account name after the command.\n";
        return 1;
    }

    // All credential commands require an initialized vault
    if (!vault.isInitialized()) {
        std::cerr << "Error: Vault not initialized. Run 'pwm --init' first.\n";
        return 1;
    }
    
    const std::string& account = cmd.positional.front();

    if (cmd.name == "--auto") {
        if (!ensureVaultUnlocked(vault)) {
            return 1;
        }

        if (vault.credentialExists(account)) {
            handleGetPassword(vault, account);
        } else {
            handleCreatePassword(vault, account);
        }

        vault.lock();
        return 0;
    }
    
    if (cmd.name == "--create-pw") {
        handleCreatePassword(vault, account);
        vault.lock();
        return 0;
    }
    
    if (cmd.name == "--get-pw") {
        handleGetPassword(vault, account);
        vault.lock();
        return 0;
    }
    
    if (cmd.name == "--update-pw") {
        handleUpdatePassword(vault, account);
        vault.lock();
        return 0;
    }
    
    if (cmd.name == "--delete-pw") {
        handleDeletePassword(vault, account);
        vault.lock();
        return 0;
    }
    
    return 0;
}
