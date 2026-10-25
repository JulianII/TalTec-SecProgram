#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <random>
#include <chrono>
#include <thread>
#include "vault.hpp"
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
            if (optionName == "show-pw") {
                cmd.options[optionName] = "";
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
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
    std::cout << "  --get-pw, -get <account> --show-pw  Display the password in the terminal\n";
    std::cout << "  --update-pw <account>          Generate and store a replacement password\n";
    std::cout << "  --delete-pw <account>          Delete a credential\n";
}

std::string generateRandomPassword(size_t length = 16) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    
    std::string password;
    for (size_t i = 0; i < length; ++i) {
        password += chars[dis(gen)];
    }
    return password;
}

// Function to clear clipboard after a delay
void clearClipboardAfterDelay(int seconds) {
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    // Check if clipboard still has our password
    try {
        std::string current = pwm::Clipboard::getClipboardText();
        // Only clear if it's still a password (simple heuristic: non-empty and not too long)
        if (!current.empty() && current.size() < 100) {
            pwm::Clipboard::clearClipboard();
        }
    } catch (...) {
        // Ignore errors
    }
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
    password = generateRandomPassword();
    
    try {
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

void handleGetPassword(pwm::Vault& vault, const std::string& account, bool showInTerminal) {
    if (!ensureVaultUnlocked(vault)) {
        exit(1);
    }
    
    try {
        pwm::SecureString password;
        password = vault.retrieveCredential(account);
        
        if (showInTerminal) {
            std::cout << "Password for " << account << ": " << password.get() << "\n";
        } else {
            // Copy to clipboard
            try {
                pwm::Clipboard::copyToClipboard(password.get());
                std::cout << "Password for " << account << " copied to clipboard.\n";
                
                // Start thread to clear clipboard after 30 seconds
                std::thread clearThread([]() {
                    clearClipboardAfterDelay(30);
                });
                clearThread.detach();
            } catch (const std::exception& e) {
                std::cerr << "Warning: Could not copy to clipboard: " << e.what() << "\n";
            }
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
    password = generateRandomPassword();
    
    try {
        vault.updateCredential(account, password.get());
        std::cout << "Password updated successfully.\n";
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

    if (cmd.options.find("show-pw") != cmd.options.end() &&
        cmd.name != "--get-pw" && cmd.name != "--auto") {
        std::cerr << "Error: --show-pw can only be used with --get-pw, -get, or the automatic account command.\n";
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
            const bool showInTerminal = cmd.options.find("show-pw") != cmd.options.end();
            handleGetPassword(vault, account, showInTerminal);
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
        bool showInTerminal = (cmd.options.find("show-pw") != cmd.options.end());
        handleGetPassword(vault, account, showInTerminal);
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
