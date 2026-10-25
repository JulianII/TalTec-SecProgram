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
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.size() > 2 && arg.substr(0, 2) == "--") {
            const std::string optionName = arg.substr(2);

            if (cmd.name.empty()) {
                cmd.name = arg;
                continue;
            }

            if (i + 1 < argc && argv[i + 1][0] != '-') {
                cmd.options[optionName] = argv[i + 1];
                ++i;
            } else {
                cmd.options[optionName] = "";
            }
        } else if (arg.size() > 1 && arg[0] == '-') {
            // Short options not currently used
        } else {
            if (cmd.name.empty()) {
                cmd.name = arg;
            } else {
                cmd.positional.push_back(arg);
            }
        }
    }
    return cmd;
}

void printUsage() {
    std::cout << "Usage: pwm <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  --init                          Initialize a new vault and set the master password\n";
    std::cout << "  --uninstall                     Delete the vault and all stored credentials\n";
    std::cout << "  --create-pw --account <name>   Generate and store a password for an account\n";
    std::cout << "  --get-pw --account <name>      Retrieve a password and copy it to the clipboard\n";
    std::cout << "  --get-pw --account <name> --show-pw  Display the password in the terminal\n";
    std::cout << "  --update-pw --account <name>   Generate and store a replacement password\n";
    std::cout << "  --delete-pw --account <name>   Delete a credential\n";
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
        std::cout << "Password stored successfully.\n";
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
        std::cout << "Generated password: " << password.get() << "\n";
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

    if (cmd.name != "--create-pw" && cmd.name != "--get-pw" &&
        cmd.name != "--update-pw" && cmd.name != "--delete-pw") {
        std::cerr << "Unknown command: " << cmd.name << "\n\n";
        printUsage();
        return 1;
    }
    
    // All other commands require an initialized vault
    if (!vault.isInitialized()) {
        std::cerr << "Error: Vault not initialized. Run 'pwm --init' first.\n";
        return 1;
    }
    
    // Check for account parameter
    if (cmd.options.find("account") == cmd.options.end() && 
        (cmd.name == "--create-pw" || cmd.name == "--get-pw" || 
         cmd.name == "--update-pw" || cmd.name == "--delete-pw")) {
        std::cerr << "Error: Missing --account parameter.\n";
        return 1;
    }
    
    const std::string& account = cmd.options.at("account");
    
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
