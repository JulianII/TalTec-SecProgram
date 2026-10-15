#include "vault.hpp"
#include "platform/platform.hpp"
#include <fstream>
#include <filesystem>
#include <random>
#include <algorithm>

namespace fs = std::filesystem;

namespace pwm {

Vault::Vault() : dataDirectory(platform::getUserDataDirectory()), 
                 vaultPath(dataDirectory + "/vault.bin"),
                 credentialsPath(dataDirectory + "/credentials.dat") {}

void Vault::generateSalt() {
    salt.resize(32); // 256-bit salt
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : salt) {
        byte = static_cast<unsigned char>(dis(gen));
    }
}

std::vector<unsigned char> Vault::deriveKey(const std::string& password, const std::vector<unsigned char>& salt) const {
    // TODO: Replace with Argon2id when crypto library is available
    // For now, use a simple hash (not secure, just for structure)
    std::vector<unsigned char> key(32);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<unsigned char>(password[i % password.size()] ^ salt[i % salt.size()]);
    }
    return key;
}

void Vault::createVaultDirectory() const {
    if (!fs::exists(dataDirectory)) {
        fs::create_directories(dataDirectory);
    }
}

void Vault::initialize(const std::string& masterPassword) {
    createVaultDirectory();
    generateSalt();
    
    // Derive key from master password
    auto key = deriveKey(masterPassword, salt);
    
    // For now, just store the salt
    // In a real implementation, we would:
    // 1. Generate a random vault key
    // 2. Encrypt it with the derived key
    // 3. Store the encrypted vault key + salt + Argon2 parameters
    
    std::ofstream vaultFile(vaultPath, std::ios::binary);
    if (!vaultFile) {
        throw std::runtime_error("Could not create vault file");
    }
    
    // Write salt
    vaultFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    
    // Write a magic header to identify the vault
    const char magic[] = "PWM_VAULT_01";
    vaultFile.write(magic, sizeof(magic));
    
    initialized = true;
    unlocked = false;
}

bool Vault::validatePassword(const std::string& masterPassword) const {
    if (!isInitialized()) {
        return false;
    }
    
    // In a real implementation, we would:
    // 1. Read the salt from the vault file
    // 2. Derive the key from the password
    // 3. Try to decrypt the vault key
    // 4. Verify the decryption was successful
    
    // For now, just check if the file exists
    return fs::exists(vaultPath);
}

bool Vault::isInitialized() const {
    return initialized || fs::exists(vaultPath);
}

bool Vault::isUnlocked() const {
    return unlocked;
}

void Vault::unlock(const std::string& masterPassword) {
    if (!validatePassword(masterPassword)) {
        throw std::runtime_error("Invalid password");
    }
    unlocked = true;
    loadCredentials();
}

void Vault::lock() {
    unlocked = false;
    saveCredentials();
}

void Vault::loadCredentials() const {
    if (fs::exists(credentialsPath)) {
        credentialManager.loadFromFile(credentialsPath);
    }
}

void Vault::saveCredentials() const {
    credentialManager.saveToFile(credentialsPath);
}

void Vault::storeCredential(const std::string& accountName, const std::string& password) {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.storeCredential(accountName, password);
    saveCredentials();
}

std::string Vault::retrieveCredential(const std::string& accountName) const {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    auto cred = credentialManager.retrieveCredential(accountName);
    return credentialManager.decrypt(cred.encryptedPassword, cred.nonce);
}

void Vault::updateCredential(const std::string& accountName, const std::string& newPassword) {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.updateCredential(accountName, newPassword);
    saveCredentials();
}

void Vault::deleteCredential(const std::string& accountName) {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.deleteCredential(accountName);
    saveCredentials();
}

bool Vault::credentialExists(const std::string& accountName) const {
    if (!isUnlocked()) {
        return false;
    }
    return credentialManager.exists(accountName);
}

std::vector<std::string> Vault::listAccounts() const {
    if (!isUnlocked()) {
        return {};
    }
    return credentialManager.listAccounts();
}

} // namespace pwm
