#include "credential.hpp"
#include <fstream>
#include <filesystem>
#include <random>
#include <algorithm>

namespace fs = std::filesystem;

namespace pwm {

std::vector<unsigned char> CredentialManager::generateNonce() const {
    std::vector<unsigned char> nonce(24); // 192-bit nonce for XChaCha20-Poly1305
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : nonce) {
        byte = static_cast<unsigned char>(dis(gen));
    }
    return nonce;
}

std::vector<unsigned char> CredentialManager::encrypt(const std::string& plaintext) const {
    // TODO: Replace with actual authenticated encryption (XChaCha20-Poly1305)
    // For now, just return the plaintext as "encrypted" data
    std::vector<unsigned char> result(plaintext.begin(), plaintext.end());
    // In a real implementation:
    // 1. Generate a random nonce
    // 2. Encrypt the plaintext with the vault key
    // 3. Return nonce + ciphertext + mac
    return result;
}

std::string CredentialManager::decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& nonce) const {
    // TODO: Replace with actual decryption
    // For now, just return the ciphertext as a string
    return std::string(ciphertext.begin(), ciphertext.end());
}

void CredentialManager::storeCredential(const std::string& accountName, const std::string& password) {
    // Check if credential already exists
    for (const auto& cred : credentials) {
        if (cred.accountName == accountName) {
            throw std::runtime_error("Credential already exists for account: " + accountName);
        }
    }
    
    Credential cred;
    cred.accountName = accountName;
    cred.encryptedPassword = encrypt(password);
    cred.nonce = generateNonce();
    cred.createdAt = std::time(nullptr);
    cred.updatedAt = cred.createdAt;
    
    credentials.push_back(cred);
}

Credential CredentialManager::retrieveCredential(const std::string& accountName) const {
    for (const auto& cred : credentials) {
        if (cred.accountName == accountName) {
            return cred;
        }
    }
    throw std::runtime_error("Credential not found for account: " + accountName);
}

void CredentialManager::updateCredential(const std::string& accountName, const std::string& newPassword) {
    for (auto& cred : credentials) {
        if (cred.accountName == accountName) {
            cred.encryptedPassword = encrypt(newPassword);
            cred.updatedAt = std::time(nullptr);
            return;
        }
    }
    throw std::runtime_error("Credential not found for account: " + accountName);
}

void CredentialManager::deleteCredential(const std::string& accountName) {
    auto it = std::remove_if(credentials.begin(), credentials.end(),
        [&accountName](const Credential& cred) { return cred.accountName == accountName; });
    
    if (it == credentials.end()) {
        throw std::runtime_error("Credential not found for account: " + accountName);
    }
    
    credentials.erase(it, credentials.end());
}

bool CredentialManager::exists(const std::string& accountName) const {
    return std::any_of(credentials.begin(), credentials.end(),
        [&accountName](const Credential& cred) { return cred.accountName == accountName; });
}

std::vector<std::string> CredentialManager::listAccounts() const {
    std::vector<std::string> names;
    for (const auto& cred : credentials) {
        names.push_back(cred.accountName);
    }
    return names;
}

void CredentialManager::saveToFile(const std::string& filepath) const {
    std::ofstream out(filepath, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Could not open file for writing: " + filepath);
    }
    
    // Simple serialization: account_name\0password_size\0password_data\0nonce_data
    for (const auto& cred : credentials) {
        // Write account name
        out.write(cred.accountName.c_str(), cred.accountName.size());
        out.put('\0');
        
        // Write encrypted password
        out.write(reinterpret_cast<const char*>(cred.encryptedPassword.data()), cred.encryptedPassword.size());
        out.put('\0');
        
        // Write nonce
        out.write(reinterpret_cast<const char*>(cred.nonce.data()), cred.nonce.size());
        out.put('\0');
    }
}

void CredentialManager::loadFromFile(const std::string& filepath) {
    std::ifstream in(filepath, std::ios::binary);
    if (!in) {
        if (fs::exists(filepath)) {
            throw std::runtime_error("Could not open file for reading: " + filepath);
        }
        // File doesn't exist yet, that's fine
        return;
    }
    
    credentials.clear();
    
    while (in.peek() != EOF) {
        Credential cred;
        
        // Read account name
        std::getline(in, cred.accountName, '\0');
        if (cred.accountName.empty() && in.peek() == EOF) break;
        
        // Read encrypted password
        std::string passwordData;
        std::getline(in, passwordData, '\0');
        cred.encryptedPassword.assign(passwordData.begin(), passwordData.end());
        
        // Read nonce
        std::string nonceData;
        std::getline(in, nonceData, '\0');
        cred.nonce.assign(nonceData.begin(), nonceData.end());
        
        cred.createdAt = std::time(nullptr);
        cred.updatedAt = cred.createdAt;
        
        credentials.push_back(cred);
    }
}

} // namespace pwm
