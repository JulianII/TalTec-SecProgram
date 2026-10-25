#pragma once

#include <string>
#include <vector>
#include <ctime>

namespace pwm {

struct Credential {
    std::string accountName;
    std::vector<unsigned char> encryptedPassword;
    std::vector<unsigned char> nonce; // For authenticated encryption
    time_t createdAt;
    time_t updatedAt;
};

class CredentialManager {
public:
    void setKey(const std::vector<unsigned char>& key);
    void clearKey();

    void storeCredential(const std::string& accountName, const std::string& password);
    Credential retrieveCredential(const std::string& accountName) const;
    void updateCredential(const std::string& accountName, const std::string& newPassword);
    void deleteCredential(const std::string& accountName);
    bool exists(const std::string& accountName) const;
    std::vector<std::string> listAccounts() const;
    
    void saveToFile(const std::string& filepath) const;
    void loadFromFile(const std::string& filepath);
    
    // For Vault class to access
    std::string decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& nonce) const;

private:
    std::vector<Credential> credentials;
    std::vector<unsigned char> encryptionKey;
    
    std::vector<unsigned char> encrypt(const std::string& plaintext, const std::vector<unsigned char>& nonce) const;
    std::vector<unsigned char> generateNonce() const;
};

} // namespace pwm
