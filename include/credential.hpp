#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <ctime>
#include "secure_memory.hpp"

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
    void setKey(const SecureBuffer& key);
    void clearKey();

    void storeCredential(std::string_view accountName, std::string_view password);
    Credential retrieveCredential(std::string_view accountName) const;
    void updateCredential(std::string_view accountName, std::string_view newPassword);
    void deleteCredential(std::string_view accountName);
    bool exists(std::string_view accountName) const;
    std::vector<std::string> listAccounts() const;
    
    void saveToFile(const std::string& filepath) const;
    void loadFromFile(const std::string& filepath);
    
    // For Vault class to access
    SecureString decrypt(const std::vector<unsigned char>& ciphertext,
                         const std::vector<unsigned char>& nonce) const;

private:
    std::vector<Credential> credentials;
    SecureBuffer encryptionKey;
    
    std::vector<unsigned char> encrypt(std::string_view plaintext,
                                       const std::vector<unsigned char>& nonce) const;
    std::vector<unsigned char> generateNonce() const;
};

} // namespace pwm
