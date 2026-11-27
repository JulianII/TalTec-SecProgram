#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>
#include "credential.hpp"
#include "secure_memory.hpp"

namespace pwm {

class Vault {
public:
    Vault();
    ~Vault();
    
    void initialize(std::string_view masterPassword);
    void deleteVault(std::string_view masterPassword);
    bool validatePassword(std::string_view masterPassword) const;
    void unlock(std::string_view masterPassword);
    void lock();
    bool isInitialized() const;
    bool isUnlocked() const;
    
    const std::string& getVaultPath() const { return vaultPath; }
    const std::string& getDataDirectory() const { return dataDirectory; }
    
    // Credential management
    void storeCredential(std::string_view accountName, std::string_view password);
    SecureString retrieveCredential(std::string_view accountName) const;
    void updateCredential(std::string_view accountName, std::string_view newPassword);
    void deleteCredential(std::string_view accountName);
    bool credentialExists(std::string_view accountName) const;
    std::vector<std::string> listAccounts() const;

private:
    std::string dataDirectory;
    std::string vaultPath;
    std::string credentialsPath;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> encryptedMasterKey;
    SecureBuffer vaultKey;
    bool initialized = false;
    bool unlocked = false;
    mutable CredentialManager credentialManager;
    
    void generateSalt();
    SecureBuffer deriveKey(std::string_view password,
                           const std::vector<unsigned char>& salt) const;
    void generateVaultKey();
    SecureBuffer loadVaultKey(std::string_view masterPassword) const;
    void saveVaultKey(std::string_view masterPassword, const SecureBuffer& keyToStore) const;
    void createVaultDirectory() const;
    void loadCredentials() const;
    void saveCredentials() const;
};

} // namespace pwm
