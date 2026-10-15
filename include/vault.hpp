#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include "credential.hpp"

namespace pwm {

class Vault {
public:
    Vault();
    
    void initialize(const std::string& masterPassword);
    bool validatePassword(const std::string& masterPassword) const;
    void unlock(const std::string& masterPassword);
    void lock();
    bool isInitialized() const;
    bool isUnlocked() const;
    
    const std::string& getVaultPath() const { return vaultPath; }
    const std::string& getDataDirectory() const { return dataDirectory; }
    
    // Credential management
    void storeCredential(const std::string& accountName, const std::string& password);
    std::string retrieveCredential(const std::string& accountName) const;
    void updateCredential(const std::string& accountName, const std::string& newPassword);
    void deleteCredential(const std::string& accountName);
    bool credentialExists(const std::string& accountName) const;
    std::vector<std::string> listAccounts() const;

private:
    std::string dataDirectory;
    std::string vaultPath;
    std::string credentialsPath;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> encryptedMasterKey;
    bool initialized = false;
    bool unlocked = false;
    mutable CredentialManager credentialManager;
    
    void generateSalt();
    std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) const;
    void createVaultDirectory() const;
    void loadCredentials() const;
    void saveCredentials() const;
};

} // namespace pwm
