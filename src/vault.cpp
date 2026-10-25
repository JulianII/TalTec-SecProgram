#include "vault.hpp"
#include "platform/platform.hpp"
#include <fstream>
#include <filesystem>
#include <random>
#include <algorithm>
#include <openssl/evp.h>

namespace fs = std::filesystem;

namespace {

std::vector<unsigned char> randomBytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : bytes) {
        byte = static_cast<unsigned char>(dist(gen));
    }
    return bytes;
}

std::vector<unsigned char> encryptWithAesGcm(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& nonce,
    std::vector<unsigned char>& tagOut) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-256-GCM requires a 32-byte key");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("AES-256-GCM requires a 12-byte nonce");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + 16, 0);
    int outLen1 = 0;
    int outLen2 = 0;
    tagOut.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Could not allocate OpenSSL cipher context");
    }

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
            EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen1, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagOut.data()) != 1) {
            throw std::runtime_error("Failed to encrypt vault key with AES-256-GCM");
        }

        ciphertext.resize(static_cast<size_t>(outLen1 + outLen2));
        std::vector<unsigned char> result;
        result.reserve(ciphertext.size() + tagOut.size());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tagOut.begin(), tagOut.end());
        EVP_CIPHER_CTX_free(ctx);
        return result;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<unsigned char> decryptWithAesGcm(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& ciphertextAndTag) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-256-GCM requires a 32-byte key");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("AES-256-GCM requires a 12-byte nonce");
    }
    if (ciphertextAndTag.size() < 16) {
        throw std::runtime_error("Encrypted vault key is incomplete");
    }

    std::vector<unsigned char> tag(ciphertextAndTag.end() - 16, ciphertextAndTag.end());
    std::vector<unsigned char> ciphertext(ciphertextAndTag.begin(), ciphertextAndTag.end() - 16);
    std::vector<unsigned char> plaintext(ciphertext.size() + 16, 0);
    int outLen1 = 0;
    int outLen2 = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Could not allocate OpenSSL cipher context");
    }

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
            EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1 ||
            EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
            throw std::runtime_error("Failed to decrypt vault key");
        }

        plaintext.resize(static_cast<size_t>(outLen1 + outLen2));
        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

}  // namespace

namespace pwm {

Vault::Vault() : dataDirectory(platform::getUserDataDirectory()),
                 vaultPath(dataDirectory + "/vault.bin"),
                 credentialsPath(dataDirectory + "/credentials.dat") {}

void Vault::generateSalt() {
    salt.resize(16);
    salt = randomBytes(16);
}

std::vector<unsigned char> Vault::deriveKey(const std::string& password, const std::vector<unsigned char>& saltBytes) const {
    std::vector<unsigned char> key(32, 0);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), -1,
        saltBytes.data(), static_cast<int>(saltBytes.size()),
        200000, EVP_sha256(), static_cast<int>(key.size()), key.data()) != 1) {
        throw std::runtime_error("Failed to derive a vault key from the master password");
    }
    return key;
}

void Vault::generateVaultKey() {
    vaultKey = randomBytes(32);
}

void Vault::createVaultDirectory() const {
    if (!fs::exists(dataDirectory)) {
        fs::create_directories(dataDirectory);
    }
}

std::vector<unsigned char> Vault::loadVaultKey(const std::string& masterPassword) const {
    std::ifstream vaultFile(vaultPath, std::ios::binary);
    if (!vaultFile) {
        throw std::runtime_error("Vault file is missing or unreadable");
    }

    const std::vector<unsigned char> saltPrefix(16, 0);
    const std::vector<unsigned char> expectedMagic = {'P', 'W', 'M', '_', 'V', 'A', 'U', 'L', 'T', '_', '0', '1'};

    std::vector<unsigned char> saltRead(16);
    vaultFile.read(reinterpret_cast<char*>(saltRead.data()), static_cast<std::streamsize>(saltRead.size()));
    if (vaultFile.gcount() != static_cast<std::streamsize>(saltRead.size())) {
        throw std::runtime_error("Vault file is truncated");
    }

    std::vector<unsigned char> nonce(12);
    vaultFile.read(reinterpret_cast<char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
    if (vaultFile.gcount() != static_cast<std::streamsize>(nonce.size())) {
        throw std::runtime_error("Vault nonce is missing");
    }

    const size_t encryptedSize = 48;
    std::vector<unsigned char> encryptedKeyAndTag(encryptedSize);
    vaultFile.read(reinterpret_cast<char*>(encryptedKeyAndTag.data()), static_cast<std::streamsize>(encryptedSize));
    if (vaultFile.gcount() != static_cast<std::streamsize>(encryptedSize)) {
        throw std::runtime_error("Encrypted vault key is incomplete");
    }

    std::vector<unsigned char> magic(12);
    vaultFile.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
    if (vaultFile.gcount() != static_cast<std::streamsize>(magic.size()) || magic != expectedMagic) {
        throw std::runtime_error("Vault header is invalid");
    }

    const auto derivedKey = deriveKey(masterPassword, saltRead);
    return decryptWithAesGcm(derivedKey, nonce, encryptedKeyAndTag);
}

void Vault::saveVaultKey(const std::string& masterPassword, const std::vector<unsigned char>& keyToStore) const {
    const auto derivedKey = deriveKey(masterPassword, salt);
    const auto nonce = randomBytes(12);
    std::vector<unsigned char> tag;
    const auto encryptedKeyAndTag = encryptWithAesGcm(derivedKey, keyToStore, nonce, tag);

    std::ofstream vaultFile(vaultPath, std::ios::binary | std::ios::trunc);
    if (!vaultFile) {
        throw std::runtime_error("Could not create vault file");
    }

    vaultFile.write(reinterpret_cast<const char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
    vaultFile.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
    vaultFile.write(reinterpret_cast<const char*>(encryptedKeyAndTag.data()), static_cast<std::streamsize>(encryptedKeyAndTag.size()));

    const std::vector<unsigned char> magic = {'P', 'W', 'M', '_', 'V', 'A', 'U', 'L', 'T', '_', '0', '1'};
    vaultFile.write(reinterpret_cast<const char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
}

void Vault::initialize(const std::string& masterPassword) {
    createVaultDirectory();
    generateSalt();
    generateVaultKey();
    saveVaultKey(masterPassword, vaultKey);

    initialized = true;
    unlocked = false;
    credentialManager.clearKey();
}

void Vault::deleteVault(const std::string& masterPassword) {
    if (!isInitialized()) {
        throw std::runtime_error("Vault is not initialized");
    }
    if (!validatePassword(masterPassword)) {
        throw std::runtime_error("Invalid master password or vault data");
    }

    credentialManager.clearKey();
    std::fill(vaultKey.begin(), vaultKey.end(), 0);
    vaultKey.clear();
    unlocked = false;

    std::error_code error;
    fs::remove(credentialsPath, error);
    if (error) {
        throw std::runtime_error("Could not delete credentials file: " + error.message());
    }

    fs::remove(vaultPath, error);
    if (error) {
        throw std::runtime_error("Could not delete vault file: " + error.message());
    }

    fs::remove(dataDirectory, error);
    if (error) {
        throw std::runtime_error("Could not remove empty vault data directory: " + error.message());
    }

    initialized = false;
}

bool Vault::validatePassword(const std::string& masterPassword) const {
    if (!isInitialized()) {
        return false;
    }

    try {
        const auto loadedKey = loadVaultKey(masterPassword);
        return loadedKey.size() == 32;
    } catch (...) {
        return false;
    }
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

    vaultKey = loadVaultKey(masterPassword);
    credentialManager.setKey(vaultKey);
    unlocked = true;
    loadCredentials();
}

void Vault::lock() {
    if (!isUnlocked()) {
        return;
    }

    saveCredentials();
    credentialManager.clearKey();
    std::fill(vaultKey.begin(), vaultKey.end(), 0);
    vaultKey.clear();
    unlocked = false;
}

void Vault::loadCredentials() const {
    if (fs::exists(credentialsPath)) {
        credentialManager.loadFromFile(credentialsPath);
    }
}

void Vault::saveCredentials() const {
    if (!fs::exists(dataDirectory)) {
        createVaultDirectory();
    }
    credentialManager.saveToFile(credentialsPath);
}

void Vault::storeCredential(const std::string& accountName, const std::string& password) {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.setKey(vaultKey);
    credentialManager.storeCredential(accountName, password);
    saveCredentials();
}

std::string Vault::retrieveCredential(const std::string& accountName) const {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.setKey(vaultKey);
    auto cred = credentialManager.retrieveCredential(accountName);
    return credentialManager.decrypt(cred.encryptedPassword, cred.nonce);
}

void Vault::updateCredential(const std::string& accountName, const std::string& newPassword) {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.setKey(vaultKey);
    credentialManager.updateCredential(accountName, newPassword);
    saveCredentials();
}

void Vault::deleteCredential(const std::string& accountName) {
    if (!isUnlocked()) {
        throw std::runtime_error("Vault is locked");
    }
    credentialManager.setKey(vaultKey);
    credentialManager.deleteCredential(accountName);
    saveCredentials();
}

bool Vault::credentialExists(const std::string& accountName) const {
    if (!isUnlocked()) {
        return false;
    }
    credentialManager.setKey(vaultKey);
    return credentialManager.exists(accountName);
}

std::vector<std::string> Vault::listAccounts() const {
    if (!isUnlocked()) {
        return {};
    }
    credentialManager.setKey(vaultKey);
    return credentialManager.listAccounts();
}

} // namespace pwm
