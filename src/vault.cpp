#include "vault.hpp"
#include "crypto_random.hpp"
#include "platform/platform.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <system_error>
#include <openssl/evp.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr std::array<unsigned char, 8> vaultFileMagic = {
    'P', 'W', 'M', 'V', 'L', 'T', '0', '2'
};
constexpr uint32_t vaultFileVersion = 2;
constexpr size_t vaultSaltSize = 16;
constexpr size_t vaultNonceSize = 12;
constexpr size_t encryptedVaultKeySize = 48;
constexpr size_t vaultFileSize =
    vaultFileMagic.size() + sizeof(uint32_t) + vaultSaltSize +
    vaultNonceSize + encryptedVaultKeySize;
constexpr std::array<unsigned char, 12> legacyVaultFileMagic = {
    'P', 'W', 'M', '_', 'V', 'A', 'U', 'L', 'T', '_', '0', '1'
};

void appendUint32(std::vector<unsigned char>& output, uint32_t value) {
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        output.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
    }
}

uint32_t readUint32(const std::vector<unsigned char>& input, size_t& offset) {
    if (offset > input.size() || input.size() - offset < sizeof(uint32_t)) {
        throw std::runtime_error("Vault file is truncated");
    }
    uint32_t value = 0;
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        value |= static_cast<uint32_t>(input[offset++]) << shift;
    }
    return value;
}

std::string temporaryFileSuffix() {
    constexpr char hex[] = "0123456789abcdef";
    const auto random = pwm::crypto::randomBytes(12);
    std::string suffix;
    suffix.reserve(random.size() * 2);
    for (const unsigned char byte : random) {
        suffix.push_back(hex[byte >> 4]);
        suffix.push_back(hex[byte & 0x0f]);
    }
    return suffix;
}

std::vector<unsigned char> readVaultFile(const std::string& filepath) {
    std::error_code error;
    const auto size = fs::file_size(filepath, error);
    if (error) {
        throw std::runtime_error("Could not determine vault file size: " + error.message());
    }
    if (size != vaultFileSize) {
        throw std::runtime_error("Vault file has an invalid size");
    }

    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Vault file is missing or unreadable");
    }
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (file.gcount() != static_cast<std::streamsize>(bytes.size())) {
        throw std::runtime_error("Vault file is truncated");
    }
    char extraByte = 0;
    if (file.get(extraByte)) {
        throw std::runtime_error("Vault file changed while reading");
    }
    if (!file.eof()) {
        throw std::runtime_error("Could not complete reading vault file");
    }
    return bytes;
}

void writeVaultFileAtomically(
    const std::string& filepath,
    const std::vector<unsigned char>& bytes) {
    const fs::path target(filepath);
    const fs::path temporary = target.string() + "." + temporaryFileSuffix() + ".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("Could not create temporary vault file");
        }
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        file.flush();
        if (!file) {
            file.close();
            std::error_code ignored;
            fs::remove(temporary, ignored);
            throw std::runtime_error("Could not write complete vault file");
        }
    }

#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), target.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw std::system_error(static_cast<int>(error), std::system_category(),
                                "Could not atomically replace vault file");
    }
#else
    std::error_code error;
    fs::rename(temporary, target, error);
    if (error) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw std::runtime_error("Could not atomically replace vault file: " + error.message());
    }
#endif
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
    salt = crypto::randomBytes(16);
}

std::vector<unsigned char> Vault::deriveKey(const std::string& password, const std::vector<unsigned char>& saltBytes) const {
    if (password.size() > static_cast<size_t>(INT_MAX)) {
        throw std::runtime_error("Master password is too long");
    }
    std::vector<unsigned char> key(32, 0);
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
        saltBytes.data(), static_cast<int>(saltBytes.size()),
        200000, EVP_sha256(), static_cast<int>(key.size()), key.data()) != 1) {
        throw std::runtime_error("Failed to derive a vault key from the master password");
    }
    return key;
}

void Vault::generateVaultKey() {
    vaultKey = crypto::randomBytes(32);
}

void Vault::createVaultDirectory() const {
    if (!fs::exists(dataDirectory)) {
        fs::create_directories(dataDirectory);
    }
}

std::vector<unsigned char> Vault::loadVaultKey(const std::string& masterPassword) const {
    const auto bytes = readVaultFile(vaultPath);
    size_t offset = 0;
    std::vector<unsigned char> saltRead(vaultSaltSize);
    std::vector<unsigned char> nonce(vaultNonceSize);
    std::vector<unsigned char> encryptedKeyAndTag(encryptedVaultKeySize);

    if (std::equal(vaultFileMagic.begin(), vaultFileMagic.end(), bytes.begin())) {
        offset += vaultFileMagic.size();
        if (readUint32(bytes, offset) != vaultFileVersion) {
            throw std::runtime_error("Unsupported vault file version");
        }
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    saltRead.size(), saltRead.begin());
        offset += saltRead.size();
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    nonce.size(), nonce.begin());
        offset += nonce.size();
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    encryptedKeyAndTag.size(), encryptedKeyAndTag.begin());
        offset += encryptedKeyAndTag.size();
        if (offset != bytes.size()) {
            throw std::runtime_error("Vault file contains unexpected trailing data");
        }
    } else {
        std::copy_n(bytes.begin(), saltRead.size(), saltRead.begin());
        offset += saltRead.size();
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    nonce.size(), nonce.begin());
        offset += nonce.size();
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    encryptedKeyAndTag.size(), encryptedKeyAndTag.begin());
        offset += encryptedKeyAndTag.size();
        if (!std::equal(legacyVaultFileMagic.begin(), legacyVaultFileMagic.end(),
                        bytes.begin() + static_cast<std::ptrdiff_t>(offset))) {
            throw std::runtime_error("Vault file header is invalid");
        }
    }

    const auto derivedKey = deriveKey(masterPassword, saltRead);
    return decryptWithAesGcm(derivedKey, nonce, encryptedKeyAndTag);
}

void Vault::saveVaultKey(const std::string& masterPassword, const std::vector<unsigned char>& keyToStore) const {
    const auto derivedKey = deriveKey(masterPassword, salt);
    const auto nonce = crypto::randomBytes(12);
    std::vector<unsigned char> tag;
    const auto encryptedKeyAndTag = encryptWithAesGcm(derivedKey, keyToStore, nonce, tag);

    std::vector<unsigned char> bytes(vaultFileMagic.begin(), vaultFileMagic.end());
    appendUint32(bytes, vaultFileVersion);
    bytes.insert(bytes.end(), salt.begin(), salt.end());
    bytes.insert(bytes.end(), nonce.begin(), nonce.end());
    bytes.insert(bytes.end(), encryptedKeyAndTag.begin(), encryptedKeyAndTag.end());
    writeVaultFileAtomically(vaultPath, bytes);
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
    try {
        loadCredentials();
        unlocked = true;
    } catch (...) {
        credentialManager.clearKey();
        std::fill(vaultKey.begin(), vaultKey.end(), 0);
        vaultKey.clear();
        throw;
    }
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
    credentialManager.loadFromFile(credentialsPath);
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
