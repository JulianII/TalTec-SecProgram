#include "credential.hpp"
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
    const std::string& plaintext,
    const std::vector<unsigned char>& nonce,
    std::vector<unsigned char>& tagOut) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-256-GCM requires a 32-byte key");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("AES-256-GCM requires a 12-byte nonce");
    }

    const auto* data = reinterpret_cast<const unsigned char*>(plaintext.data());
    const size_t plaintextLen = plaintext.size();
    std::vector<unsigned char> ciphertext(plaintextLen + 16, 0);
    int outLen1 = 0;
    int outLen2 = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Could not allocate OpenSSL cipher context");
    }

    tagOut.resize(16);

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
            EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen1, data, static_cast<int>(plaintextLen)) != 1 ||
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagOut.data()) != 1) {
            throw std::runtime_error("Failed to encrypt plaintext with AES-256-GCM");
        }

        const int totalLen = outLen1 + outLen2;
        ciphertext.resize(static_cast<size_t>(totalLen));
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

std::string decryptWithAesGcm(
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
        throw std::runtime_error("Ciphertext is too short to contain an authentication tag");
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
            throw std::runtime_error("Failed to authenticate and decrypt ciphertext");
        }

        const int totalLen = outLen1 + outLen2;
        plaintext.resize(static_cast<size_t>(totalLen));
        EVP_CIPHER_CTX_free(ctx);
        return std::string(plaintext.begin(), plaintext.end());
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

}  // namespace

namespace pwm {

void CredentialManager::setKey(const std::vector<unsigned char>& key) {
    encryptionKey = key;
}

void CredentialManager::clearKey() {
    if (!encryptionKey.empty()) {
        std::fill(encryptionKey.begin(), encryptionKey.end(), 0);
        encryptionKey.clear();
    }
}

std::vector<unsigned char> CredentialManager::generateNonce() const {
    return randomBytes(12);
}

std::vector<unsigned char> CredentialManager::encrypt(const std::string& plaintext, const std::vector<unsigned char>& nonce) const {
    if (encryptionKey.empty()) {
        throw std::runtime_error("Credential encryption key is not available");
    }

    std::vector<unsigned char> tag;
    return encryptWithAesGcm(encryptionKey, plaintext, nonce, tag);
}

std::string CredentialManager::decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& nonce) const {
    if (encryptionKey.empty()) {
        throw std::runtime_error("Credential decryption key is not available");
    }
    return decryptWithAesGcm(encryptionKey, nonce, ciphertext);
}

void CredentialManager::storeCredential(const std::string& accountName, const std::string& password) {
    for (const auto& cred : credentials) {
        if (cred.accountName == accountName) {
            throw std::runtime_error("Credential already exists for account: " + accountName);
        }
    }

    Credential cred;
    cred.accountName = accountName;
    cred.nonce = generateNonce();
    cred.encryptedPassword = encrypt(password, cred.nonce);
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
            cred.nonce = generateNonce();
            cred.encryptedPassword = encrypt(newPassword, cred.nonce);
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

    for (const auto& cred : credentials) {
        uint32_t nameLength = static_cast<uint32_t>(cred.accountName.size());
        out.write(reinterpret_cast<const char*>(&nameLength), sizeof(nameLength));
        out.write(cred.accountName.data(), static_cast<std::streamsize>(cred.accountName.size()));

        uint32_t passwordSize = static_cast<uint32_t>(cred.encryptedPassword.size());
        out.write(reinterpret_cast<const char*>(&passwordSize), sizeof(passwordSize));
        out.write(reinterpret_cast<const char*>(cred.encryptedPassword.data()), static_cast<std::streamsize>(cred.encryptedPassword.size()));

        uint32_t nonceSize = static_cast<uint32_t>(cred.nonce.size());
        out.write(reinterpret_cast<const char*>(&nonceSize), sizeof(nonceSize));
        out.write(reinterpret_cast<const char*>(cred.nonce.data()), static_cast<std::streamsize>(cred.nonce.size()));

        out.write(reinterpret_cast<const char*>(&cred.createdAt), sizeof(cred.createdAt));
        out.write(reinterpret_cast<const char*>(&cred.updatedAt), sizeof(cred.updatedAt));
    }
}

void CredentialManager::loadFromFile(const std::string& filepath) {
    std::ifstream in(filepath, std::ios::binary);
    if (!in) {
        if (fs::exists(filepath)) {
            throw std::runtime_error("Could not open file for reading: " + filepath);
        }
        return;
    }

    credentials.clear();

    while (in.peek() != EOF) {
        Credential cred;

        uint32_t nameLength = 0;
        in.read(reinterpret_cast<char*>(&nameLength), sizeof(nameLength));
        if (in.fail() || in.eof()) {
            break;
        }

        cred.accountName.resize(nameLength);
        if (nameLength > 0) {
            in.read(cred.accountName.data(), static_cast<std::streamsize>(nameLength));
        }

        uint32_t passwordLength = 0;
        in.read(reinterpret_cast<char*>(&passwordLength), sizeof(passwordLength));
        if (in.fail()) {
            throw std::runtime_error("Credential file is malformed");
        }

        cred.encryptedPassword.resize(passwordLength);
        if (passwordLength > 0) {
            in.read(reinterpret_cast<char*>(cred.encryptedPassword.data()), static_cast<std::streamsize>(passwordLength));
        }

        uint32_t nonceLength = 0;
        in.read(reinterpret_cast<char*>(&nonceLength), sizeof(nonceLength));
        if (in.fail()) {
            throw std::runtime_error("Credential file is malformed");
        }

        cred.nonce.resize(nonceLength);
        if (nonceLength > 0) {
            in.read(reinterpret_cast<char*>(cred.nonce.data()), static_cast<std::streamsize>(nonceLength));
        }

        in.read(reinterpret_cast<char*>(&cred.createdAt), sizeof(cred.createdAt));
        in.read(reinterpret_cast<char*>(&cred.updatedAt), sizeof(cred.updatedAt));
        if (in.fail()) {
            throw std::runtime_error("Credential metadata is malformed");
        }

        credentials.push_back(cred);
    }
}

} // namespace pwm
