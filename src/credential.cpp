#include "credential.hpp"
#include "crypto_random.hpp"
#include "secure_memory.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <set>
#include <system_error>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr std::array<unsigned char, 8> credentialFileMagic = {
    'P', 'W', 'M', 'C', 'R', 'D', '0', '2'
};
constexpr uint32_t credentialFileVersion = 2;
constexpr size_t authenticationTagSize = 32;
constexpr size_t maxCredentialFileSize = 64 * 1024 * 1024;
constexpr uint32_t maxCredentialCount = 100000;
constexpr uint32_t maxAccountNameSize = 4096;
constexpr uint32_t maxEncryptedPasswordSize = 1024 * 1024;

void appendUint32(std::vector<unsigned char>& output, uint32_t value) {
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        output.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
    }
}

void appendUint64(std::vector<unsigned char>& output, uint64_t value) {
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        output.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
    }
}

uint32_t readUint32(const std::vector<unsigned char>& input, size_t& offset, size_t limit) {
    if (offset > limit || limit - offset < sizeof(uint32_t)) {
        throw std::runtime_error("Credential file is truncated");
    }
    uint32_t value = 0;
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        value |= static_cast<uint32_t>(input[offset++]) << shift;
    }
    return value;
}

uint64_t readUint64(const std::vector<unsigned char>& input, size_t& offset, size_t limit) {
    if (offset > limit || limit - offset < sizeof(uint64_t)) {
        throw std::runtime_error("Credential file is truncated");
    }
    uint64_t value = 0;
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        value |= static_cast<uint64_t>(input[offset++]) << shift;
    }
    return value;
}

void appendBytes(std::vector<unsigned char>& output, const unsigned char* data, size_t size) {
    output.insert(output.end(), data, data + size);
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

time_t readLegacyTime(const std::vector<unsigned char>& bytes, size_t& offset) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(time_t)) {
        throw std::runtime_error("Legacy credential file is truncated");
    }
    time_t value;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    offset += sizeof(value);
    return value;
}

std::vector<unsigned char> calculateFileMac(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& data,
    size_t size) {
    if (key.size() != 32) {
        throw std::runtime_error("Credential file authentication key is unavailable");
    }
    static constexpr unsigned char keyLabel[] = "PWM credential file authentication key v2";
    std::array<unsigned char, 32> authenticationKey{};
    unsigned int derivedKeySize = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              keyLabel, sizeof(keyLabel) - 1, authenticationKey.data(), &derivedKeySize) ||
        derivedKeySize != authenticationKey.size()) {
        throw std::runtime_error("Could not derive credential file authentication key");
    }

    std::vector<unsigned char> mac(EVP_MAX_MD_SIZE);
    unsigned int macSize = 0;
    if (!HMAC(EVP_sha256(), authenticationKey.data(), static_cast<int>(authenticationKey.size()),
              data.data(), size, mac.data(), &macSize) ||
        macSize != authenticationTagSize) {
        std::fill(authenticationKey.begin(), authenticationKey.end(), 0);
        throw std::runtime_error("Could not authenticate credential file");
    }
    std::fill(authenticationKey.begin(), authenticationKey.end(), 0);
    mac.resize(macSize);
    return mac;
}

std::vector<unsigned char> readFile(const std::string& filepath) {
    std::error_code error;
    const uintmax_t fileSize = fs::file_size(filepath, error);
    if (error) {
        throw std::runtime_error("Could not determine credential file size: " + error.message());
    }
    if (fileSize > maxCredentialFileSize) {
        throw std::runtime_error("Credential file exceeds the maximum supported size");
    }

    std::ifstream in(filepath, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Could not open file for reading: " + filepath);
    }

    std::vector<unsigned char> bytes(static_cast<size_t>(fileSize));
    if (!bytes.empty()) {
        in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (in.gcount() != static_cast<std::streamsize>(bytes.size())) {
            throw std::runtime_error("Credential file changed or was truncated while reading");
        }
    }
    char extraByte = 0;
    if (in.get(extraByte)) {
        throw std::runtime_error("Credential file changed while reading");
    }
    if (!in.eof()) {
        throw std::runtime_error("Could not complete reading credential file");
    }
    return bytes;
}

class CleanseVectorOnExit {
public:
    explicit CleanseVectorOnExit(std::vector<unsigned char>& bytes) : bytes(bytes) {}

    ~CleanseVectorOnExit() {
        if (!bytes.empty()) {
            OPENSSL_cleanse(bytes.data(), bytes.size());
        }
    }

private:
    std::vector<unsigned char>& bytes;
};

void writeAtomically(const std::string& filepath, const std::vector<unsigned char>& bytes) {
    const fs::path target(filepath);
    const fs::path temporary = target.string() + "." + temporaryFileSuffix() + ".tmp";
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("Could not create temporary credential file: " + temporary.string());
        }
        if (!bytes.empty()) {
            out.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        }
        out.flush();
        if (!out) {
            out.close();
            std::error_code ignored;
            fs::remove(temporary, ignored);
            throw std::runtime_error("Could not write complete temporary credential file");
        }
    }

#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), target.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw std::system_error(static_cast<int>(error), std::system_category(),
                                "Could not atomically replace credential file");
    }
#else
    std::error_code error;
    fs::rename(temporary, target, error);
    if (error) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw std::runtime_error("Could not atomically replace credential file: " + error.message());
    }
#endif
}

std::vector<pwm::Credential> parseVersion2File(
    const std::vector<unsigned char>& bytes,
    const std::vector<unsigned char>& key) {
    const size_t minimumSize = credentialFileMagic.size() + 4 + 4 + authenticationTagSize;
    if (bytes.size() < minimumSize) {
        throw std::runtime_error("Credential file is truncated");
    }

    const size_t bodySize = bytes.size() - authenticationTagSize;
    const auto expectedMac = calculateFileMac(key, bytes, bodySize);
    if (CRYPTO_memcmp(expectedMac.data(), bytes.data() + bodySize, authenticationTagSize) != 0) {
        throw std::runtime_error("Credential file authentication failed");
    }

    size_t offset = 0;
    if (!std::equal(credentialFileMagic.begin(), credentialFileMagic.end(), bytes.begin())) {
        throw std::runtime_error("Credential file header is invalid");
    }
    offset += credentialFileMagic.size();
    if (readUint32(bytes, offset, bodySize) != credentialFileVersion) {
        throw std::runtime_error("Unsupported credential file version");
    }

    const uint32_t count = readUint32(bytes, offset, bodySize);
    if (count > maxCredentialCount) {
        throw std::runtime_error("Credential file contains too many records");
    }

    std::vector<pwm::Credential> loaded;
    loaded.reserve(count);
    std::set<std::string> accountNames;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t nameSize = readUint32(bytes, offset, bodySize);
        if (nameSize == 0 || nameSize > maxAccountNameSize ||
            nameSize > bodySize - offset) {
            throw std::runtime_error("Credential file contains an invalid account name length");
        }

        pwm::Credential cred;
        cred.accountName.assign(
            reinterpret_cast<const char*>(bytes.data() + offset), nameSize);
        offset += nameSize;
        if (!accountNames.insert(cred.accountName).second) {
            throw std::runtime_error("Credential file contains duplicate account names");
        }

        const uint32_t encryptedSize = readUint32(bytes, offset, bodySize);
        if (encryptedSize < 16 || encryptedSize > maxEncryptedPasswordSize ||
            encryptedSize > bodySize - offset) {
            throw std::runtime_error("Credential file contains an invalid encrypted password length");
        }
        cred.encryptedPassword.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                      bytes.begin() + static_cast<std::ptrdiff_t>(offset + encryptedSize));
        offset += encryptedSize;

        cred.nonce.resize(12);
        if (offset > bodySize || bodySize - offset < cred.nonce.size()) {
            throw std::runtime_error("Credential file is truncated");
        }
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    cred.nonce.size(), cred.nonce.begin());
        offset += cred.nonce.size();
        cred.createdAt = static_cast<time_t>(readUint64(bytes, offset, bodySize));
        cred.updatedAt = static_cast<time_t>(readUint64(bytes, offset, bodySize));
        loaded.push_back(std::move(cred));
    }

    if (offset != bodySize) {
        throw std::runtime_error("Credential file contains unexpected trailing data");
    }
    return loaded;
}

std::vector<pwm::Credential> parseLegacyFile(const std::vector<unsigned char>& bytes) {
    std::vector<pwm::Credential> loaded;
    std::set<std::string> accountNames;
    size_t offset = 0;
    while (offset < bytes.size()) {
        const uint32_t nameSize = readUint32(bytes, offset, bytes.size());
        if (nameSize == 0 || nameSize > maxAccountNameSize ||
            nameSize > bytes.size() - offset) {
            throw std::runtime_error("Legacy credential file contains an invalid account name length");
        }

        pwm::Credential cred;
        cred.accountName.assign(reinterpret_cast<const char*>(bytes.data() + offset), nameSize);
        offset += nameSize;
        if (!accountNames.insert(cred.accountName).second) {
            throw std::runtime_error("Legacy credential file contains duplicate account names");
        }

        const uint32_t encryptedSize = readUint32(bytes, offset, bytes.size());
        if (encryptedSize > maxEncryptedPasswordSize ||
            encryptedSize > bytes.size() - offset) {
            throw std::runtime_error("Legacy credential file contains an invalid encrypted password length");
        }
        cred.encryptedPassword.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                      bytes.begin() + static_cast<std::ptrdiff_t>(offset + encryptedSize));
        offset += encryptedSize;

        const uint32_t nonceSize = readUint32(bytes, offset, bytes.size());
        if (nonceSize != 12 || nonceSize > bytes.size() - offset) {
            throw std::runtime_error("Legacy credential file contains an invalid nonce");
        }
        cred.nonce.resize(12);
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    cred.nonce.size(), cred.nonce.begin());
        offset += nonceSize;
        cred.createdAt = readLegacyTime(bytes, offset);
        cred.updatedAt = readLegacyTime(bytes, offset);
        loaded.push_back(std::move(cred));
        if (loaded.size() > maxCredentialCount) {
            throw std::runtime_error("Legacy credential file contains too many records");
        }
    }
    return loaded;
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
        std::string result(plaintext.begin(), plaintext.end());
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        EVP_CIPHER_CTX_free(ctx);
        return result;
    } catch (...) {
        if (!plaintext.empty()) {
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
        }
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
    return crypto::randomBytes(12);
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
    if (credentials.size() > maxCredentialCount) {
        throw std::runtime_error("Too many credentials to save");
    }

    std::vector<unsigned char> bytes(
        credentialFileMagic.begin(), credentialFileMagic.end());
    appendUint32(bytes, credentialFileVersion);
    appendUint32(bytes, static_cast<uint32_t>(credentials.size()));

    std::set<std::string> accountNames;
    for (const auto& cred : credentials) {
        if (cred.accountName.empty() || cred.accountName.size() > maxAccountNameSize ||
            cred.encryptedPassword.size() < 16 ||
            cred.encryptedPassword.size() > maxEncryptedPasswordSize ||
            cred.nonce.size() != 12) {
            throw std::runtime_error("Credential contains invalid data and cannot be saved");
        }
        if (!accountNames.insert(cred.accountName).second) {
            throw std::runtime_error("Duplicate account names cannot be saved");
        }

        appendUint32(bytes, static_cast<uint32_t>(cred.accountName.size()));
        appendBytes(bytes,
                    reinterpret_cast<const unsigned char*>(cred.accountName.data()),
                    cred.accountName.size());
        appendUint32(bytes, static_cast<uint32_t>(cred.encryptedPassword.size()));
        appendBytes(bytes, cred.encryptedPassword.data(), cred.encryptedPassword.size());
        appendBytes(bytes, cred.nonce.data(), cred.nonce.size());
        appendUint64(bytes, static_cast<uint64_t>(cred.createdAt));
        appendUint64(bytes, static_cast<uint64_t>(cred.updatedAt));

        if (bytes.size() > maxCredentialFileSize - authenticationTagSize) {
            throw std::runtime_error("Credential data exceeds the maximum supported file size");
        }
    }

    const auto mac = calculateFileMac(encryptionKey, bytes, bytes.size());
    appendBytes(bytes, mac.data(), mac.size());
    writeAtomically(filepath, bytes);
}

void CredentialManager::loadFromFile(const std::string& filepath) {
    if (!fs::exists(filepath)) {
        credentials.clear();
        return;
    }

    auto bytes = readFile(filepath);
    CleanseVectorOnExit cleanseBytes(bytes);
    const bool isVersion2 = bytes.size() >= credentialFileMagic.size() &&
        std::equal(credentialFileMagic.begin(), credentialFileMagic.end(), bytes.begin());

    std::vector<Credential> loaded = isVersion2
        ? parseVersion2File(bytes, encryptionKey)
        : parseLegacyFile(bytes);

    if (loaded.size() > maxCredentialCount) {
        throw std::runtime_error("Credential file contains too many records");
    }

    if (!isVersion2) {
        if (encryptionKey.size() != 32) {
            throw std::runtime_error("Credential encryption key is unavailable for legacy migration");
        }
        for (auto& cred : loaded) {
            pwm::SecureString legacyPassword(std::string(
                cred.encryptedPassword.begin(), cred.encryptedPassword.end()));
            OPENSSL_cleanse(cred.encryptedPassword.data(), cred.encryptedPassword.size());
            cred.nonce = generateNonce();
            cred.encryptedPassword = encrypt(legacyPassword.get(), cred.nonce);
        }
    }

    std::vector<Credential> previous;
    previous.swap(credentials);
    credentials = std::move(loaded);
    if (!isVersion2) {
        try {
            saveToFile(filepath);
        } catch (...) {
            credentials.swap(previous);
            throw;
        }
    }
}

} // namespace pwm
