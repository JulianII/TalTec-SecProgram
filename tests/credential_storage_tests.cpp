#include "credential.hpp"
#include "vault.hpp"
#include "platform/platform.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string configuredVaultDirectory;

class TestDirectory {
public:
    TestDirectory() {
        path = fs::temp_directory_path() /
            ("pwm-credential-tests-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        fs::create_directories(path);
    }

    ~TestDirectory() {
        std::error_code ignored;
        fs::remove_all(path, ignored);
    }

    fs::path path;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<unsigned char> readBytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void writeBytes(const fs::path& path, const std::vector<unsigned char>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    require(static_cast<bool>(output), "Could not write test credential file");
}

void expectLoadFailure(pwm::CredentialManager& manager, const fs::path& path) {
    bool threw = false;
    try {
        manager.loadFromFile(path.string());
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, "Malformed or tampered credential file was accepted");
}

void testRoundTripAndAuthenticatedMetadata(const fs::path& path) {
    const std::vector<unsigned char> key(32, 0x5a);
    pwm::CredentialManager writer;
    writer.setKey(key);
    writer.storeCredential("example", "correct horse battery staple");
    writer.saveToFile(path.string());

    pwm::CredentialManager reader;
    reader.setKey(key);
    reader.loadFromFile(path.string());
    const auto credential = reader.retrieveCredential("example");
    require(reader.decrypt(credential.encryptedPassword, credential.nonce) ==
                "correct horse battery staple",
            "Credential did not survive a save/load round trip");

    reader.updateCredential("example", "updated password");
    reader.saveToFile(path.string());
    pwm::CredentialManager updatedReader;
    updatedReader.setKey(key);
    updatedReader.loadFromFile(path.string());
    const auto updatedCredential = updatedReader.retrieveCredential("example");
    require(updatedReader.decrypt(updatedCredential.encryptedPassword,
                                  updatedCredential.nonce) == "updated password",
            "Credential update did not persist");

    updatedReader.deleteCredential("example");
    updatedReader.saveToFile(path.string());
    pwm::CredentialManager deletedReader;
    deletedReader.setKey(key);
    deletedReader.loadFromFile(path.string());
    require(!deletedReader.exists("example"), "Credential deletion did not persist");

    reader.loadFromFile(path.string());
    auto bytes = readBytes(path);
    require(bytes.size() > 12, "Versioned credential file is unexpectedly short");
    bytes[12] ^= 0x01;
    writeBytes(path, bytes);

    pwm::CredentialManager tamperReader;
    tamperReader.setKey(key);
    expectLoadFailure(tamperReader, path);
}

void testTruncatedFileDoesNotReplaceCurrentState(const fs::path& path) {
    const std::vector<unsigned char> key(32, 0x33);
    pwm::CredentialManager writer;
    writer.setKey(key);
    writer.storeCredential("saved", "saved-password");
    writer.saveToFile(path.string());

    auto bytes = readBytes(path);
    bytes.resize(bytes.size() - 1);
    writeBytes(path, bytes);

    pwm::CredentialManager reader;
    reader.setKey(key);
    reader.storeCredential("in-memory", "keep-this");
    expectLoadFailure(reader, path);
    require(reader.exists("in-memory"),
            "Failed load partially replaced existing in-memory credentials");
}

void testLegacyFileIsMigrated(const fs::path& path) {
    const std::vector<unsigned char> key(32, 0x7c);
    pwm::CredentialManager original;
    original.setKey(key);
    original.storeCredential("legacy", "legacy-password");
    const auto credential = original.retrieveCredential("legacy");

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    const uint32_t nameSize = static_cast<uint32_t>(credential.accountName.size());
    const std::string legacyPassword = "legacy-password";
    const uint32_t encryptedSize = static_cast<uint32_t>(legacyPassword.size());
    const uint32_t nonceSize = 12;
    output.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
    output.write(credential.accountName.data(),
                 static_cast<std::streamsize>(credential.accountName.size()));
    output.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));
    output.write(legacyPassword.data(),
                 static_cast<std::streamsize>(legacyPassword.size()));
    output.write(reinterpret_cast<const char*>(&nonceSize), sizeof(nonceSize));
    const std::vector<unsigned char> legacyNonce(nonceSize, 0x42);
    output.write(reinterpret_cast<const char*>(legacyNonce.data()),
                 static_cast<std::streamsize>(legacyNonce.size()));
    output.write(reinterpret_cast<const char*>(&credential.createdAt), sizeof(time_t));
    output.write(reinterpret_cast<const char*>(&credential.updatedAt), sizeof(time_t));
    output.close();
    require(static_cast<bool>(output), "Could not create legacy credential fixture");

    pwm::CredentialManager migrated;
    migrated.setKey(key);
    migrated.loadFromFile(path.string());
    const auto loaded = migrated.retrieveCredential("legacy");
    require(migrated.decrypt(loaded.encryptedPassword, loaded.nonce) == "legacy-password",
            "Legacy credential could not be loaded after migration");

    const auto migratedBytes = readBytes(path);
    const std::vector<unsigned char> expectedMagic = {
        'P', 'W', 'M', 'C', 'R', 'D', '0', '2'
    };
    require(migratedBytes.size() >= expectedMagic.size() &&
                std::equal(expectedMagic.begin(), expectedMagic.end(), migratedBytes.begin()),
            "Legacy credential file was not migrated to the versioned format");
    const std::string plaintext = "legacy-password";
    const auto plaintextPosition = std::search(
        migratedBytes.begin(), migratedBytes.end(), plaintext.begin(), plaintext.end());
    require(plaintextPosition == migratedBytes.end(),
            "Legacy password remains in plaintext after migration");
}

void testVaultPersistenceAndFailedUnlockCleanup(const fs::path& directory) {
    configuredVaultDirectory = directory.string();

    pwm::Vault vault;
    vault.initialize("test-master-password");
    bool rejectedWrongPassword = false;
    try {
        vault.unlock("incorrect-password");
    } catch (const std::exception&) {
        rejectedWrongPassword = true;
    }
    require(rejectedWrongPassword && !vault.isUnlocked(),
            "Vault accepted an incorrect master password");

    vault.unlock("test-master-password");
    vault.storeCredential("persisted-account", "persisted-password");
    vault.lock();

    pwm::Vault reopened;
    reopened.unlock("test-master-password");
    require(reopened.retrieveCredential("persisted-account") == "persisted-password",
            "Credential was not available after reopening the vault");
    reopened.lock();

    const fs::path credentialsPath = directory / "credentials.dat";
    auto bytes = readBytes(credentialsPath);
    bytes[12] ^= 0x01;
    writeBytes(credentialsPath, bytes);

    pwm::Vault damaged;
    bool rejectedDamagedFile = false;
    try {
        damaged.unlock("test-master-password");
    } catch (const std::exception&) {
        rejectedDamagedFile = true;
    }
    require(rejectedDamagedFile && !damaged.isUnlocked(),
            "Vault remained unlocked after credential-file authentication failed");
}

void testVaultFileVersionAndTamperRejection(const fs::path& directory) {
    configuredVaultDirectory = directory.string();
    pwm::Vault vault;
    vault.initialize("master-password");

    const fs::path vaultPath = directory / "vault.bin";
    auto bytes = readBytes(vaultPath);
    const std::vector<unsigned char> expectedMagic = {
        'P', 'W', 'M', 'V', 'L', 'T', '0', '2'
    };
    require(bytes.size() == 88 &&
                std::equal(expectedMagic.begin(), expectedMagic.end(), bytes.begin()),
            "Vault was not saved with the expected versioned format");

    bytes[28] ^= 0x01;
    writeBytes(vaultPath, bytes);

    pwm::Vault tampered;
    bool rejectedTamperedVault = false;
    try {
        tampered.unlock("master-password");
    } catch (const std::exception&) {
        rejectedTamperedVault = true;
    }
    require(rejectedTamperedVault && !tampered.isUnlocked(),
            "Vault accepted a tampered encrypted key envelope");

    bytes.resize(bytes.size() - 1);
    writeBytes(vaultPath, bytes);
    pwm::Vault truncated;
    bool rejectedTruncatedVault = false;
    try {
        truncated.unlock("master-password");
    } catch (const std::exception&) {
        rejectedTruncatedVault = true;
    }
    require(rejectedTruncatedVault && !truncated.isUnlocked(),
            "Vault accepted a truncated vault file");
}

}  // namespace

namespace platform {

std::string getUserDataDirectory() {
    return configuredVaultDirectory;
}

}  // namespace platform

int main() {
    try {
        TestDirectory directory;
        testRoundTripAndAuthenticatedMetadata(directory.path / "round-trip.dat");
        testTruncatedFileDoesNotReplaceCurrentState(directory.path / "truncated.dat");
        testLegacyFileIsMigrated(directory.path / "legacy.dat");
        testVaultPersistenceAndFailedUnlockCleanup(directory.path / "vault-data");
        testVaultFileVersionAndTamperRejection(directory.path / "vault-format");
        std::cout << "Credential storage tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Credential storage tests failed: " << error.what() << "\n";
        return 1;
    }
}
