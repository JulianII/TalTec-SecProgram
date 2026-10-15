#pragma once

#include <vector>
#include <string>
#include <cstring>

namespace pwm {

// Namespace for the global zeroize function
namespace detail {
    inline void zeroize_memory(void* ptr, size_t size) {
        if (ptr && size > 0) {
            volatile char* p = static_cast<volatile char*>(ptr);
            while (size--) {
                *p++ = 0;
            }
        }
    }
}

// Secure string that zeroizes itself on destruction
class SecureString {
public:
    SecureString() = default;
    
    explicit SecureString(const std::string& str) : data(str) {}
    explicit SecureString(const char* str) : data(str ? str : "") {}
    explicit SecureString(std::string&& str) : data(std::move(str)) {}
    
    SecureString(const SecureString& other) : data(other.data) {}
    SecureString(SecureString&& other) noexcept : data(std::move(other.data)) {}
    
    SecureString& operator=(const SecureString& other) {
        if (this != &other) {
            clear();
            data = other.data;
        }
        return *this;
    }
    
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            clear();
            data = std::move(other.data);
        }
        return *this;
    }
    
    SecureString& operator=(const std::string& str) {
        clear();
        data = str;
        return *this;
    }
    
    SecureString& operator=(const char* str) {
        clear();
        data = str ? str : "";
        return *this;
    }
    
    ~SecureString() {
        clear();
    }
    
    // Clear the string and zeroize the memory
    void clear() {
        if (!data.empty()) {
            detail::zeroize_memory(&data[0], data.size());
            data.clear();
        }
    }
    
    // Accessors
    const std::string& get() const { return data; }
    const char* c_str() const { return data.c_str(); }
    size_t size() const { return data.size(); }
    bool empty() const { return data.empty(); }
    
    // Allow implicit conversion to std::string for compatibility
    operator const std::string&() const { return data; }
    
    // Allow access to underlying string
    std::string& unsafe_get() { return data; }
    const std::string& unsafe_get() const { return data; }

private:
    std::string data;
};

// Secure buffer that zeroizes itself on destruction
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size) : buffer(size) {}
    
    SecureBuffer(const SecureBuffer& other) : buffer(other.buffer) {}
    SecureBuffer(SecureBuffer&& other) noexcept : buffer(std::move(other.buffer)) {}
    
    SecureBuffer& operator=(const SecureBuffer& other) {
        if (this != &other) {
            clear();
            buffer = other.buffer;
        }
        return *this;
    }
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            clear();
            buffer = std::move(other.buffer);
        }
        return *this;
    }
    
    ~SecureBuffer() {
        clear();
    }
    
    void clear() {
        if (!buffer.empty()) {
            detail::zeroize_memory(buffer.data(), buffer.size());
            buffer.clear();
        }
    }
    
    void resize(size_t size) {
        clear();
        buffer.resize(size);
    }
    
    unsigned char* raw_data() { return buffer.data(); }
    const unsigned char* raw_data() const { return buffer.data(); }
    size_t size() const { return buffer.size(); }
    bool empty() const { return buffer.empty(); }
    
    unsigned char& operator[](size_t index) { return buffer[index]; }
    const unsigned char& operator[](size_t index) const { return buffer[index]; }
    
    // For compatibility
    unsigned char* data() { return buffer.data(); }
    const unsigned char* data() const { return buffer.data(); }

private:
    std::vector<unsigned char> buffer;
};

} // namespace pwm
