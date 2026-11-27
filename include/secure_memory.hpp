#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <openssl/crypto.h>

namespace pwm {

namespace detail {

inline void zeroize_memory(void* ptr, size_t size) noexcept {
    if (ptr && size != 0) {
        OPENSSL_cleanse(ptr, size);
    }
}

template <typename T>
class SecureAllocator {
    static_assert(std::is_trivially_copyable<T>::value,
                  "SecureAllocator requires trivially copyable elements");

public:
    using value_type = T;
    using is_always_equal = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* ptr, size_t count) noexcept {
        if (ptr) {
            zeroize_memory(ptr, count * sizeof(T));
            std::allocator<T>{}.deallocate(ptr, count);
        }
    }

    template <typename U>
    struct rebind {
        using other = SecureAllocator<U>;
    };
};

template <typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return true;
}

template <typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return false;
}

}  // namespace detail

class SecureString {
public:
    using Storage = std::vector<char, detail::SecureAllocator<char>>;

    SecureString() = default;
    explicit SecureString(std::string_view value) {
        if (!value.empty()) {
            data.assign(value.begin(), value.end());
        }
    }
    SecureString(const SecureString&) = default;
    SecureString(SecureString&&) noexcept = default;
    SecureString& operator=(const SecureString& other) {
        if (this != &other) {
            clear();
            if (!other.data.empty()) {
                data.assign(other.data.begin(), other.data.end());
            }
        }
        return *this;
    }
    SecureString& operator=(SecureString&&) noexcept = default;

    SecureString& operator=(std::string_view value) {
        clear();
        if (!value.empty()) {
            data.assign(value.begin(), value.end());
        }
        return *this;
    }

    void append(char value) { data.push_back(value); }

    void clear() noexcept {
        detail::zeroize_memory(data.data(), data.size());
        data.clear();
    }

    std::string_view view() const noexcept {
        return data.empty() ? std::string_view{} :
            std::string_view(data.data(), data.size());
    }
    const char* data_ptr() const noexcept { return data.empty() ? "" : data.data(); }
    size_t size() const noexcept { return data.size(); }
    bool empty() const noexcept { return data.empty(); }

private:
    Storage data;
};

class SecureBuffer {
public:
    using Storage = std::vector<unsigned char, detail::SecureAllocator<unsigned char>>;

    SecureBuffer() = default;
    explicit SecureBuffer(size_t size) : buffer(size) {}
    SecureBuffer(const SecureBuffer&) = default;
    SecureBuffer(SecureBuffer&&) noexcept = default;
    SecureBuffer& operator=(const SecureBuffer& other) {
        if (this != &other) {
            clear();
            buffer.assign(other.buffer.begin(), other.buffer.end());
        }
        return *this;
    }
    SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

    void assign(const unsigned char* data, size_t size) {
        clear();
        if (size != 0) {
            buffer.assign(data, data + size);
        }
    }

    void assign(const std::vector<unsigned char>& data) {
        clear();
        if (!data.empty()) {
            buffer.assign(data.begin(), data.end());
        }
    }

    void clear() noexcept {
        detail::zeroize_memory(buffer.data(), buffer.size());
        buffer.clear();
    }

    void resize(size_t size) {
        if (size < buffer.size()) {
            detail::zeroize_memory(buffer.data() + size, buffer.size() - size);
        }
        buffer.resize(size);
    }

    unsigned char* data() noexcept { return buffer.data(); }
    const unsigned char* data() const noexcept { return buffer.data(); }
    unsigned char* raw_data() noexcept { return buffer.data(); }
    const unsigned char* raw_data() const noexcept { return buffer.data(); }
    size_t size() const noexcept { return buffer.size(); }
    bool empty() const noexcept { return buffer.empty(); }

    unsigned char& operator[](size_t index) { return buffer[index]; }
    const unsigned char& operator[](size_t index) const { return buffer[index]; }

private:
    Storage buffer;
};

}  // namespace pwm
