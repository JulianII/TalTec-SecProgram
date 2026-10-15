
cmake_minimum_required(VERSION 3.20)

project(pwm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    set(PLATFORM_SOURCE src/platform/windows.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_SOURCE src/platform/linux.cpp)
else()
    message(FATAL_ERROR "Unsupported operating system")
endif()

find_package(Sodium QUIET)
if(Sodium_FOUND)
    message(STATUS "Found libsodium")
    set(HAVE_SODIUM TRUE)
else()
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        message(STATUS "Found OpenSSL")
        set(HAVE_OPENSSL TRUE)
    endif()
endif()

add_executable(pwm
    src/main.cpp
    src/vault.cpp
    src/credential.cpp
    ${PLATFORM_SOURCE}
)

if(WIN32)
    target_sources(pwm PRIVATE src/clipboard.cpp)
endif()

target_include_directories(pwm PRIVATE
    src/platform
    include
)

if(HAVE_SODIUM)
    target_include_directories(pwm PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(pwm PRIVATE ${SODIUM_LIBRARIES})
elseif(HAVE_OPENSSL)
    target_include_directories(pwm PRIVATE ${OPENSSL_INCLUDE_DIRS})
    target_link_libraries(pwm PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
