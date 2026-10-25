
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

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

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

target_link_libraries(pwm PRIVATE OpenSSL::Crypto)

include(CTest)
if(BUILD_TESTING)
    add_executable(credential_storage_tests
        tests/credential_storage_tests.cpp
        src/credential.cpp
        src/vault.cpp
    )
    target_include_directories(credential_storage_tests PRIVATE include src)
    target_link_libraries(credential_storage_tests PRIVATE OpenSSL::Crypto)
    add_test(NAME credential_storage_tests COMMAND credential_storage_tests)

    add_test(NAME show_password_option_rejected
        COMMAND pwm --get-pw sample-account --show-pw
    )
    set_tests_properties(show_password_option_rejected PROPERTIES WILL_FAIL TRUE)
endif()
