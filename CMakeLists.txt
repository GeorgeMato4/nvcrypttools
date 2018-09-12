cmake_minimum_required(VERSION 3.9)
project(nvcrypttools C)

add_subdirectory(mbedtls EXCLUDE_FROM_ALL)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux|Android")
add_executable(warmboot-h4x warmboot-h4x.c nvaes.c)
target_compile_options(warmboot-h4x PRIVATE -Wall -Wextra -std=gnu11)
install(TARGETS warmboot-h4x RUNTIME DESTINATION .)
endif ()

add_executable(warmboot-h4x-portable warmboot-h4x.c nvaes-non-device.c)
target_compile_options(warmboot-h4x-portable PRIVATE -Wall -Wextra -std=gnu11)
target_link_libraries(warmboot-h4x-portable mbedcrypto)
target_include_directories(warmboot-h4x-portable PRIVATE ${CMAKE_SOURCE_DIR}/mbedtls/include)

install(TARGETS warmboot-h4x-portable RUNTIME DESTINATION .)
