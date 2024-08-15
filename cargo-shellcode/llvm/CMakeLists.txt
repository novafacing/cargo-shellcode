cmake_minimum_required(VERSION 3.20)
project(Shellcode)

find_program(LLVM_CONFIG NAMES llvm-config)

if (NOT LLVM_CONFIG)
    message(FATAL_ERROR "llvm-config not found")
endif()

execute_process(
    COMMAND ${LLVM_CONFIG} --cmakedir
    OUTPUT_VARIABLE LLVM_CMAKE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

list(APPEND CMAKE_PREFIX_PATH ${LLVM_CMAKE_DIR})

find_package(LLVM REQUIRED CONFIG)

if (${LLVM_PACKAGE_VERSION} VERSION_LESS "15.0.0")
    message(FATAL_ERROR "LLVM version must be at least 15.0.0")
endif()

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

if (NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAXE_CXX_FLAGS} -fno-rtti")
endif()

add_library(${PROJECT_NAME} SHARED Shellcode.cpp)

target_link_libraries(${PROJECT_NAME}
  "$<$<PLATFORM_ID:Darwin>:-undefined dynamic_lookup>")

install(TARGETS ${PROJECT_NAME} DESTINATION lib)