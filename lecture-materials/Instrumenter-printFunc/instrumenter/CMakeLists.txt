cmake_minimum_required(VERSION 3.13)
project(PrintFuncPass LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(HandleLLVMOptions)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

# Build as a plugin MODULE
add_library(pfpass MODULE printFunc.cpp)

# Optional: Set C++ standard (good practice)
set_target_properties(pfpass PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)
