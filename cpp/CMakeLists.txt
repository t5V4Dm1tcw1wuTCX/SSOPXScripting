cmake_minimum_required(VERSION 3.20)
project(SSOExternal LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Keystone — build from source or point KEYSTONE_DIR to an install
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../keystone/CMakeLists.txt")
    set(BUILD_LIBS_ONLY ON CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(LLVM_TARGETS_TO_BUILD "X86" CACHE STRING "" FORCE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../keystone ${CMAKE_CURRENT_BINARY_DIR}/keystone)
    set(KS_INC ${CMAKE_CURRENT_SOURCE_DIR}/../../keystone/include)
    set(KS_LIB keystone)
else()
    set(KEYSTONE_DIR "" CACHE PATH "Keystone install prefix")
    set(KS_INC ${KEYSTONE_DIR}/include)
    find_library(KS_LIB NAMES keystone PATHS ${KEYSTONE_DIR}/lib)
endif()

add_executable(SSOExternal SSOExternal.cpp)
target_include_directories(SSOExternal PRIVATE ${KS_INC})
target_link_libraries(SSOExternal PRIVATE ${KS_LIB})
target_compile_definitions(SSOExternal PRIVATE KEYSTONE_STATIC)
