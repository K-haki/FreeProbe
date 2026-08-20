add_executable(ptx_test ptx_test.cpp)

# spdlog is provided by parent CMakeLists.txt via FetchContent
if(NOT TARGET spdlog::spdlog)
    find_package(spdlog REQUIRED)
endif()

option(LLVMBPF_CUDA_PATH "Path where CUDA installs")
message(STATUS "LLVMBPF_CUDA_PATH=${LLVMBPF_CUDA_PATH}")
if(NOT LLVMBPF_CUDA_PATH)
    message(FATAL_ERROR "Please set LLVMBPF_CUDA_PATH if you want to build ptx_test, otherwise set LLVMBPF_ENABLE_PTX to NO")
endif()
set(LLVM_LINK_COMPONENTS 
  ${LLVM_TARGETS_TO_BUILD}
  )
target_link_directories(ptx_test PRIVATE ${LLVMBPF_CUDA_PATH}/lib64 ${LLVMBPF_CUDA_PATH}/lib64/stubs)

# Detect CUDA version to determine if nvptxcompiler_static is available
if(EXISTS "${LLVMBPF_CUDA_PATH}/version.json")
    file(READ "${LLVMBPF_CUDA_PATH}/version.json" CUDA_VERSION_JSON)
    string(REGEX MATCH "\"cuda\"[^{]*\\{[^}]*\"version\"[^\"]*\"([0-9]+)\\.([0-9]+)" _ "${CUDA_VERSION_JSON}")
    set(LLVMBPF_CUDA_VERSION_MAJOR ${CMAKE_MATCH_1})
elseif(EXISTS "${LLVMBPF_CUDA_PATH}/version.txt")
    file(READ "${LLVMBPF_CUDA_PATH}/version.txt" CUDA_VERSION_TXT)
    string(REGEX MATCH "CUDA Version ([0-9]+)\\.([0-9]+)" _ "${CUDA_VERSION_TXT}")
    set(LLVMBPF_CUDA_VERSION_MAJOR ${CMAKE_MATCH_1})
else()
    string(REGEX MATCH "cuda-([0-9]+)\\.([0-9]+)" _ "${LLVMBPF_CUDA_PATH}")
    set(LLVMBPF_CUDA_VERSION_MAJOR ${CMAKE_MATCH_1})
endif()

# nvptxcompiler_static is only available in CUDA 12.x and earlier
if(LLVMBPF_CUDA_VERSION_MAJOR LESS 13)
    find_library(NVPTXCOMPILER_LIB
        NAMES
        nvptxcompiler_static
        PATHS
        ${LLVMBPF_CUDA_PATH}/lib64
        ${LLVMBPF_CUDA_PATH}/lib64/stubs
        NO_DEFAULT_PATH)
    if(NOT NVPTXCOMPILER_LIB)
        message(FATAL_ERROR "nvptxcompiler_static library not found in ${LLVMBPF_CUDA_PATH}/lib64 or ${LLVMBPF_CUDA_PATH}/lib64/stubs")
    endif()
    message(STATUS "CUDA ${LLVMBPF_CUDA_VERSION_MAJOR}.x: Linking with nvptxcompiler_static")
    target_link_libraries(ptx_test
                PRIVATE
                ${LLVM_LIBS}
                llvmbpf_vm
                cuda
                ${NVPTXCOMPILER_LIB}
                spdlog::spdlog)
else()
    message(STATUS "CUDA ${LLVMBPF_CUDA_VERSION_MAJOR}.x: Skipping nvptxcompiler_static (not available)")
    target_link_libraries(ptx_test
                PRIVATE
                ${LLVM_LIBS}
                llvmbpf_vm
                cuda
                spdlog::spdlog)
endif()
  
add_dependencies(ptx_test llvmbpf_vm spdlog::spdlog)
target_include_directories(ptx_test PRIVATE ${LLVM_INCLUDE_DIRS} include src ${LLVMBPF_CUDA_PATH}/include ${SPDLOG_INCLUDES})
