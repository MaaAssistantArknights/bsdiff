### cmake file for building libdivsufsort Package ###
cmake_minimum_required(VERSION 3.10)

project(libdivsufsort C)

## Project options ##
option(DIVSUFSORT_USE_OPENMP "Use OpenMP" OFF)

if(DIVSUFSORT_USE_OPENMP)
  find_package(OpenMP REQUIRED)
endif()

# ## Compiler options ##
# if(MSVC)
#   append_c_compiler_flags("/W4" "VC" CMAKE_C_FLAGS)
#   append_c_compiler_flags("/Oi;/Ot;/Ox;/Oy" "VC" CMAKE_C_FLAGS_RELEASE)
#   if(USE_OPENMP)
#     append_c_compiler_flags("/openmp" "VC" CMAKE_C_FLAGS)
#   endif(USE_OPENMP)
# elseif(BORLAND)
#   append_c_compiler_flags("-w" "BCC" CMAKE_C_FLAGS)
#   append_c_compiler_flags("-Oi;-Og;-Os;-Ov;-Ox" "BCC" CMAKE_C_FLAGS_RELEASE)
# else(MSVC)
#   if(CMAKE_COMPILER_IS_GNUCC)
#     append_c_compiler_flags("-Wall" "GCC" CMAKE_C_FLAGS)
#     append_c_compiler_flags("-fomit-frame-pointer" "GCC" CMAKE_C_FLAGS_RELEASE)
#     if(USE_OPENMP)
#       append_c_compiler_flags("-fopenmp" "GCC" CMAKE_C_FLAGS)
#     endif(USE_OPENMP)
#   else(CMAKE_COMPILER_IS_GNUCC)
#     append_c_compiler_flags("-Wall" "UNKNOWN" CMAKE_C_FLAGS)
#     append_c_compiler_flags("-fomit-frame-pointer" "UNKNOWN" CMAKE_C_FLAGS_RELEASE)
#     if(USE_OPENMP)
#       append_c_compiler_flags("-fopenmp;-openmp;-omp" "UNKNOWN" CMAKE_C_FLAGS)
#     endif(USE_OPENMP)
#   endif(CMAKE_COMPILER_IS_GNUCC)
# endif(MSVC)


add_library(divsufsort STATIC lib/divsufsort.c lib/sssort.c lib/trsort.c lib/utils.c)
target_compile_definitions(divsufsort PRIVATE HAVE_CONFIG_H=1)

add_library(divsufsort64 STATIC lib/divsufsort.c lib/sssort.c lib/trsort.c lib/utils.c)
target_compile_definitions(divsufsort64 PRIVATE BUILD_DIVSUFSORT64=1)

foreach(target divsufsort divsufsort64)
  target_compile_definitions(${target} PRIVATE HAVE_CONFIG_H=1)
  target_include_directories(${target} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  if(DIVSUFSORT_USE_OPENMP)
    target_link_libraries(${target} PRIVATE OpenMP::OpenMP_C)
  endif()
endforeach(target divsufsort divsufsort64)

install(TARGETS divsufsort divsufsort64
        EXPORT libdivsufsort-targets)
install(FILES include/divsufsort.h DESTINATION include)
