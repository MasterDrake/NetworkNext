cmake_minimum_required(VERSION 3.15)

# Set the runtime library to static for the entire project
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(next LANGUAGES CXX C VERSION 1.0.0)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Define common compile options and warnings
#add_compile_options(
#    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX /fp:fast>
#    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Werror -ffast-math>
#)
# Set warning flags depending on the compiler
if(MSVC)
    # Use MSVC-specific warning level
    add_compile_options(/W4 /WX) # /W4: Enable most warnings, /WX: Treat warnings as errors
else()
    # Use GCC/Clang warning flags
    add_compile_options(-Wall -Wextra -Werror) # -Wall: Enable most warnings, -Wextra: Enable extra warnings, -Werror: Treat warnings as errors
endif()

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(sodium)

add_subdirectory(source)

function(create_example_target example)
    add_executable(${example} ${example}.cpp)

    target_link_libraries(${example} PRIVATE NetworkNext::next sodium)

    # Platform-specific libraries
    if(APPLE)
        target_link_libraries(${example} PRIVATE "-framework SystemConfiguration" "-framework CoreFoundation")
    elseif(UNIX)
        target_link_libraries(${example} PRIVATE pthread)
    endif()
endfunction()

OPTION(BUILD_EXAMPLES "Build examples" ON)
OPTION(BUILD_TEST "Build test" ON)
OPTION(BUILD_SOAK "Build soak" ON)
OPTION(BUILD_FUZZ "Build fuzz" ON)

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BUILD_SOAK)
    create_example_target(soak "")
endif()

if(BUILD_TEST)
	create_example_target(test "")
endif()

if(BUILD_FUZZ)
	add_executable(fuzz soak.cpp)

    target_link_libraries(fuzz PRIVATE NetworkNext::next sodium)

    # Platform-specific libraries
    if(APPLE)
        target_link_libraries(fuzz PRIVATE "-framework SystemConfiguration" "-framework CoreFoundation")
    elseif(UNIX)
        target_link_libraries(fuzz PRIVATE pthread)
    endif()

    target_compile_definitions(fuzz PRIVATE NEXT_FUZZ=1)
endif()

## Set installation rules
#install(TARGETS next sodium
#    EXPORT NextworkNextTargets
#    RUNTIME DESTINATION bin
#    LIBRARY DESTINATION lib
#    ARCHIVE DESTINATION lib
#)
## Install CMake configuration
#include(CMakePackageConfigHelpers)
#write_basic_package_version_file(
#    "${CMAKE_CURRENT_BINARY_DIR}/NextworkNextConfigVersion.cmake"
#    VERSION ${PROJECT_VERSION}
#    COMPATIBILITY SameMajorVersion
#)
#install(EXPORT NextworkNextTargets
#    FILE NextworkNextTargets.cmake
#    NAMESPACE NextworkNext::
#    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/next
#)
#install(FILES
#    cmake/NextworkNextConfig.cmake
#    "${CMAKE_CURRENT_BINARY_DIR}/NextworkNextConfigVersion.cmake"
#    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/next
#)
#
install(DIRECTORY include/ DESTINATION include)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/NextworkNextConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)
install(TARGETS next sodium
        EXPORT NextworkNextTargets
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT NextworkNextTargets
        FILE "NetworkNextConfig.cmake"
        NAMESPACE NetworkNext::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/next)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/NextworkNextConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/next)

#install(DIRECTORY include
#        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

#export(TARGETS next sodium NAMESPACE NetworkNext:: FILE NextworkNextTargets.cmake)
