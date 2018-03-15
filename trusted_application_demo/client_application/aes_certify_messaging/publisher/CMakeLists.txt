cmake_minimum_required(VERSION 3.5)
project(aes_publisher_certify)

# Default to C++14
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)
  ament_lint_auto_find_test_dependencies()
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Trusted application libraries
if((NOT DEFINED OPTEE_CLIENT_EXPORT) OR (NOT IS_DIRECTORY ${OPTEE_CLIENT_EXPORT}))
  message(WARNING "OPTEE_CLIENT_EXPORT must be defined to compile ${PROJECT_NAME} -- Skipping this package")
  return()
endif()

link_directories(${OPTEE_CLIENT_EXPORT}/lib)
include_directories(${OPTEE_CLIENT_EXPORT}/include)

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(rcutils REQUIRED)
find_package(aes_custom_interface REQUIRED)
find_package(ca_security_api REQUIRED)
include_directories(${ca_security_api_INCLUDE_DIRS}/ca_security_api)

find_package(ta_security_api REQUIRED)
ament_export_dependencies(ta_security_api)
include_directories(${ta_security_api_INCLUDE_DIRS}/ta_security_api)

file(GLOB_RECURSE SRC_FILES_CXX ${PROJECT_SOURCE_DIR}/*.cpp)

add_executable(${PROJECT_NAME} ${SRC_FILES_CXX})

target_link_libraries(${PROJECT_NAME}
                      ${ca_security_api_LIBRARIES}
                      teec)

ament_target_dependencies(${PROJECT_NAME}
                          rclcpp
                          ca_security_api
                          aes_custom_interface)

install(TARGETS ${PROJECT_NAME}
        DESTINATION lib/${PROJECT_NAME}
)

ament_package()
