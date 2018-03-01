cmake_minimum_required(VERSION 3.5)
project(aes_publisher_certify)

# Default to C++14
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

set(BINARY_NAME aes_publisher_certify)
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
find_package(fastrtps REQUIRED)
find_package(fastcdr REQUIRED)
find_package(std_msgs REQUIRED)
find_package(aes_custom_interface REQUIRED)
find_package(ca_security_api REQUIRED)
include_directories(${ca_security_api_INCLUDE_DIRS}/ca_security_api)

find_package(optee_ta_security REQUIRED)
ament_export_dependencies(optee_ta_security)
include_directories(${optee_ta_security_INCLUDE_DIRS}/optee_ta_security)

file(GLOB_RECURSE SRC_FILES_CXX ${PROJECT_SOURCE_DIR}/*.cpp)

add_executable(${BINARY_NAME} ${SRC_FILES_CXX})

target_link_libraries(${BINARY_NAME}
                      ${ca_security_api_LIBRARIES}
                      teec
                      )

ament_target_dependencies(${BINARY_NAME}
                            fastrtps
                            fastcdr
                            rclcpp
                            std_msgs
                            ca_security_api
                            aes_custom_interface
                            )

install(TARGETS ${BINARY_NAME}
        DESTINATION lib/${PROJECT_NAME}
)

ament_package()
