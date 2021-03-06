cmake_minimum_required(VERSION 3.5)

project(aes_custom_interface)

# Default to C++14
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # we dont use add_compile_options with pedantic in message packages
  # because the Python C extensions don't comply with it
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
endif()

find_package(ament_cmake REQUIRED)
find_package(rosidl_default_generators REQUIRED)

set(msg_files "msg/AesMessageCertify.msg")

set(srv_files "srv/GetSymmSecret.srv")

rosidl_generate_interfaces(${PROJECT_NAME}
                           ${srv_files}
                           ${msg_files})

ament_export_dependencies(rosidl_default_runtime)

ament_package()
