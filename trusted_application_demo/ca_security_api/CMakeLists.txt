cmake_minimum_required(VERSION 3.5)
project(ca_security_api)

add_compile_options(-Wall -Wextra -Wpedantic)
find_package(ament_cmake_ros REQUIRED)

if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)
  ament_lint_auto_find_test_dependencies()
endif()

if((NOT DEFINED OPTEE_CLIENT_EXPORT) OR (NOT IS_DIRECTORY ${OPTEE_CLIENT_EXPORT}))
  message(WARNING "OPTEE_CLIENT_EXPORT must be defined to compile ${PROJECT_NAME} -- Skipping this package")
  return()
endif()

find_package(ta_security_api REQUIRED)
include_directories(${ta_security_api_INCLUDE_DIRS}/ta_security_api)

link_directories(${OPTEE_CLIENT_EXPORT}/lib)
include_directories(${OPTEE_CLIENT_EXPORT}/include)

include_directories(include)

set(${PROJECT_NAME}_sources
    src/teec_utils.c
    src/aes_api.c
    src/rsa_api.c
    src/hmac_api.c)

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_sources})

install(TARGETS ${PROJECT_NAME}
        DESTINATION lib/${PROJECT_NAME})

ament_export_include_directories(include)
ament_export_libraries(${PROJECT_NAME})

install(DIRECTORY include/
  DESTINATION include/${PROJECT_NAME}
  FILES_MATCHING PATTERN "*.h")

install(
  TARGETS ${PROJECT_NAME}
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)

ament_package()
