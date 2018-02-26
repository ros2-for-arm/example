# Build arm examples

In order to build arm-examples using TrustZone, the following parameters should be given to ament in order to specify the path to the specific build of Optee-OS and Optee-Client

```
#!/bin/bash

export CROSS_COMPILE=aarch64-linux-gnu-

optee_os_export=<Path to OPTEE-OS>/out/arm-plat-hikey/export-ta_arm64
optee_client_export=<Path to OPTEE-Client>/out/export

src/ament/ament_tools/scripts/ament.py build --force-cmake-configure \
        --cmake-args \
        -DCMAKE_TOOLCHAIN_FILE=`pwd`/aarch64_toolchainfile.cmake \
        -DTHIRDPARTY=ON \
        -DOPTEE_OS_EXPORT=$optee_os_export \
        -DOPTEE_CLIENT_EXPORT=$optee_client_export
```

Produced binaries and libraries will go under the following folders in ROS2:
- *./ros2/install/lib/aes_publisher_certify* and *./ros2/install/lib/aes_subscriber_certify* for the binary applications
- *./ros2/install/lib* for all the necessary libraries if ROS2 was Dynamically cross-compiled. Those libraries should be copied into the file system and LD_LIBRARY_PATH variable should point to the folder containing them.
- *./ros2/install/lib/optee_ta_security* for the Trusted application. This should go to */lib/optee_armtz/* in the file-system used
- tee-supplicant must be started. It can be found into the optee-client directory: *optee-client/out/export/bin*
	- The libraries in *out/export/lib* must be copied in the used file-system and LD_LIBRARY_PATH should point to the directory containing those libraries.

## Reference board setup
You can find information in how to setup an HiKey 960 board on the arm community page:
https://community.arm.com/dev-platforms/w/docs/309/hikey-96-boards

## Wiki
More documentation is in the wiki: https://github.com/ros2-for-arm/ros2/wiki/ROS2-on-arm-architecture
