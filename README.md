# shadowsocks-asio

An unofficial shadowsocks implementation that can work with official shadowsocks.

This project uses Asio(non-Boost) and Boost.Coroutine2, as well as the Coroutine and Concept features of C++20 to implement a concurrent server which can protect your Internet traffic.

This project is for learning purposes.

## Dependent libraries
- [Asio(non-Boost)](https://think-async.com/Asio/) and [Boost.Coroutine2](https://www.boost.org/doc/libs/1_75_0/libs/coroutine2/doc/html/index.html) are used to implement asynchronous logic in a synchronous manner. 
- [Crypto++](https://github.com/weidai11/cryptopp) is used for encryption and decryption.
- [spdlog](https://github.com/gabime/spdlog) is used for logging.

## Building on Ubuntu 20.04 LTS

1. Install g++-10
    ~~~bash
    $ sudo apt-get install g++-10
    ~~~

2. Install CMake and Ninja
    ~~~bash
    $ sudo apt-get install cmake ninja-build
    ~~~

3. Install vcpkg
    ~~~bash
    $ git clone https://github.com/microsoft/vcpkg
    $ ./vcpkg/bootstrap-vcpkg.sh
    ~~~
    See <https://github.com/microsoft/vcpkg#quick-start-unix>

4. Install dependencies
    ~~~bash
    $ ./vcpkg install asio[coroutine] cryptopp fmt spdlog
    ~~~

5. Clone and build
    ~~~bash
    $ git clone https://github.com/ocfbnj/shadowsocks-asio
    $ cd shadowsocks-asio
    $ mkdir build
    $ cd build
    $ cmake \
        -G Ninja \
        -DCMAKE_CXX_COMPILER:FILEPATH=/bin/g++-10 \
        -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake \
        ..
    $ cmake --build .
    ~~~
    Where the [path to vcpkg] is your vcpkg root directory.

## Test on
- Ubuntu Server 20.04 LTS
- g++-10 (`sudo apt-get install g++-10`)
- Asio(non-Boost) 1.18.0 (`vcpkg install asio[coroutine]`)
- Crypto++ 8.2.0-2 (`vcpkg install cryptopp`)
- fmt 7.1.3#2 (`vcpkg install fmt`)
- spdlog 1.8.0#2 (`vcpkg install spdlog`)
