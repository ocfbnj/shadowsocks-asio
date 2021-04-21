# shadowsocks-asio

An unofficial shadowsocks implementation that can work with official shadowsocks.

This project uses Asio(non-Boost) network library, as well as the Coroutine and Concept features of C++20 to implement a concurrent server which can protect your Internet traffic.

This project is for learning purposes.

## Usage

### Server

Start a server listening on port 5421 using `chacha20-ietf-poly1305` AEAD cipher with password `ocfbnj`.

~~~bash
$ shadowsocks-asio --Server -p 5421 -k ocfbnj -m chacha20-ietf-poly1305
~~~

### Client

Start a client connecting to the `ocfbnj.cn`.

The client listens on port 1080 for incoming SOCKS5 connections and uses `chacha20-ietf-poly1305` AEAD cipher with password `ocfbnj`.

~~~bash
$ shadowsocks-asio --Client -s ocfbnj.cn -p 5421 -l 1080 -k ocfbnj -m chacha20-ietf-poly1305
~~~

### Reference

~~~text
Usage: 
    --Server                   Server mode. (Default)
    --Client                   Client mode.

    -s <server host>           Host name or IP address of your remote server.
    -p <server port>           Port number of your remote server.
    -l <local port>            Port number of your local server.
    -k <password>              Password of your remote server.

    -m <encrypt method>        Encrypt method:
                               aes-128-gcm, aes-256-gcm,
                               chacha20-ietf-poly1305 (Default).

    -V                         Verbose mode.
~~~

## Dependent libraries
- [Asio(non-Boost)](https://think-async.com/Asio/) is used to implement asynchronous logic in a synchronous manner. 
- [Crypto++](https://github.com/weidai11/cryptopp) is used for encryption and decryption.
- [fmt](https://github.com/fmtlib/fmt) is used to format strings.
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
    $ ./vcpkg install asio cryptopp fmt spdlog gtest
    ~~~

5. Clone and build
    ~~~bash
    $ git clone https://github.com/ocfbnj/shadowsocks-asio
    $ cd shadowsocks-asio
    $ mkdir build && cd build
    $ cmake .. \
        -G Ninja \
        -DCMAKE_CXX_COMPILER:FILEPATH=/bin/g++-10 \
        -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake
    $ cmake --build .
    ~~~
    Where the `[path to vcpkg]` is your vcpkg root directory.

## Test on
- Ubuntu Server 20.04 LTS
- g++-10 (`sudo apt-get install g++-10`)
- Asio(non-Boost) 1.18.1 (`vcpkg install asio`)
- Crypto++ 8.2.0-2 (`vcpkg install cryptopp`)
- fmt 7.1.3#2 (`vcpkg install fmt`)
- spdlog 1.8.0#3 (`vcpkg install spdlog`)

## References
- <https://shadowsocks.org>
- <https://github.com/shadowsocks/shadowsocks-libev>
- <https://github.com/shadowsocks/go-shadowsocks2>
- <https://github.com/shadowsocks/shadowsocks-windows>
