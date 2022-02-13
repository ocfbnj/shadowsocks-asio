# shadowsocks-asio

[![CI](https://github.com/ocfbnj/shadowsocks-asio/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ocfbnj/shadowsocks-asio/actions/workflows/ci.yml)

An unofficial shadowsocks implementation that can work with official shadowsocks.

This project uses Asio network library, as well as the Coroutine and Concept features of C++20 to implement a concurrent server which can protect your Internet traffic.

## Features

- [x] [SOCKS5](https://datatracker.ietf.org/doc/html/rfc1928) CONNECT command
- [x] [AEAD](https://shadowsocks.org/en/wiki/AEAD-Ciphers.html) ciphers
- [x] Defend against [replay attacks](https://github.com/shadowsocks/shadowsocks-org/issues/44)
- [x] [Access control list](https://github.com/shadowsocks/shadowsocks-rust#acl) (IPv4 only)
- [x] [SIP002](https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html) URI scheme

## Get Started

### Server

Start a server listening on port 5421 using `chacha20-ietf-poly1305` AEAD cipher with password `ocfbnj`.

~~~bash
shadowsocks-asio --Server -p 5421 -k ocfbnj -m chacha20-ietf-poly1305
~~~

### Client

Start a client connecting to the `ocfbnj.cn`.

The client listens on port 1080 for incoming SOCKS5 connections and uses `chacha20-ietf-poly1305` AEAD cipher with password `ocfbnj`.

~~~bash
shadowsocks-asio --Client -s ocfbnj.cn -p 5421 -l 1080 -k ocfbnj -m chacha20-ietf-poly1305
~~~

## How to build

### Prerequisites

- A compiler supporting C++20.
- Python3 installed.

### Building with Conan Package Manager

1. Install Conan

    ~~~bash
    pip install conan -U
    ~~~

2. Clone

    ~~~bash
    git clone https://github.com/ocfbnj/shadowsocks-asio --recurse-submodules
    cd shadowsocks-asio
    mkdir build && cd build
    ~~~

3. Build
    - On Windows

        ~~~bash
        cmake .. -DCMAKE_BUILD_TYPE=Release
        cmake --build . --config Release
        ~~~

    - On Linux or Mac OS

        ~~~bash
        cmake .. -DCMAKE_BUILD_TYPE=Release
        cmake --build .
        ~~~

    > Tip:
    >
    > I prefer to use the Ninja generator.
    >
    > See <https://ninja-build.org/>

## Dependent libraries

- [Asio](https://think-async.com/Asio/) is used to implement asynchronous logic in a synchronous manner.
- [mbedtls](https://github.com/ARMmbed/mbedtls) is used for encryption and decryption.
- [fmt](https://github.com/fmtlib/fmt) is used to format strings.
- [spdlog](https://github.com/gabime/spdlog) is used for logging.

## References

- <https://shadowsocks.org>
- <https://github.com/shadowsocks/shadowsocks-libev>
- <https://github.com/shadowsocks/go-shadowsocks2>
- <https://github.com/shadowsocks/shadowsocks-windows>
