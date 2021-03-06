# shadowsocks-asio

An unofficial shadowsocks implementation that can work with official shadowsocks.

This project uses Asio network library, as well as the Coroutine and Concept features of C++20 to implement a concurrent server which can protect your Internet traffic.

## Get Started

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

## How to build

### Prerequisites

- A compiler supporting C++20.
- Python3 installed.

### Building with Conan Package Manager

1. Install Conan
    ~~~bash
    $ pip install conan -U
    ~~~

    > Important: If you are using GCC compiler >= 5.1, Conan will set the compiler.libcxx to the old ABI for backwards compatibility.<br/>
    > You can avoid this with the following commands:<br/>
    > ~~~bash
    > $ conan profile new default --detect
    > $ conan profile update settings.compiler.libcxx=libstdc++11 default
    > ~~~
    > See <https://docs.conan.io/en/latest/howtos/manage_gcc_abi.html#manage-gcc-abi>

2. Clone and install dependencies
    ~~~bash
    $ git clone https://github.com/ocfbnj/shadowsocks-asio
    $ cd shadowsocks-asio
    $ mkdir build
    $ cd build
    $ conan install ..
    ~~~

3. Build
    - On Windows
        ~~~bash
        $ cmake .. -G "Visual Studio 16"
        $ cmake --build . --config Release
        ~~~

    - On Linux
        ~~~bash
        $ cmake .. -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
        $ cmake --build .
        ~~~
    
    > Tip:<br/>
    > I prefer to use the Ninja generator.<br/>
    > See <https://ninja-build.org/>

## Dependent libraries
- [Asio](https://think-async.com/Asio/) is used to implement asynchronous logic in a synchronous manner.
- [cryptopp](https://github.com/weidai11/cryptopp) is used for encryption and decryption.
- [fmt](https://github.com/fmtlib/fmt) is used to format strings.
- [spdlog](https://github.com/gabime/spdlog) is used for logging.

## Test on
- GCC 10.3.0
- MSVC 19.29

## References
- <https://shadowsocks.org>
- <https://github.com/shadowsocks/shadowsocks-libev>
- <https://github.com/shadowsocks/go-shadowsocks2>
- <https://github.com/shadowsocks/shadowsocks-windows>
