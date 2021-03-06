# shadowsocks-asio

An unofficial shadowsocks implementation that can work with official shadowsocks.

This project uses Asio(non-Boost) and Boost.Coroutine2, as well as the Coroutine and Concept features of C++20 to implement a concurrent server which can protect your Internet traffic.

This project is for learning purposes.

## Dependent libraries
- [Asio(non-Boost)](https://think-async.com/Asio/) and [Boost.Coroutine2](https://www.boost.org/doc/libs/1_75_0/libs/coroutine2/doc/html/index.html) are used to implement asynchronous logic in a synchronous manner. 
- [Crypto++](https://github.com/weidai11/cryptopp) is used for encryption and decryption.
- [spdlog](https://github.com/gabime/spdlog) is used for logging.

## Test on
- Ubuntu Server 20.04 LTS
- g++-10 (`sudo apt-get install g++-10`)
- Asio(non-Boost) 1.18.0 (`vcpkg install asio[coroutine]`)
- Crypto++ 8.2.0-2 (`vcpkg install cryptopp`)
- spdlog 1.8.0#2 (`vcpkg install spdlog`)
