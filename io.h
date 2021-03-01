#ifndef IO_H
#define IO_H

#include <concepts>
#include <cstddef>
#include <cstdint>

#include <asio/awaitable.hpp>
#include <asio/ts/buffer.hpp>

#include "logger.h"

// clang-format off

template <typename T>
concept Reader = requires (T r, asio::mutable_buffer buf) {
    { r.read(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept Writer = requires (T w, asio::const_buffer buf) {
    { w.write(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept Closer = requires (T c) {
    { c.close() } -> std::same_as<void>;
};

template <typename T>
concept ReadWriteCloser = Reader<T> && Writer<T> && Closer<T>;

template <ReadWriteCloser W, ReadWriteCloser R>
asio::awaitable<void> ioCopy(std::shared_ptr<W> w, std::shared_ptr<R> r) {
    std::array<std::uint8_t, 32768> buf;

    try {
        while (true) {
            std::size_t size = co_await r->read(asio::buffer(buf));
            co_await w->write(asio::buffer(buf, size));
        }
    } catch (const std::system_error& e) {
        r->close();
        w->close();

        if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
            log(WARN) << e.what() << "\n";
        }
    }
}

// clang-format on

asio::awaitable<std::size_t> readFull(Reader auto& r, asio::mutable_buffer buf) {
    std::uint8_t* data = static_cast<std::uint8_t*>(buf.data());
    std::size_t nRead = 0;
    std::size_t remaining = buf.size();

    while (remaining > 0) {
        std::size_t n = co_await r.read(asio::buffer(data + nRead, remaining));

        nRead += n;
        remaining -= n;
    }

    co_return nRead;
}

#endif
