#ifndef IO_H
#define IO_H

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#include <asio/awaitable.hpp>
#include <spdlog/spdlog.h>

// clang-format off

template <typename T>
concept Reader = requires (T r, std::span<std::uint8_t> buf) {
    { r.read(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept Writer = requires (T w, std::span<std::uint8_t> buf) {
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
            std::size_t size = co_await r->read(buf);
            co_await w->write(std::span{std::data(buf), size});
        }
    } catch (const std::system_error& e) {
        r->close();
        w->close();

        if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
            spdlog::debug(e.what());
        }
    }
}

// clang-format on

// readFull reads exactly std::size(buf) bytes from r.
asio::awaitable<std::size_t> readFull(Reader auto& r, std::span<std::uint8_t> buf) {
    std::uint8_t* data = std::data(buf);
    std::size_t nRead = 0;
    std::size_t remaining = std::size(buf);

    while (remaining > 0) {
        std::size_t n = co_await r.read(std::span{data + nRead, remaining});

        nRead += n;
        remaining -= n;
    }

    co_return nRead;
}

#endif
