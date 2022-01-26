#ifndef IO_H
#define IO_H

#include <array>
#include <concepts>
#include <cstdint>
#include <span>
#include <system_error>

#include <asio/awaitable.hpp>
#include <spdlog/spdlog.h>

template <typename T>
concept Reader = requires(T r, std::span<std::uint8_t> buf) {
    { r.read(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept Writer = requires(T w, std::span<const std::uint8_t> buf) {
    { w.write(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept Closer = requires(T c) {
    { c.close() } -> std::same_as<void>;
};

template <typename T>
concept ReadWriter = Reader<T> && Writer<T>;

template <typename T>
concept ReadWriterCloser = Reader<T> && Writer<T> && Closer<T>;

template <typename T>
concept Conn = ReadWriterCloser<T> && requires(T conn, int timeout) {
    { conn.setReadTimeout(timeout) } -> std::same_as<void>;
};

constexpr auto BufferSize = 32768;

template <Conn W, Conn R>
asio::awaitable<void> ioCopy(std::shared_ptr<W> w, std::shared_ptr<R> r) {
    std::array<std::uint8_t, BufferSize> buf;

    try {
        while (true) {
            std::size_t size = co_await r->read(buf);
            co_await w->write(std::span{buf.data(), size});
        }
    } catch (const std::system_error& e) {
        if (e.code() == asio::error::eof) {
            w->close();
        }

        w->setReadTimeout(5); // 5 seconds

        if (e.code() != asio::error::eof && e.code() != asio::error::timed_out) {
            spdlog::debug("{}", e.what());
        }
    }
}

// readFull reads exactly buf.size() bytes from r.
asio::awaitable<std::size_t> readFull(Reader auto& r, std::span<std::uint8_t> buf) {
    std::uint8_t* data = buf.data();
    std::size_t nRead = 0;
    std::size_t remaining = buf.size();

    while (remaining > 0) {
        std::size_t n = co_await r.read(std::span{data + nRead, remaining});

        nRead += n;
        remaining -= n;
    }

    co_return nRead;
}

#endif
