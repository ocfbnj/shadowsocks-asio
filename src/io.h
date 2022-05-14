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
concept reader = requires(T r, std::span<std::uint8_t> buf) {
    { r.read(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept writer = requires(T w, std::span<const std::uint8_t> buf) {
    { w.write(buf) } -> std::same_as<asio::awaitable<std::size_t>>;
};

template <typename T>
concept closer = requires(T c) {
    { c.close() } -> std::same_as<void>;
};

template <typename T>
concept reader_writer = reader<T> && writer<T>;

template <typename T>
concept reader_writer_closer = reader<T> && writer<T> && closer<T>;

template <typename T>
concept conn = reader_writer_closer<T> && requires(T conn, int timeout) {
    { conn.set_read_timeout(timeout) } -> std::same_as<void>;
};

constexpr auto buffer_size = 32768;

template <conn W, conn R>
asio::awaitable<void> io_copy(std::shared_ptr<W> w, std::shared_ptr<R> r) {
    std::array<std::uint8_t, buffer_size> buf;

    try {
        while (true) {
            std::size_t size = co_await r->read(buf);
            co_await w->write(std::span{buf.data(), size});
        }
    } catch (const std::system_error& e) {
        if (e.code() == asio::error::eof) {
            w->close();
        }

        w->set_read_timeout(5); // 5 seconds

        if (e.code() != asio::error::eof && e.code() != asio::error::timed_out) {
            spdlog::debug("{}", e.what());
        }
    }
}

// read_full reads exactly buf.size() bytes from r.
asio::awaitable<std::size_t> read_full(reader auto& r, std::span<std::uint8_t> buf) {
    std::uint8_t* data = buf.data();
    std::size_t n_read = 0;
    std::size_t remaining = buf.size();

    while (remaining > 0) {
        std::size_t n = co_await r.read(std::span{data + n_read, remaining});

        n_read += n;
        remaining -= n;
    }

    co_return n_read;
}

#endif
