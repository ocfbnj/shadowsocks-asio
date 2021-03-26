#ifndef IO_H
#define IO_H

#include <array>
#include <concepts>
#include <system_error>

#include <asio/awaitable.hpp>
#include <spdlog/spdlog.h>

#include "type.h"

// clang-format off

template <typename T>
concept Reader = requires (T r, BytesView buf) {
    { r.read(buf) } -> std::same_as<asio::awaitable<Size>>;
};

template <typename T>
concept Writer = requires (T w, BytesView buf) {
    { w.write(buf) } -> std::same_as<asio::awaitable<Size>>;
};

template <typename T>
concept Closer = requires (T c) {
    { c.close() } -> std::same_as<void>;
};

template <typename T>
concept ReadWriter = Reader<T> && Writer<T>;

template <typename T>
concept ReadWriteCloser = Reader<T> && Writer<T> && Closer<T>;

// clang-format on

template <ReadWriteCloser W, ReadWriteCloser R>
asio::awaitable<void> ioCopy(std::shared_ptr<W> w, std::shared_ptr<R> r) {
    std::array<u8, 32768> buf;

    try {
        while (true) {
            Size size = co_await r->read(buf);
            co_await w->write(BytesView{buf.data(), size});
        }
    } catch (const std::system_error& e) {
        r->close();
        w->close();

        if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
            spdlog::debug(e.what());
        }
    }
}

// readFull reads exactly buf.size() bytes from r.
asio::awaitable<Size> readFull(Reader auto& r, BytesView buf) {
    u8* data = buf.data();
    Size nRead = 0;
    Size remaining = buf.size();

    while (remaining > 0) {
        Size n = co_await r.read(BytesView{data + nRead, remaining});

        nRead += n;
        remaining -= n;
    }

    co_return nRead;
}

#endif
