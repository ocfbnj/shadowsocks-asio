#ifndef IO_H
#define IO_H

#include <cstddef>
#include <memory>

#include <asio/spawn.hpp>
#include <asio/ts/buffer.hpp>

struct Reader {
    virtual ~Reader() = default;
    virtual std::size_t read(asio::mutable_buffer buffer, asio::yield_context yield) = 0;
};

struct Writer {
    virtual ~Writer() = default;
    virtual std::size_t write(asio::const_buffer buffer, asio::yield_context yield) = 0;
};

struct Closer {
    virtual ~Closer() = default;
    virtual void close() = 0;
};

struct ReadWriter : Reader, Writer {};
struct ReadWriteCloser : ReadWriter, Closer {};

std::size_t readFull(Reader& r, asio::mutable_buffer buf, asio::yield_context yield);
void ioCopy(std::shared_ptr<ReadWriteCloser> w, std::shared_ptr<ReadWriteCloser> r,
            asio::yield_context yield);

#endif
