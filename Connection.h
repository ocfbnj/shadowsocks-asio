#ifndef CONNECTION_H
#define CONNECTION_H

#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>

#include "io.h"

// Connection encapsulates a socket for reading and writing.
class Connection : public ReadWriteCloser {
public:
    Connection(asio::ip::tcp::socket&& s);

    std::size_t read(asio::mutable_buffer buffer, asio::yield_context yield) override;
    std::size_t write(asio::const_buffer buffer, asio::yield_context yield) override;
    void close() override;

protected:
    asio::ip::tcp::socket socket;
};

#endif
