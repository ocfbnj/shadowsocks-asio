#ifndef CONNECTION_H
#define CONNECTION_H

#include <asio/awaitable.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>

#include "AsyncObject.h"
#include "type.h"

// Connection encapsulates a socket for reading and writing.
class Connection {
public:
    Connection(TCPSocket s);

    asio::awaitable<Size> read(BytesView buffer);
    asio::awaitable<Size> write(BytesView buffer);
    void close();

protected:
    TCPSocket socket;

private:
    bool closed = false;
};

#endif
