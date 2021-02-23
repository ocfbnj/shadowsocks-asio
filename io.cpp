#include <cstdint>

#include "io.h"
#include "logger.h"

std::size_t readFull(Reader& r, asio::mutable_buffer buf, asio::yield_context yield) {
    std::uint8_t* data = static_cast<std::uint8_t*>(buf.data());
    std::size_t nRead = 0;
    std::size_t remaining = buf.size();

    while (remaining > 0) {
        std::size_t n = r.read(asio::buffer(data + nRead, remaining), yield);

        nRead += n;
        remaining -= n;
    }

    return nRead;
}

void ioCopy(std::shared_ptr<ReadWriteCloser> w, std::shared_ptr<ReadWriteCloser> r,
            asio::yield_context yield) {
    std::array<std::uint8_t, 32768> buf;

    // Unknown problem: If we use std::error_code instead of try catch,
    // read() returns 0 and cannot get asio::error::eof.
    try {
        while (true) {
            std::size_t size = r->read(asio::buffer(buf), yield);
            w->write(asio::buffer(buf, size), yield);
        }
    } catch (const std::system_error& e) {
        r->close();
        w->close();

        if (e.code() != asio::error::eof) {
            log(WARN) << e.what() << "\n";
        }
    }
}
