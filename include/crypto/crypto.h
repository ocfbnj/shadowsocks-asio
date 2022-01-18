#ifndef OCFBNJ_CRYPTO_CRYPTO_H
#define OCFBNJ_CRYPTO_CRYPTO_H

#include "type.h"

// increment the number by 1.
void increment(BytesView num);

// deriveKey generate the master key from a password.
void deriveKey(ConstBytesView password, BytesView key);

// hkdfSha1 produces a subkey that is cryptographically strong even if the input secret key is weak.
void hkdfSha1(BytesView key, BytesView salt, BytesView subkey);

#endif
