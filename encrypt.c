#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "encrypt.h"
#include "debug.h"

void prints2h(const unsigned char *value, size_t size) {
    #ifdef DEBUG
        int i;
        fprintf(stderr, "0x");
        for (i = 0; i < size; ++i) {
            fprintf(stderr, "%02x", *(value + i));
        }
        fprintf(stderr, "\n");
    #endif
}

void init_counter(CounterState *state, const unsigned char iv[16]) {
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
    * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

ssize_t write_encrypted(int writefd, EncryptionKey *key, unsigned char *buffer,
                        size_t size) {
    AES_KEY aeskey;
    size_t i;
    ssize_t bytes_written, total_bytes_written = 0;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    CounterState state;
    memset(&state, 0, sizeof(CounterState));

    debug("Buffer size: %ld\n", size);

    // Generate an IV
    if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
       error("Could not create random bytes for iv.\n");
       exit(EXIT_FAILURE);
    }

    // Set the key
    if (AES_set_encrypt_key(key->value, 128, &aeskey) < 0) {
        fprintf(stderr, "Could not set encryption key.");
        exit(1);
    }

    // Start encrypting the file
    memset(indata, 0, AES_BLOCK_SIZE);
    memset(outdata, 0, AES_BLOCK_SIZE);
    // Make the last 8 bytes of the IV 0
    memset(iv + 8, 0, 8);
    // Initialize the counter
    init_counter(&state, iv);

    // Write the IV bytes to the socket
    write(writefd, iv, AES_BLOCK_SIZE);
    for(i = 0; i < size; i += 16) {
        int bytes_cpy = (size - i >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : size - i;
        debug("Bytes_cpy: %d\n", bytes_cpy);
        // Copy the buffer into the in-data buffer
        memcpy(indata, buffer + i, bytes_cpy);
        // Encrypt the bytes with the key
        AES_ctr128_encrypt(indata, outdata, bytes_cpy, &aeskey, state.ivec,
                           state.ecount, &(state.num));

        // Write the encrypted bytes back out
        if ((bytes_written = write(writefd, outdata, bytes_cpy)) != bytes_cpy) {
            // TODO: Something bad happened
            total_bytes_written = -1;
            break;
        }

        // Total up the bytes written
        total_bytes_written += bytes_written;

        // Zero out the buffers
        memset(indata, 0, AES_BLOCK_SIZE);
        memset(outdata, 0, AES_BLOCK_SIZE);

        debug("ivec: ");
        prints2h(state.ivec, AES_BLOCK_SIZE);
        debug("num: %d\n", state.num);
        debug("ecount: ");
        prints2h(state.ecount, AES_BLOCK_SIZE);
    }
    debug("Total_bytes_written: %ld\n", total_bytes_written);

    return total_bytes_written;
}

ssize_t write_decrypted(int writefd, EncryptionKey *key, unsigned char *buffer,
                        size_t size) {
    AES_KEY aeskey;
    size_t i;
    ssize_t bytes_written, total_bytes_written = 0;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    CounterState state;
    memset(&state, 0, sizeof(CounterState));

    // Set the key
    if (AES_set_encrypt_key(key->value, 128, &aeskey) < 0) {
        fprintf(stderr, "Could not set encryption key.");
        exit(1);
    }

    // Start encrypting the file
    memset(indata, 0, AES_BLOCK_SIZE);
    memset(outdata, 0, AES_BLOCK_SIZE);
    // Read in the IV from the buffer
    memcpy(iv, buffer, 16);
    // Initialize the counter
    init_counter(&state, iv);

    for(i = 16; i < size; i += 16) {
        int bytes_cpy = (size - i >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : size - i;
        // Copy the buffer into the in-data buffer
        memcpy(indata, buffer + i, bytes_cpy);
        // Encrypt the bytes with the key
        AES_ctr128_encrypt(indata, outdata, bytes_cpy, &aeskey, state.ivec,
                           state.ecount, &(state.num));

        // Write the encrypted bytes back out
        if ((bytes_written = write(writefd, outdata, bytes_cpy)) != bytes_cpy) {
            // TODO: Something bad happened
            total_bytes_written = -1;
            break;
        }

        // Total up the bytes written
        total_bytes_written += bytes_written;

        // Zero out the buffers
        memset(indata, 0, AES_BLOCK_SIZE);
        memset(outdata, 0, AES_BLOCK_SIZE);

        debug("ivec: ");
        prints2h(state.ivec, AES_BLOCK_SIZE);
        debug("num: %d\n", state.num);
        debug("ecount: ");
        prints2h(state.ecount, AES_BLOCK_SIZE);
    }
    debug("Total_bytes_written: %ld\n", total_bytes_written);

    return total_bytes_written;
}
