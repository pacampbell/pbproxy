#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
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

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, AES_BLOCK_SIZE);
}

ssize_t write_encrypted(int writefd, EncryptionKey *key, CounterState *state,
                        unsigned char *buffer, size_t size) {
    ssize_t bytes_written = 0;
    unsigned char *outbuff = malloc(size);

    // Zero out memory in use
    // memset(outbuff, 0, size);

    // Encrypt the data
    // info("Encrypt: size: %ld, outsize: %ld\n", size, outsize);
    debug("Encrypt IV: ");
    prints2h(state->ivec, AES_BLOCK_SIZE);
    debug("ecount: ");
    prints2h(state->ecount, AES_BLOCK_SIZE);
    debug("num: %u\n", state->num);
    AES_ctr128_encrypt(buffer, outbuff, size, &(key->aeskey), state->ivec,
                       state->ecount, &(state->num));
    // memcpy(outbuff, buffer, size);

    // Write the buffer to the socket
    if ((bytes_written = write(writefd, outbuff, size)) != size) {
        // TODO: Something bad happened
        // perror("");
        goto cleanup;
    }

    // debug("Encrypt: Total_bytes_written: %ld\n\n", bytes_written);
cleanup:
    free(outbuff);
    return bytes_written;
}

ssize_t write_decrypted(int writefd, EncryptionKey *key, CounterState *state,
                        unsigned char *buffer, size_t size) {
    ssize_t bytes_written = 0;
    unsigned char *outbuff = malloc(size);

    // Zero out buffers
    // memset(outbuff, 0, size);

    // Decrypt the contents of the buffer
    // info("Decrypt: size: %ld, outsize: %ld\n", size - AES_BLOCK_SIZE, outsize);
    debug("Decrypt IV: ");
    prints2h(state->ivec, AES_BLOCK_SIZE);
    debug("ecount: ");
    prints2h(state->ecount, AES_BLOCK_SIZE);
    debug("num: %u\n", state->num);
    AES_ctr128_encrypt(buffer, outbuff, size, &(key->aeskey), state->ivec,
                       state->ecount, &(state->num));
    // memcpy(outbuff, buffer, size);
    // Write the buffer to the socket
    if ((bytes_written = write(writefd, outbuff, size)) != size) {
        error("bytes_witten: %ld, outsize: %ld\n", bytes_written, size);
        // TODO: Something bad happened
        // perror("");
        goto cleanup;
    }

    // debug("Decrypt: Total_bytes_written: %ld\n\n", bytes_written);
cleanup:
    free(outbuff);
    return bytes_written;
}
