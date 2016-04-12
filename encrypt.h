#ifndef ENCRYPT_H
#define ENCRYPT_H
#include <sys/types.h>
#include <openssl/aes.h>

// Tutorial @ http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/

struct counter_state {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};
typedef struct counter_state CounterState;

struct encryption_key {
    unsigned char *value;
    size_t size;
    AES_KEY aeskey;
};
typedef struct encryption_key EncryptionKey;

void prints2h(const unsigned char *value, size_t size);

void init_counter(CounterState *state, const unsigned char iv[16]);

ssize_t write_encrypted(int writefd, EncryptionKey *key, CounterState state,
                        unsigned char *buffer, size_t size);
ssize_t write_decrypted(int writefd, EncryptionKey *key, CounterState state,
                        unsigned char *buffer, size_t size);
#endif
