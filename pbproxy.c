#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

#include "pbproxy.h"
#include "encrypt.h"
#include "debug.h"

static int setupserver(int proxyport);
static int connectdest(struct sockaddr_in dest);
static void proxy(int infd, int dstfd, EncryptionKey *key, CounterState *instate, CounterState *outstate);
static void pbclient(struct sockaddr_in dest, EncryptionKey *key);
static void pbserver(struct sockaddr_in dest, int proxyport, EncryptionKey *key);

int main(int argc, char *argv[]) {
    // int server_sock;
    int opt, port = 0, proxy_port;
    bool servermode = false;
    char *keyfile_path = NULL, *desthostname = NULL, *error = NULL;
    struct sockaddr_in dest;
    EncryptionKey key;

    while((opt = getopt(argc, argv, "hl:k:")) != -1) {
        switch(opt) {
            case 'l':
                proxy_port = (unsigned short) strtoul(optarg, &error, 10);
                if (*error != '\0') {
                    error("Invalid proxy port number '%s' supplied\n", optarg);
                    return EXIT_FAILURE;
                }
                servermode = true;
                break;
            case 'k':
                keyfile_path = optarg;
                break;
            case 'h':
                HELP();
                return EXIT_SUCCESS;
            default: /* ? */
                HELP();
                return EXIT_FAILURE;
        }
    }

    // Make sure we have a keyfile
    if (keyfile_path == NULL) {
        error("Please provide a path to the keyfile.\n");
        return EXIT_FAILURE;
    } else {
        int keyfd;
        // See if the keyfile actually exists
        struct stat st;
        memset(&st, 0, sizeof(struct stat));
        if (stat(keyfile_path, &st) < 0) {
            error("Keyfile %s does not exist\n", keyfile_path);
            return EXIT_FAILURE;
        }
        // Make room to read in the keyfile
        key.value = malloc(st.st_size);
        key.size = st.st_size;
        // Open the keyfile
        if ((keyfd = open(keyfile_path, 0)) < 0) {
            error("Failed to open the %s. Perhapps permissions?\n", keyfile_path);
            return EXIT_FAILURE;
        }
        // Read in the contents
        if (read(keyfd, key.value, key.size) != key.size) {
            error("An error occurred while trying to read the key file.\n");
            return EXIT_FAILURE;
        }

        // Now close the open fd
        if (keyfd != STDIN_FILENO)
            close(keyfd);

        // Create the AES encryption key
        if (AES_set_encrypt_key(key.value, 128, &(key.aeskey)) < 0) {
            fprintf(stderr, "Could not set encryption key.\n");
        }
    }

    // Make sure a destination and port is provided
    if (optind < argc && (argc - optind) == 2) {
        // Get the destination hostname
        // TODO: error check the hostname
        desthostname = argv[optind];
        // Get the destination port number
        error = NULL;
        port = (unsigned short) strtoul(argv[optind + 1], &error, 10);
        if (*error != '\0') {
            error("Invalid port number '%s' supplied\n", argv[optind + 1]);
            return EXIT_FAILURE;
        }
    } else {
        error("Incorrect positional arguments provided.\n");
        error("Expected 2 but found %d positional arguments.\n", argc - optind);
        return EXIT_FAILURE;
    }

    // Now setup params to connect with the destination
    dest.sin_addr.s_addr = inet_addr(desthostname);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);

    if (servermode) {
        pbserver(dest, proxy_port, &key);
    } else {
        pbclient(dest, &key);
    }
    return EXIT_SUCCESS;
}

static void pbclient(struct sockaddr_in dest, EncryptionKey *key) {
    int destfd = connectdest(dest);

    CounterState clientstate, serverstate;
    unsigned char clientiv[AES_BLOCK_SIZE];
    unsigned char serveriv[AES_BLOCK_SIZE];

    // Generate an IV for the client
    memset(clientiv, 0, AES_BLOCK_SIZE);
    memset(serveriv, 0, AES_BLOCK_SIZE);
    memset(&clientstate, 0, sizeof(CounterState));
    memset(&serverstate, 0, sizeof(CounterState));

    if(!RAND_bytes(clientiv, AES_BLOCK_SIZE)) {
       error("Could not create random bytes for iv.\n");
       return;
    }

    // Make the last 8 bytes of the IV 0
    memset(clientiv + 8, 0, 8);

    // Send the IV to the server
    write(destfd, clientiv, AES_BLOCK_SIZE);
    // Wait for the server IV
    read(destfd, serveriv, AES_BLOCK_SIZE);

    // debug("Client IV: ");
    // prints2h(clientiv, AES_BLOCK_SIZE);
    // debug("Server IV: ");
    // prints2h(serveriv, AES_BLOCK_SIZE);

    // Initialize both states
    init_counter(&clientstate, clientiv);
    init_counter(&serverstate, serveriv);

    // Start the proxy
    proxy(STDIN_FILENO, destfd, key, &clientstate, &serverstate);
}

static void pbserver(struct sockaddr_in dest, int proxyport, EncryptionKey *key) {
    struct sockaddr_in client;
    int proxyfd = setupserver(proxyport);
    int proxyclientfd, addrlen = 0;
    bool running = true;

    // Begin listening for connections
    while(running) {
        // Wait for a connection
        if ((proxyclientfd = accept(proxyfd, (struct sockaddr*)&client, (socklen_t*)&addrlen)) < 0) {
            error("Failed to create a connection with the client\n");
            // perror("");
            continue;
        }
        // debug("Accepted a new connection: %d\n", proxyclientfd);

        // Create memory to store IV
        CounterState clientstate, serverstate;
        unsigned char clientiv[AES_BLOCK_SIZE];
        unsigned char serveriv[AES_BLOCK_SIZE];


        // Generate an IV for the server and read clients
        memset(clientiv, 0, AES_BLOCK_SIZE);
        memset(serveriv, 0, AES_BLOCK_SIZE);
        memset(&clientstate, 0, sizeof(CounterState));
        memset(&serverstate, 0, sizeof(CounterState));

        if(!RAND_bytes(serveriv, AES_BLOCK_SIZE)) {
           error("Could not create random bytes for iv.\n");
           return;
        }
        // Make the last 8 bytes of the IV 0
        memset(serveriv + 8, 0, 8);

        write(proxyclientfd, serveriv, AES_BLOCK_SIZE);

        // Look for the IV packet
        // debug("Waiting to receive the iv...\n");
        read(proxyclientfd, clientiv, AES_BLOCK_SIZE);
        // debug("Received the iv...\n");

        // Now that we have a client, open a connection to the destination
        int destfd = connectdest(dest);
        // debug("Connected to destination: %d\n", destfd);

        // Initialize both states
        // debug("Client IV: ");
        prints2h(clientiv, AES_BLOCK_SIZE);
        // debug("Server IV: ");
        prints2h(serveriv, AES_BLOCK_SIZE);

        init_counter(&clientstate, clientiv);
        init_counter(&serverstate, serveriv);

        // Start being a middle man
        proxy(destfd, proxyclientfd, key, &serverstate, &clientstate);
    }
}

static void proxy(int infd, int dstfd, EncryptionKey *key,
                  CounterState *instate, CounterState *outstate) {
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;
    bool connected = true;
    fd_set rset;
    // Start relaying traffic
    while (connected) {
        FD_ZERO(&rset);
        FD_SET(infd, &rset);
        FD_SET(dstfd, &rset);

        // Figure out the larger fd
        int max = infd > dstfd ? infd + 1 : dstfd + 1;

        // Begin waiting for something to happen
        if (select(max, &rset, NULL, NULL, NULL) < 0) {
            error("select failed\n");
            // perror("");
            connected = false;
            goto close_connections;
        }

        // Handle the encrypted fd being written to
        if (FD_ISSET(infd, &rset)) {
            if ((bytes_read = read(infd, buffer, BUFFER_SIZE)) < 1) {
                // debug("Bytes_read: %ld\n", bytes_read);
                if (bytes_read < 0) {
                    // perror("Error: ");
                    connected = false;
                    goto close_connections;
                } else {
                    connected = false;
                    goto close_connections;
                }
            }
            // Encrypt and write data to destination
            if ((bytes_written = write_encrypted(dstfd, key, instate, buffer, bytes_read)) <= 0) {
                // TODO: handle error
                // EINTER
                // EPIPE
                // perror("");
                error("Write decrypted failed: %ld\n", bytes_written);
                connected = false;
                goto close_connections;
            }
        }

        // Handle The proxy writing to me
        if (FD_ISSET(dstfd, &rset)) {
            if ((bytes_read = read(dstfd, buffer, BUFFER_SIZE)) < 1) {
                // debug("Bytes_read: %ld\n", bytes_read);
                // perror("");
                connected = false;
                goto close_connections;
            }
            int tfd = (infd == STDIN_FILENO) ? STDOUT_FILENO : infd;
            // Encrypt and write data to destination
            if ((bytes_written = write_decrypted(tfd, key, outstate, buffer, bytes_read)) <= 0) {
                // TODO: handle error
                // EINTER
                // EPIPE
                // perror("");
                error("Write decrypted failed: %ld\n", bytes_written);
                connected = false;
                goto close_connections;
            }
        }
    }
close_connections:
        info("Cleaning up fd's\n");
        if (infd != STDIN_FILENO)
            close(infd);
        close(dstfd);
}

static int setupserver(int proxyport) {
    struct sockaddr_in server;
    int server_sock;

    if ((server_sock = socket(AF_INET , SOCK_STREAM , 0)) < 0) {
        // perror("Failed to open socket");
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(proxyport);

    // Set address reuse
    int optval = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    // Create the server socket
    if(bind(server_sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        // perror("Failed to bind on port.");
        return -1;
    }

    // Finally start listening for connections
    listen(server_sock, 127);

    return server_sock;
}

static int connectdest(struct sockaddr_in dest) {
    int destfd;
    if ((destfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        // perror("");
        error("Unable to create a socket\n");
        return -1;
    }

    if (connect(destfd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
       // perror("");
       error("Failed to connect\n");
       return -1;
    }

    return destfd;
}
