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

#include "pbproxy.h"
#include "encrypt.h"
#include "debug.h"

static int setupserver(int proxyport);
static int connectdest(struct sockaddr_in dest);
static void proxy(int destfd, int proxyclient, EncryptionKey *key);
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
                // TODO: PRINT HELP MENU
                return EXIT_SUCCESS;
            default: /* ? */
                // TODO: PRINT HELP MENU
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

    debug("Proxy Port: %u, destination: %s, port: %u\n", proxy_port, desthostname, port);

    if (servermode) {
        pbserver(dest, proxy_port, &key);
    } else {
        pbclient(dest, &key);
    }
    return EXIT_SUCCESS;
}

static void pbclient(struct sockaddr_in dest, EncryptionKey *key) {
    int destfd = connectdest(dest);
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    // Start being a middle man
    bool connected = true;
    fd_set rset;
    // char buffer[BUFFER_SIZE];
    // Start relaying traffic
    while (connected) {
        FD_ZERO(&rset);
        FD_SET(STDIN_FILENO, &rset);
        FD_SET(destfd, &rset);

        // Figure out the larger fd
        int max = destfd > STDIN_FILENO ? destfd + 1 : STDIN_FILENO + 1;

        // Begin waiting for something to happen
        select(max, &rset, NULL, NULL, NULL);

        // Handle local socket/fd
        if (FD_ISSET(STDIN_FILENO, &rset)) {
            warn("Reading stdin\n");
            bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
            // Encrypt and write data to destination
            if (write_encrypted(destfd, key, buffer, bytes_read) <= 0) {
                // TODO: handle error
                // EINTER
                // EPIPE
                connected = false;
                goto close_connections;
            }
        }

        // Handle destination socket
        if (FD_ISSET(destfd, &rset)) {
            warn("Reading dest\n");
            bytes_read = read(destfd, buffer, BUFFER_SIZE);
            warn("Bytes_read: %ld\n", bytes_read);
            // Encrypt and write data to destination
            if (write_decrypted(STDOUT_FILENO, key, buffer, bytes_read) <= 0) {
                // TODO: handle error
                // EINTER
                // EPIPE
                connected = false;
                goto close_connections;
            }
        }
    }
close_connections:
    debug("Cleaning up fd's\n");
    close(destfd);
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
            perror("");
            continue;
        }

        debug("Accepted a new connection: %d\n", proxyclientfd);

        // Now that we have a client, open a connection to the destination
        int destfd = connectdest(dest);
        debug("Connected to destination: %d\n", destfd);

        // Start being a middle man
        proxy(destfd, proxyclientfd, key);
    }
}

static void proxy(int destfd, int proxyclient, EncryptionKey *key) {
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    bool connected = true;
    fd_set rset;
    // Start relaying traffic
    while (connected) {
        FD_ZERO(&rset);
        FD_SET(destfd, &rset);
        FD_SET(proxyclient, &rset);

        // Figure out the larger fd
        int max = destfd > proxyclient ? destfd + 1 : proxyclient + 1;

        // Begin waiting for something to happen
        select(max, &rset, NULL, NULL, NULL);

        // Handle the destination writing to me
        if (FD_ISSET(destfd, &rset)) {
            bytes_read = read(destfd, buffer, BUFFER_SIZE);
            // Encrypt and write data to destination
            if (write_encrypted(proxyclient, key, buffer, bytes_read) <= 0) {
                // TODO: handle error
                // EINTER
                // EPIPE
                connected = false;
                goto close_connections;
            }
        }

        // Handle The proxy writing to me
        if (FD_ISSET(proxyclient, &rset)) {
            bytes_read = read(proxyclient, buffer, BUFFER_SIZE);
            // Encrypt and write data to destination
            if (write_decrypted(destfd, key, buffer, bytes_read) <= 0) {
                // TODO: handle error
                // EINTER
                // EPIPE
                connected = false;
                goto close_connections;
            }
        }
    }
close_connections:
        debug("Cleaning up fd's\n");
        close(proxyclient);
        close(destfd);
}

static int setupserver(int proxyport) {
    struct sockaddr_in server;
    int server_sock;

    if ((server_sock = socket(AF_INET , SOCK_STREAM , 0)) < 0) {
        perror("Failed to open socket");
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
        perror("Failed to bind on port.");
        return -1;
    }

    // Finally start listening for connections
    listen(server_sock, 3); // Start trashing incomming connections after 3

    return server_sock;
}

static int connectdest(struct sockaddr_in dest) {
    int destfd;
    if ((destfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("");
        error("Unable to create a socket\n");
        return -1;
    }

    if (connect(destfd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
       perror("");
       error("Failed to connect\n");
       return -1;
    }

    return destfd;
}
