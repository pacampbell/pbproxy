#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pbproxy.h"
#include "debug.h"

static int setupserver(int proxyport);
static int connectdest(struct sockaddr_in dest);
static void proxy(int destfd, int inputfd);
// static void forwardtraffic(int infd, int outfd, bool servermode, struct sockaddr_in server);
static void pbclient(struct sockaddr_in dest);
static void pbserver(struct sockaddr_in destination, int proxyport);

int main(int argc, char *argv[]) {
    // int server_sock;
    int opt, port = 0, proxy_port;
    bool servermode = false;
    char *keyfile_path = NULL, *desthostname = NULL, *error = NULL;
    struct sockaddr_in dest;

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
        pbserver(dest, proxy_port);
    } else {
        pbclient(dest);
    }
    return EXIT_SUCCESS;
}

static void pbclient(struct sockaddr_in dest) {
    int destfd = connectdest(dest);
    // Start being a middle man
    proxy(destfd, STDIN_FILENO);
}

static void pbserver(struct sockaddr_in dest, int proxyport) {
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
        proxy(destfd, proxyclientfd);
    }
}

static void proxy(int destfd, int inputfd) {
    int bytesread = 0, bytesent = 0;
    bool serving = true;
    fd_set rset;
    char buffer[BUFFER_SIZE];
    // Start relaying traffic
    while (serving) {
        FD_ZERO(&rset);
        FD_SET(inputfd, &rset);
        FD_SET(destfd, &rset);

        // Figure out the larger fd
        int max = inputfd > destfd ? inputfd + 1 : destfd + 1;

        // Begin waiting for something to happen
        select(max, &rset, NULL, NULL, NULL);

        // Handle proxy server socket
        if (FD_ISSET(inputfd, &rset)) {
            if ((bytesread = recv(inputfd, buffer, BUFFER_SIZE, 0)) == 0) {
                // Connection closed
                goto close_connections;
            }

            // Forward data to the destination
            if ((bytesent = send(destfd, buffer, bytesread, 0)) != bytesread) {
                // TODO: handle error
                // EINTER
                // EPIPE
            }
        }

        // Handle destination socket
        if (FD_ISSET(destfd, &rset)) {
            int writeto = (inputfd == STDIN_FILENO) ? STDOUT_FILENO : inputfd;
            if ((bytesread = recv(destfd, buffer, BUFFER_SIZE, 0)) == 0) {
                // Connection closed
                goto close_connections;
            }

            if ((bytesent = send(writeto, buffer, bytesread, 0)) != bytesread) {
                // TODO: Handle error
                // EINTER
                // EPIPE
            }
        }
    }
close_connections:
        debug("Cleaning up fd's\n");
        if (inputfd != STDIN_FILENO)
            close(inputfd);
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
