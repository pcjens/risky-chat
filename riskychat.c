/* A security risk disguised as a chat room web application.
 * Copyright (C) 2020  Jens Pitkanen <jens.pitkanen@helsinki.fi>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* A few quick notes about reading this source code:
 * - The code is divided into four sections, which are easily findable with any string searching tool (grep, ctrl+f):
 * - "decls:", "main:", "privfuncs:", "pubfuncs:". Search the text inbetween the quotes to find the section.
 * - The code should compile on any system which supports the the POSIX socket API and has a C89 compiler.
 */

#define _POSIX_C_SOURCE 200112L
#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* decls: Declarations used by the rest of the program. */

enum riskychat_error {
    NO_ERROR, SOCKET_CREATION, SOCKET_BINDING, SOCKET_LISTENING
};

void print_err(enum riskychat_error err);
void connect_socket(enum riskychat_error *err, int *socket_fd);
void handle_connection(int connect_fd);
void handle_terminate(int sig);
void printf_clear_line(void);


/* main: The main function */

static int SERVER_TERMINATED = 0;
int main(void) {
    enum riskychat_error err;
    int socket_fd, connect_fd;
    struct sigaction sa;

    /* Creation of the TCP socket we will listen to HTTP connections on. */
    printf("Starting the Risky Chat server on %s:%d...\r",
           RISKYCHAT_HOST, RISKYCHAT_PORT);
    connect_socket(&err, &socket_fd);
    if (err != NO_ERROR) { print_err(err); return 1; }
    printf_clear_line();
    printf("Started the Risky Chat server on %s:%d.\n",
           RISKYCHAT_HOST, RISKYCHAT_PORT);

    /* Setup interrupt handler. */
    sa.sa_handler = handle_terminate;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("could not set up a handler for SIGINT");
    } else {
        printf(" (Interrupt with ctrl+c to close.)\n");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("could not set up a handle for SIGTERM");
    }

    /* The main listening loop. */
    for (;;) {
        connect_fd = accept(socket_fd, NULL, NULL);
        if (SERVER_TERMINATED) break;
        if (connect_fd == -1) {
            perror("could not accept on the socket");
            break;
        }
        handle_connection(connect_fd);
    }

    /* Resource cleanup. */
    close(socket_fd);
    printf_clear_line();
    printf("\rClosed the socket on %s:%d. Good night!\n", RISKYCHAT_HOST, RISKYCHAT_PORT);

    return EXIT_SUCCESS;
}


/* privfuncs: Functions used by the functions used in main(). */

ssize_t read_line(int fd, char **buffer, ssize_t *buffer_len) {
    ssize_t read_bytes = 0;
    ssize_t string_len = 0;

    for (;;) {
        if (string_len >= *buffer_len) {
            *buffer_len += 1;
            *buffer = realloc(*buffer, *buffer_len);
            if (*buffer == NULL) {
                perror("error when stretching line buffer");
                exit(EXIT_FAILURE);
            }
        }

        read_bytes = read(fd, &(*buffer)[string_len], 1);
        if (read_bytes == 0) {
            break;
        } else if (read_bytes == -1) {
            perror("error while reading from the socket");
            break;
        } else {
            string_len += read_bytes;
            if ((*buffer)[string_len - 1] == '\n') break;
        }
    }

    return string_len;
}


/* pubfuncs: Functions used in main(). */

void print_err(enum riskychat_error err) {
    switch (err) {
    case SOCKET_CREATION:
        perror("tcp socket creation failed");
        break;
    case SOCKET_BINDING:
        perror("binding to the address failed");
        break;
    case SOCKET_LISTENING:
        perror("listening to the socket failed");
        break;
    case NO_ERROR:
    default:
        break;
    }
}

void connect_socket(enum riskychat_error *err, int *socket_fd) {
    int fd;
    struct sockaddr_in sa;

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) { *err = SOCKET_CREATION; return; }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RISKYCHAT_PORT);
    sa.sin_addr.s_addr = inet_addr(RISKYCHAT_HOST);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == -1) {
        *err = SOCKET_BINDING;
        return;
    }

    if (listen(fd, SOMAXCONN) == -1) { *err = SOCKET_LISTENING; return; }

    *err = NO_ERROR;
    *socket_fd = fd;
}

void handle_connection(int connect_fd) {
    int line_length;
    char *buffer = NULL;
    ssize_t buffer_len = 0;

    for (;;) {
        line_length = read_line(connect_fd, &buffer, &buffer_len);
        if (line_length == 0) {
            goto cleanup;
        }
        buffer[line_length] = '\0';

        /* TODO: Read the request and set any state needed with them. */
        /* TODO: Respond with the frontend to GET /. */
        /* TODO: Handle API calls. */

        if (line_length == 2 && strcmp("\r\n", buffer) == 0) {
            /* This is a temporary debugging response: just a 200 OK with "Hello, World!" in the body. */
            const char *res = "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nHello, World!\n";
            size_t res_len = strlen(res);
            ssize_t written_len = write(connect_fd, res, res_len);
            if (written_len == -1) {
                perror("error when writing response");
            }
            break;
        }
    }

cleanup:
    free(buffer);
    shutdown(connect_fd, SHUT_RDWR);
    close(connect_fd);
}

void handle_terminate(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        SERVER_TERMINATED = 1;
    }
}

void printf_clear_line(void) {
    /* See "Clear entire line" here (it's a VT100 escape code):
     * https://espterm.github.io/docs/VT100%20escape%20codes.html */
    printf("%c[2K", 27);
}
