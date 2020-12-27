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
 * - The code is divided into four sections, which are easily findable with
 *   any string searching tool (grep, ctrl+f):
 *   "decls:", "main:", "responses:", "privfuncs:", "pubfuncs:".
 *   Search the text inbetween the quotes to find the section.
 * - The code should compile on any system which supports the POSIX socket API
 *   and has a C89 compiler.
 */

#define _POSIX_C_SOURCE 200112L
const char *RISKYCHAT_HOST = "127.0.0.1";
const short RISKYCHAT_PORT = 8000;
const int RISKYCHAT_VERBOSE = 1;

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
/* ssize_t: */
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
/* Sockets: */
#include <winsock2.h>
#define SHUT_RDWR SD_BOTH
#define close closesocket
#pragma comment(lib, "Ws2_32.lib")
#else
/* Sockets: */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
/* Signals: */
#include <signal.h>
#define SOCKET_ERROR (-1)
#define INVALID_SOCKET (-1)
#endif

/* decls: Declarations used by the rest of the program. */

enum http_method {
    GET, POST /* Just the ones we care about. */
};

enum resource {
    UNKNOWN_RESOURCE, RESOURCE_INDEX, RESOURCE_NEW_POST
};

struct connection_ctx {
    int connect_fd;
    char *buffer;
    size_t buffer_len;
    size_t read_len;
    size_t written_len;
    int stage;
    enum http_method method;
    enum resource requested_resource;
    size_t expected_content_length;
};

int connect_socket(void);
int handle_connection(struct connection_ctx *ctx);
void cleanup_connection(struct connection_ctx *ctx);
#ifndef _WIN32
void handle_terminate(int sig);
#endif
void printf_clear_line(void);


/* main: The main function */

static int SERVER_TERMINATED = 0;
int main(void) {
    int result, socket_fd, connect_fd;
    struct connection_ctx ctx;

#ifndef _WIN32
    struct sigaction sa;
#endif

#ifdef _WIN32
    WSADATA wsaData;

    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
#endif

    /* Creation of the TCP socket we will listen to HTTP connections on. */
    socket_fd = connect_socket();
    if (socket_fd == -1) { return 1; }
    printf("Started the Risky Chat server on http://%s:%d.\n",
           RISKYCHAT_HOST, RISKYCHAT_PORT);

#ifndef _WIN32
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
#endif

    /* The main listening loop. */
    for (;;) {
        connect_fd = accept(socket_fd, NULL, NULL);
        if (SERVER_TERMINATED) break;
        if (connect_fd != INVALID_SOCKET) {
            memset(&ctx, 0, sizeof ctx);
            ctx.connect_fd = connect_fd;
            for (;;) {
                result = handle_connection(&ctx);
                if (result == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("error while handling connection");
                    cleanup_connection(&ctx);
                    break;
                } else if (result == 0) {
                    break;
                }
            }
        }
    }

    /* Resource cleanup. */
    close(socket_fd);
#ifdef _WIN32
    WSACleanup();
#endif
    printf_clear_line();
    printf("\rGood night!\n");

    return EXIT_SUCCESS;
}


/* responses: The static response bodies. */

static char static_response_index[] = "\
<!DOCTYPE html>\r\n\
<html><head><meta charset=\"utf-8\"><title>Risky Chat</title>\
<style>html{\
background-color:#EEEEE8;color:#222;\
}\
chatbox{display:flex;flex-direction:column-reverse;}\
post{\
margin:0;padding:4px;\
border-top:2px solid #DDD;\
}</style>\
</head><body>\
<form method=\"POST\" action=\"/post\"\
 onsubmit=\"submit(); reset(); return false;\">\
<input type=\"text\" id=\"content\" name=\"content\" autofocus>\
<button type=\"submit\">Post</button>\
</form><br>\
<chatbox><post>Example post</post></chatbox></body></html>\r\n";

static char static_response_400[] = "\
400 Bad Request\r\n";

static char static_response_404[] = "\
<!DOCTYPE html>\r\n\
<html><head>\r\n\
<meta charset=\"utf-8\"><title>404 Not Found</title>\r\n\
<style>body { width: 30em; margin: auto; }</style>\r\n\
</head><body>\r\n\
<h2>404 Not Found</h2>\r\n\
</body></html>\r\n";

static char static_post_response_raw[] =  "HTTP/1.1 205 Reset Content\r\n\
Content-Length: 0\r\n\
\r\n";


/* privfuncs: Functions used by the functions used in main(). */

/* Reads from the given file descriptor, until a newline (LF) is encountered.
 * The return value is 0 if a line was read in entirety, -1 if not.
 * This should keep getting called until it returns 0 to get the entire line. */
ssize_t read_line(int fd, char **buffer, size_t *buffer_len, size_t *string_len) {
    ssize_t read_bytes = 0;

    for (;;) {
        if (*string_len >= *buffer_len) {
            *buffer_len += 1024;
            *buffer = realloc(*buffer, *buffer_len);
            if (*buffer == NULL) {
                perror("error when stretching line buffer");
                exit(EXIT_FAILURE);
            }
        }

        read_bytes = recv(fd, &(*buffer)[*string_len], 1, 0);
        if (read_bytes == 0) {
            break;
        } else if (read_bytes == -1) {
            return -1;
        } else {
            *string_len += read_bytes;
            if ((*buffer)[*string_len - 1] == '\n') break;
        }
    }

    /* Add the null terminator. */
    if (*string_len + 1 > *buffer_len) {
        *buffer_len = *string_len + 1;
        *buffer = realloc(*buffer, *buffer_len);
        if (*buffer == NULL) {
            perror("error when stretching line buffer for the NUL");
            exit(EXIT_FAILURE);
        }
    }
    (*buffer)[*string_len] = '\0';

    return 0;
}

static char http_response_head[] = "HTTP/1.1 ";
/* Returns 0 when the entire response has been sent. */
ssize_t write_http_response(int fd, size_t *written_len,
                            char *status, size_t status_len,
                            char *response, size_t response_len) {
    ssize_t result, target_len, section_start;
    char buf[64];
    int buf_len;

    section_start = 0;
    target_len = sizeof http_response_head - 1;
    while (*written_len < target_len) {
        result = send(fd, &http_response_head[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    section_start = target_len;
    target_len += status_len;
    while (*written_len < target_len) {
        result = send(fd, &status[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    buf_len = snprintf(buf, sizeof buf, "\r\nContent-Length: %d\r\n\r\n",
                       response_len);
    section_start = target_len;
    target_len += buf_len;
    while (*written_len < target_len) {
        result = send(fd, &buf[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    section_start = target_len;
    target_len += response_len;
    while (*written_len < target_len) {
        result = send(fd, &response[*written_len - section_start],
                      target_len - *written_len, 0);
        if (result == -1) return -1;
        else *written_len += result;
    }

    return 0;
}


/* pubfuncs: Functions used in main(). */

int connect_socket(void) {
    int fd;
    struct sockaddr_in sa;

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        perror("tcp socket creation failed");
        return -1;
    }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RISKYCHAT_PORT);
    sa.sin_addr.s_addr = inet_addr(RISKYCHAT_HOST);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR) {
        perror("binding to the address failed");
        return -1;
    }

    if (listen(fd, SOMAXCONN) == SOCKET_ERROR) {
        perror("listening to the socket failed");
        return -1;
    }

    return fd;
}

/* Returns 0 when the connection is closed, -1 otherwise.
 * This should keep being called if the return value is -1. */
int handle_connection(struct connection_ctx *ctx) {
    ssize_t result, total_response_len;
    char *token;

    switch (ctx->stage) {
    case 0:
        /* Read the status line. */
        result = read_line(ctx->connect_fd, &ctx->buffer, &ctx->buffer_len,
                           &ctx->read_len);
        if (result == -1) {
            return -1;
        }
        token = strtok(ctx->buffer, " ");
        if (strcmp("GET", token) == 0) {
            ctx->method = GET;
            if (RISKYCHAT_VERBOSE >= 1) printf("GET ");
        } else if (strcmp("POST", token) == 0) {
            ctx->method = POST;
            if (RISKYCHAT_VERBOSE >= 1) printf("POST ");
        } else {
            ctx->stage = 3;
            goto respond_400;
        }
        token = strtok(NULL, " ");
        if (strcmp("/", token) == 0) {
            ctx->requested_resource = RESOURCE_INDEX;
            if (RISKYCHAT_VERBOSE >= 1) printf("/ ");
        } else if (strcmp("/post", token) == 0) {
            ctx->requested_resource = RESOURCE_NEW_POST;
            if (RISKYCHAT_VERBOSE >= 1) printf("/post ");
        }

        /* Reset the line length after processing the statusline. */
        ctx->read_len = 0;
        ctx->stage++;

    case 1:
        /* Read the headers. */
        for (;;) {
            result = read_line(ctx->connect_fd, &ctx->buffer, &ctx->buffer_len,
                               &ctx->read_len);
            if (result == -1) {
                return -1;
            }

            token = strtok(ctx->buffer, ":");
            if (strcmp("Content-Length", token) == 0) {
                token = strtok(NULL, ":");
                ctx->expected_content_length = atoi(token);
                if (RISKYCHAT_VERBOSE >= 1)
                    printf("(%ld) ", ctx->expected_content_length);
            }

            /* The end of the header section is marked by an empty line. */
            if (ctx->read_len == 2 && strcmp("\r\n", ctx->buffer) == 0) {
                ctx->read_len = 0;
                break;
            }

            /* Reset the line length after processing the line. */
            ctx->read_len = 0;
        }
        ctx->stage++;

    case 2:
        /* Read the body, when needed. */
        if (ctx->method == POST && ctx->expected_content_length > 0) {
            if (RISKYCHAT_VERBOSE >= 1) printf("br");
            if (ctx->buffer_len < ctx->expected_content_length + 1) {
                ctx->buffer_len = ctx->expected_content_length + 1;
                ctx->buffer = realloc(ctx->buffer, ctx->buffer_len);
                if (ctx->buffer == NULL) {
                    perror("error when allocating buffer for user response");
                    exit(EXIT_FAILURE);
                }
            }
            ctx->read_len = 0;
            while (ctx->read_len < ctx->expected_content_length) {
                result = recv(ctx->connect_fd, &ctx->buffer[ctx->read_len],
                              ctx->expected_content_length, 0);
                if (result == -1) return -1;
                else ctx->read_len += result;
            }
            ctx->buffer[ctx->expected_content_length] = '\0';
            if (RISKYCHAT_VERBOSE >= 1)
                printf("\b\b(%ld bytes read) ", ctx->expected_content_length);
        }
        ctx->read_len = 0;
        ctx->stage++;

    case 3:
        /* Respond. */
        switch (ctx->requested_resource) {
        case RESOURCE_INDEX:
            if (ctx->method == GET) goto respond_index;
            else break;
        case RESOURCE_NEW_POST:
            if (ctx->method == POST) goto respond_new_post;
            else break;
        default:
            goto respond_404;
        }
        goto respond_400;
    }

respond_new_post:
    total_response_len = sizeof static_post_response_raw - 1;
    while (ctx->written_len < total_response_len) {
        result = send(ctx->connect_fd, static_post_response_raw,
                      total_response_len - ctx->written_len, 0);
        if (result == -1) return -1;
        else ctx->written_len += result;
    }
    if (RISKYCHAT_VERBOSE >= 1) printf("<- post handled\n");
    goto cleanup;

respond_index:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "200 OK", sizeof "200 OK" - 1,
                                 static_response_index,
                                 sizeof static_response_index - 1);
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 1) printf("<- responded with index\n");
    goto cleanup;

respond_400:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "400 Bad Request",
                                 sizeof "400 Bad Request" - 1,
                                 static_response_400,
                                 sizeof static_response_400 - 1);
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 1) printf("<- responded with 400\n");
    goto cleanup;

respond_404:
    result = write_http_response(ctx->connect_fd, &ctx->written_len,
                                 "404 Not Found",
                                 sizeof "404 Not Found" - 1,
                                 static_response_404,
                                 sizeof static_response_404 - 1);
    if (result == -1) return -1;
    if (RISKYCHAT_VERBOSE >= 1) printf("<- responded with 404\n");
    goto cleanup;

cleanup:
    cleanup_connection(ctx);
    return 0;
}

void cleanup_connection(struct connection_ctx *ctx) {
    free(ctx->buffer);
    shutdown(ctx->connect_fd, SHUT_RDWR);
    close(ctx->connect_fd);
}

#ifndef _WIN32
void handle_terminate(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        SERVER_TERMINATED = 1;
    }
}
#endif

void printf_clear_line(void) {
    /* See "Clear entire line" here (it's a VT100 escape code):
     * https://espterm.github.io/docs/VT100%20escape%20codes.html */
    printf("%c[2K", 27);
}
