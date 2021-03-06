/*
 * A web server that serves a blank html page for any request
 *
 * By Daniel Fetchinson <fetchinson@gmail.com> 2007
 * http://code.google.com/p/kwakd/
 *
 * A stripped down version of
 *
 * cheetah
 *
 * Copyright (C) 2003 Luke Reeves (luke@neuro-tech.net)
 * http://www.neuro-tech.net/
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define INFO    0
#define WARNING 1
#define PANIC   2

#define BACKLOG  32
#define CONN_MAX 1024

/* globals */
static int verbose = 0;    /* verbose output to stdout */
static int quiet = 0;      /* suppress any output */
static int sockfd = -1;
static nfds_t nfds = 0;
static struct pollfd fds[CONN_MAX];

static void help(void) {
    printf("Usage: kwakd [OPTIONS]\n\n");
    printf("  Serve a blank html page for any request\n\n");
    printf("  -b, --background     background mode (disables console output, and allows\n");
    printf("                       multiple requests to be served simultaneously)\n");
    printf("  -p, --port           port to listen for requests on, defaults to 8000\n");
    printf("  -u, --user           user ID to switch to\n");
    printf("  -g, --group          group ID to switch to\n");
    printf("  -v, --verbose        verbose output\n");
    printf("  -q, --quiet          suppress any output\n");
    printf("  -V, --version        print version and exit\n");
    printf("  -h, --help           display this message and exit\n");
}

/* prototypes */
static void accept_connection(void);
static int handle_connection(int fd);
static int handle_request(int fd);
static void logmessage(int level, char *message);
static void sigcatch(int signal);
static ssize_t fds_add(int fd);
static void fds_remove_at_index(nfds_t i);

int main(int argc, char *argv[]) {
    uint16_t port = 8000;
    uid_t uid = 0;
    gid_t gid = 0;
    int background = 0; /* go to background */
    struct sigaction sa;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-V") == 0) {
            printf("This is kwakd %s.\n", VERSION);
            exit(0);
        } else if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0)) {
            help();
            exit(0);
        } else if ((strcmp(argv[i], "-p") == 0) || (strcmp(argv[i], "--port") == 0)) {
            port = (uint16_t)atoi(argv[i + 1]);
            i++;
        } else if ((strcmp(argv[i], "-u") == 0) || (strcmp(argv[i], "--user") == 0)) {
            uid = (uid_t)atoi(argv[i + 1]);
            i++;
        } else if ((strcmp(argv[i], "-g") == 0) || (strcmp(argv[i], "--group") == 0)) {
            gid = (gid_t)atoi(argv[i + 1]);
            i++;
        } else if ((strcmp(argv[i], "-v") == 0) || (strcmp(argv[i], "--verbose") == 0)) {
            verbose++;
        } else if ((strcmp(argv[i], "-q") == 0) || (strcmp(argv[i], "--quiet") == 0)) {
            quiet = 1;
        } else if ((strcmp(argv[i], "-b") == 0)
                   || (strcmp(argv[i], "--background") == 0)) {
            background = 1;
        }
    }

    /* fork if necessary */
    if (background) {
        verbose = 0;
        int rv = fork();
        if (rv == -1) {
            logmessage(PANIC, "Error forking.");
        } else if (rv > 0) {
            /* Exit if this is the parent */
            _exit(0);
        }
        if (setsid() == -1) {
            logmessage(PANIC, "Couldn't create SID session.");
        }
        if ((close(0) == -1) || (close(1) == -1) || (close(2) == -1)) {
            logmessage(PANIC, "Couldn't close streams.");
        }
    }

    /* Trap signals */
    memset(&sa, 0, sizeof sa);
    sigfillset(&sa.sa_mask);
    sa.sa_handler = sigcatch;
    if (sigaction(SIGTERM, &sa, NULL) || sigaction(SIGINT, &sa, NULL)) {
        logmessage(PANIC, "Couldn't setup signal traps.");
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        logmessage(PANIC, "Couldn't create socket.");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
        logmessage(PANIC, "Couldn't set SO_REUSEADDR.");
    }

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        logmessage(PANIC, "Couldn't set O_NONBLOCK.");
    }

    struct sockaddr_in my_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof my_addr) == -1) {
        logmessage(PANIC, "Couldn't bind to specified port.");
    }

    if (listen(sockfd, BACKLOG) == -1) {
        logmessage(PANIC, "Couldn't listen on specified port.");
    }

    if (getuid() == 0) {
        if (verbose) {
            printf("Dropping privileges\n");
        }
        if (chdir("/var/empty") != 0) {
            logmessage(PANIC, "Couldn't chdir to empty directory.");
        }
        if (chroot("/var/empty") != 0) {
            logmessage(PANIC, "Couldn't chroot to empty directory.");
        }
        if (setgid(gid) != 0) {
            logmessage(PANIC, "Couldn't drop group privileges.");
        }
        if (setuid(uid) != 0) {
            logmessage(PANIC, "Couldn't drop user privileges.");
        }
    }

    if (verbose) {
        printf("Listening for connections on port %d...\n", port);
    }

    fds_add(sockfd);

    for (;;) {
        if (poll(fds, nfds, -1) == -1) {
            logmessage(PANIC, "Error in poll.");
        }

        if (fds[0].revents & POLLIN) {
            accept_connection();
        }

        for (nfds_t i = 1; i <= nfds; i++) {
            if (fds[i].fd < 0 || !(fds[i].revents & POLLIN)) continue;
            if (handle_connection(fds[i].fd) == 0) {
                fds_remove_at_index(i);

                // Examine fds[i] again. Removal swaps the last item into this slot.
                i -= 1;
            }
        }
    }
}

static void accept_connection(void) {
    struct sockaddr_storage remote_addr;
    socklen_t sin_size = sizeof remote_addr;
    int newfd = accept(sockfd, (struct sockaddr *)&remote_addr, &sin_size);
    if (newfd == -1) {
        logmessage(WARNING, "Couldn't accept connection!");
        return;
    }

    if (fds_add(newfd) < 0) {
        logmessage(WARNING, "Couldn't accept connection! Too many clients.");
        return;
    }

    logmessage(INFO, "Connected, handling requests.");
}

static int handle_connection(int fd) {
    int rv = handle_request(fd);

    if (close(fd) == -1) {
        logmessage(WARNING, "Error closing client socket.");
    }

    return rv;
}

static const char response_format[] = "HTTP/1.0 200 OK\r\n"
                                      "Date: aaa, dd bbb YYYY HH:MM:SS GMT\r\n"
                                      "Expires: aaa, dd bbb YYYY HH:MM:SS GMT\r\n"
                                      "Last-Modified: Fri, 13 Feb 2009 23:31:30 GMT\r\n"
                                      "Cache-Control: public, max-age=31536000\r\n"
                                      "Content-Type: text/html;charset=UTF-8\r\n"
                                      "Content-Length: 0\r\n"
                                      "\r\n";

static const char http_date_weekdays[] = "SunMonTueWedThuFriSat";
static const char http_date_months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";

#define HEADER_DATE_OFFSET 23
#define HEADER_DATE_LENGTH 25
#define HEADER_EXPIRES_OFFSET (HEADER_DATE_OFFSET + HEADER_DATE_LENGTH + 4 + 2 + 9)

#define ONE_YEAR (60 * 60 * 24 * 365)

static void format_int2(char *buf, int n) {
    buf[0] = '0' + (char)(n / 10);
    buf[1] = '0' + (char)(n % 10);
}

static void format_int4(char *buf, int n0) {
    int n1 = n0 / 10;
    int n2 = n1 / 10;
    buf[0] = '0' + (char)(n2 / 10);
    buf[1] = '0' + (char)(n2 % 10);
    buf[2] = '0' + (char)(n1 % 10);
    buf[3] = '0' + (char)(n0 % 10);
}

static int format_http_date(char *buf, time_t t) {
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL) {
        return -errno;
    }

    if (tm.tm_wday < 0 || tm.tm_wday >= 7) {
        return -1;
    }
    if (tm.tm_mon < 0 || tm.tm_mon >= 12) {
        return -1;
    }

    memcpy(buf, http_date_weekdays + 3 * tm.tm_wday, 3);
    format_int2(buf + 5, tm.tm_mday);
    memcpy(buf + 8, http_date_months + 3 * tm.tm_mon, 3);
    format_int4(buf + 12, tm.tm_year + 1900);
    format_int2(buf + 17, tm.tm_hour);
    format_int2(buf + 20, tm.tm_min);
    format_int2(buf + 23, tm.tm_sec);

    return 0;
}

static int format_response(char *message) {
    time_t now_time = time(0);
    if (now_time == (time_t)-1) {
        return -1;
    }

    memcpy(message, response_format, sizeof response_format);

    int rv;
    rv = format_http_date(message + HEADER_DATE_OFFSET, now_time);
    if (rv < 0) {
        return rv;
    }
    rv = format_http_date(message + HEADER_EXPIRES_OFFSET, now_time + ONE_YEAR);

    return rv;
}

// Returns 0 when it want to close the connection, -1 when it wants to read more.
static int handle_request(int fd) {
    ssize_t rv;
    char inbuffer[2048];
    char message[sizeof response_format];

    rv = recv(fd, inbuffer, sizeof(inbuffer), 0);
    if (rv == EAGAIN) {
        return -1;
    }
    if (rv == -1) {
        logmessage(WARNING, "Error receiving request from client.");
        return 0;
    }

    if (format_response(message) < 0) {
        logmessage(WARNING, "Error formatting response.");
        return 0;
    }

    if (send(fd, message, sizeof message - 1, 0) == -1) {
        logmessage(WARNING, "Error sending data to client.");
        return 0;
    }

    return 0;
}

static void logmessage(int level, char *message) {
    switch (level) {
        case INFO:
            if (verbose) {
                printf("[info] %s\n", message);
            }
            break;
        case WARNING:
            if (!quiet) {
                fprintf(stderr, "[warning] %s\n", message);
            }
            break;
        case PANIC:
            if (!quiet) {
                fprintf(stderr, "[panic] %s\n", message);
            }
            exit(1);
            break;
    }
}

static void sigcatch(int s) {
    (void)s;
    if (verbose) {
        printf("Signal caught, exiting.\n");
    }
    if (sockfd != -1) {
        if (close(sockfd) == -1) {
            logmessage(WARNING, "Error closing socket.");
        }
        exit(0);
    }
}

static ssize_t fds_add(int fd) {
    if (nfds == CONN_MAX) {
        return -1;
    }

    nfds_t i = nfds++;
    fds[i].fd = fd;
    fds[i].events = POLLIN;
    return i;
}

static void fds_swap(nfds_t i, nfds_t j) {
    if (i == j) return;
    struct pollfd tmp = fds[i];
    fds[i] = fds[j];
    fds[j] = tmp;
}

static void fds_remove_at_index(nfds_t i) {
    memset(&fds[i], 0, sizeof fds[i]);
    fds[i].fd = -1;
    nfds -= 1;
    fds_swap(i, nfds);
}
