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

/* globals */
static int verbose = 0;    /* verbose output to stdout */
static int quiet = 0;      /* suppress any output */
static int background = 0; /* go to background */
static int sockfd = -1;

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
static void handle_connection(int fd);
static void handle_request(int fd);
static void logmessage(int level, char *message);
static void sigcatch(int signal);

int main(int argc, char *argv[]) {
    uint16_t port = 8000;
    uid_t uid = 0;
    gid_t gid = 0;
    struct sigaction sa;
    struct sockaddr_in my_addr;
    struct sockaddr_in remote_addr;
    socklen_t sin_size;
    int newfd;
    int i, fr, rv;

    /* Parse options */
    for (i = 1; i < argc; i++) {
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
        rv = fork();
        if (rv == -1) {
            logmessage(PANIC, "Error forking.");
        } else if (rv > 0) {
            /* Exit if this is the parent */
            _exit(0);
        }
        if (setsid() == -1) {
            logmessage(PANIC, "Couldn't create SID session.");
        }
        memset(&sa, 0, sizeof sa);
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL)) {
            logmessage(PANIC, "Couldn't initialize signal handlers.");
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

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(my_addr.sin_zero), 8);

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        logmessage(PANIC, "Couldn't bind to specified port.");
    }

    sin_size = sizeof(struct sockaddr_in);

    if (listen(sockfd, 25) == -1) {
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

    while (1) {
        newfd = accept(sockfd, (struct sockaddr *)&remote_addr, &sin_size);
        if (newfd == -1) {
            logmessage(PANIC, "Couldn't accept connection!");
        }

        logmessage(INFO, "Connected, handling requests.");

        if (background) {
            fr = fork();
            if (fr != 0) {
                continue;
            }
            handle_connection(newfd);
            _exit(0);
        }
        handle_connection(newfd);
    }
}

static void handle_connection(int fd) {
    handle_request(fd);

    if (close(fd) == -1) {
        logmessage(WARNING, "Error closing client socket.");
    }
}

static const char response_format[] = "HTTP/1.0 200 OK\r\n"
                                      "Date: aaa, dd bbb YYYY HH:MM:SS GMT\r\n"
                                      "Expires: aaa, dd bbb YYYY HH:MM:SS GMT\r\n"
                                      "Last-Modified: Fri, 13 Feb 2009 23:31:30 GMT\r\n"
                                      "Cache-Control: public, max-age=31536000\r\n"
                                      "Content-Type: text/html;charset=UTF-8\r\n"
                                      "Content-Length: 0\r\n"
                                      "\r\n";

static const char http_date_format[] = "%a, %d %b %Y %H:%M:%S";

#define HEADER_DATE_OFFSET 23
#define HEADER_DATE_LENGTH 25
#define HEADER_EXPIRES_OFFSET (HEADER_DATE_OFFSET + HEADER_DATE_LENGTH + 4 + 2 + 9)

#define ONE_YEAR (60 * 60 * 24 * 356)

static int format_http_date(char *buf, time_t t) {
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL) {
        return -errno;
    }

    if (strftime(buf, HEADER_DATE_LENGTH + 1, http_date_format, &tm) == 0) {
        return -1;
    }
    buf[HEADER_DATE_LENGTH] = ' '; // Restore space clobbered by trailing null

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

static void handle_request(int fd) {
    ssize_t rv;
    char inbuffer[2048];
    char message[sizeof response_format];

    rv = recv(fd, inbuffer, sizeof(inbuffer), 0);
    if (rv == -1) {
        logmessage(WARNING, "Error receiving request from client.");
        return;
    }

    if (format_response(message) < 0) {
        logmessage(WARNING, "Error formatting response.");
        return;
    }

    if (send(fd, message, sizeof message - 1, 0) == -1) {
        logmessage(WARNING, "Error sending data to client.");
        return;
    }
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

static void sigcatch(int signal) {
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
