/* Shared by the libFuzzer harnesses of this directory (fuzz/README.md). */
#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "../src/utils.h"
#include "../src/protocol.h"

#define FUZZ_MAX_INPUT 4096

/* Where protocol_parse() answers: one end of a socketpair, the other end drained after each input so the
   answer of one input never blocks the next. Returns the sender id to put in msg_t. */
static int fuzz_peer_fd = -1;
static int fuzz_sender_fd = -1;

static void fuzz_peer_open(void)
{
    int fd[2];
    /* not a property: the harness could not open its own socketpair */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0)
        abort();
    fuzz_sender_fd = fd[0];
    fuzz_peer_fd = fd[1];
    fcntl(fuzz_peer_fd, F_SETFL, O_NONBLOCK);
    fcntl(fuzz_sender_fd, F_SETFL, O_NONBLOCK);
}

static void fuzz_peer_drain(void)
{
    char buf[4096];
    while (read(fuzz_peer_fd, buf, sizeof(buf)) > 0)
        ;
}

/* The input as the NUL-terminated message the socket layer hands the parser (it cuts at the first NUL). */
static char *fuzz_message(const uint8_t *data, size_t size)
{
    char *copy = malloc(size + 1);
    /* not a property: the harness's own allocation failed */
    if (!copy)
        abort();
    memcpy(copy, data, size);
    copy[size] = '\0';
    return copy;
}

#endif
