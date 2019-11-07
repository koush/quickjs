#include "quickjs-debugger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <poll.h>

struct js_transport_data {
    int handle;
} js_transport_data;

static size_t js_transport_read(void *udata, char *buffer, size_t length) {
    struct js_transport_data* data = (struct js_transport_data *)udata;
    if (data->handle <= 0)
        return -1;

    if (length == 0)
        return -2;

    if (buffer == NULL)
        return -3;

    ssize_t ret = read(data->handle, (void *)buffer, length);
    if (ret < 0)
        return -4;

    if (ret == 0)
        return -5;

    if (ret > length)
        return -6;

    return ret;
}

static size_t js_transport_write(void *udata, const char *buffer, size_t length) {
    struct js_transport_data* data = (struct js_transport_data *)udata;
    if (data->handle <= 0)
        return -1;

    if (length == 0)
        return -2;

    if (buffer == NULL)
        return -3;

    size_t ret = write(data->handle, (const void *) buffer, length);
    if (ret <= 0 || ret > (ssize_t) length)
        return -4;

    return ret;
}

static size_t js_transport_peek(void *udata) {
    struct pollfd fds[1];
    int poll_rc;

    struct js_transport_data* data = (struct js_transport_data *)udata;
    if (data->handle <= 0)
        return -1;

    fds[0].fd = data->handle;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    poll_rc = poll(fds, 1, 0);
    if (poll_rc < 0)
        return -2;
    if (poll_rc > 1)
        return -3;
    // no data
    if (poll_rc == 0)
        return 0;
    // has data
    return 1;
}

static void js_transport_close(JSContext* ctx, void *udata) {
    struct js_transport_data* data = (struct js_transport_data *)udata;
    if (data->handle <= 0)
        return;
    close(data->handle);
    data->handle = 0;
}

void js_debugger_connect(JSContext *ctx, char *address) {
    char* port_string = strstr(address, ":");
    assert(port_string);

    int port = atoi(port_string + 1);
    assert(port);

    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client > 0);
    char host_string[256];
    strcpy(host_string, address);
    host_string[port_string - address] = 0;

    struct hostent *host = gethostbyname(host_string);
    assert(host);
    struct sockaddr_in addr;

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    bcopy((char *)host->h_addr, (char *)&addr.sin_addr.s_addr, host->h_length);
    addr.sin_port = htons(port);

    assert(!connect(client, (const struct sockaddr *)&addr, sizeof(addr)));

    struct js_transport_data *data = (struct js_transport_data *)malloc(sizeof(struct js_transport_data));
    data->handle = client;
    js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}
