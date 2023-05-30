#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/workqueue.h>
#include <net/sock.h>


struct http_server_param {
    struct socket *listen_socket;
};

struct http_service {
    bool is_stopped;
    struct list_head worker;
};

struct khttpd {
    struct socket *sock;
    struct list_head list;
    struct work_struct khttpd_work;
};

extern struct workqueue_struct *khttpd_wq;
extern int http_server_daemon(void *arg);
#endif
