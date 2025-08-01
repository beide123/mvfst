#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ev.h>
#include <time.h>
#include <errno.h>
#include <shm_sock.h>

#define NORMAL_SIZE 1024
#define BUF_SIZE 1024 * 64  // 64 KB 缓冲区大小
#define MAX_CLIENTS 100     // 最大客户端数量

typedef struct {
    char server_ip[16];
    int port;
    int packet_length;
    int test_duration;
    int conn_num;
} config_t;

struct client_watcher {
    struct ev_io io_watcher_read;
    struct ev_io io_watcher_write;
    struct ev_timer timer_watcher;
    int client_idx;     // Index for conn_fds, pipe arrays, etc.
    int shm_conn_fd;    // The shm_accept-ed fd for this client
    int usd_fd;         // The usd_socket for this client
    int request_count;  // To track requests from this client
    int response_count; // To track responses from this client
    size_t request_bytes;
    size_t response_bytes;
    ssize_t *read_ptr;
    ssize_t *write_ptr;
    config_t *config;
};

size_t response_count; // To track responses for this connection
size_t request_count; // To track requests for this connection
size_t response_bytes;
size_t request_bytes;

size_t last_total_requests = 0;
size_t last_total_responses = 0;
size_t last_total_rspbytes = 0;
size_t last_total_reqbytes = 0;

void handle_error(const char *message) {
    fprintf(stderr, "%s\n", message);
    cleanup_shared_memory(1);
    exit(EXIT_FAILURE);
}

void handle_write(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct client_watcher *watcher = (struct client_watcher *)w->data;
    if (revents & EV_ERROR) {
        handle_error("EV_ERROR in handle_write");
        return;
    }
    char response[256];
    snprintf(response, sizeof(response), "Response %d from Connection %d", watcher->request_count, watcher->client_idx);
    ssize_t ret = shm_write(watcher->shm_conn_fd, response, strlen(response) + 1);
    if (ret < 0) {
        handle_error("Failed to send response to SHM");
    } else {
        LOG_DEBUG("Sent response %d to client: %s\n", watcher->request_count, response);
        // Send notification back via UDS
        ssize_t *ret_ptr = watcher->write_ptr;
        *ret_ptr = ret;
        if(write(watcher->usd_fd, ret_ptr, sizeof(ssize_t)) < 0) {
            perror("Failed to send notification via UDS");
        }
    }
    response_count++;
    response_bytes += ret;

    ev_io_stop(loop, w);
}

void handle_read(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct client_watcher *watcher = (struct client_watcher *)w->data;
    ssize_t *dummy = watcher->read_ptr;

    if (revents & EV_ERROR) {
        handle_error("EV_ERROR in handle_read");
        return;
    }

    // Read notification from UDS
    ssize_t nread = read(watcher->usd_fd, dummy, sizeof(ssize_t));
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; // Should not happen for level-triggered
        }
        perror("UDS read error");
        ev_io_stop(loop, w);
        close(watcher->usd_fd);
        return;
    }

    if (nread == 0) {
        printf("Client %d of UDS %d disconnected.\n", watcher->client_idx, watcher->usd_fd);
        ev_io_stop(loop, w);
        close(watcher->usd_fd);
        close(watcher->shm_conn_fd);
        // In a real app, you might free the watcher if dynamically allocated
        return;
    }

    if(*dummy == 0){
        return;
    }

    char request[1024];
    size_t count = *dummy;
    ssize_t ret = shm_read(watcher->shm_conn_fd, request, count);
    if (ret == -1) {
        handle_error("Failed to receive request");
    }else if(ret == 0){
        printf("Client SHM send %d bytes, but disconnected at request %d.\n", count, request_count);
        ev_io_stop(loop, w);
        close(watcher->usd_fd);
        shm_close(watcher->shm_conn_fd);
        // In a real app, you might free the watcher if dynamically allocated
        return;
    }else{
        LOG_DEBUG("Received request: %s\n", request);
    }

    
    request_count++;
    request_bytes += ret;

    ev_io_start(loop, &watcher->io_watcher_write);
}

void *stats_thread_func(void *arg) {
    struct client_watcher *client_info = (struct client_watcher *)arg;
    config_t *config = client_info->config;

    
    if(client_info->usd_fd < 0){
        return;
    }
    
    size_t total_requests = 0;
    size_t total_responses = 0;
    size_t total_responses_bytes = 0;
    size_t total_requests_bytes = 0;
    
    total_requests += request_count;
    total_responses += response_count; // 统计响应
    total_responses_bytes += response_bytes;
    total_requests_bytes += request_bytes;
    
    double requests_per_second = (double)(total_requests - last_total_requests);
    double responses_per_second = (double)(total_responses - last_total_responses);
    double response_bytes_second = (double)(total_responses_bytes - last_total_rspbytes);
    double request_bytes_second = (double)(total_requests_bytes - last_total_reqbytes);
    double throughput = (double)(request_bytes_second + response_bytes_second) * 8 / (1024 * 1024);
    printf("Total requests: %d, Requests per second: %.2f, Total responses: %d, Responses per second: %.2f, Throughput: %.2f Mbps/s\n", total_requests, requests_per_second, total_responses, responses_per_second, throughput);
    last_total_requests = total_requests;
    last_total_responses = total_responses;
    last_total_rspbytes = total_responses_bytes;
    last_total_reqbytes = total_requests_bytes;

}

int read_srv_config(const char *filename, config_t *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open config file");
        return -1;
    }

    // 解析配置文件
    fscanf(file, "server_ip=%15s\n", config->server_ip);
    fscanf(file, "port=%d\n", &config->port);
    fscanf(file, "packet_length=%d\n", &config->packet_length);
    fscanf(file, "test_duration=%d\n", &config->test_duration);
    fscanf(file, "conn_num=%d\n", &config->conn_num);

    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t threads[MAX_CLIENTS];
    int client_count = 0;

    if (argc < 3 || strcmp(argv[1], "-c") != 0) {
        fprintf(stderr, "Usage: %s -c <config_file>\n", argv[0]);
        exit(1);
    }
    const char *config_file = argv[2];

    config_t *config = (config_t *)malloc(sizeof(config_t));

    if (read_srv_config("config.txt", config) != 0) {
        return -1;
    }

     // Read configuration file
    shm_config_t *shm_config = read_config(config_file);

    // Initialize global shared memory
    shm_init_global(*shm_config);

    int uds_listen_fd;
    
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(1194);
    address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if ((uds_listen_fd = socket(AF_INET, SOCK_STREAM, 6)) == -1) {
        handle_error("UDS socket error");
    }

    if (bind(uds_listen_fd, (struct sockaddr*)&address, sizeof(address)) == -1) {
        handle_error("UDS bind error");
    }
    if (listen(uds_listen_fd, 15) == -1) {
        handle_error("UDS listen error");
    }
    printf("UDS server listening on %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    // Accept UDS connection
    int uds_conn_fd = accept(uds_listen_fd, (struct sockaddr*)&address, &addrlen);
    if (uds_conn_fd < 0) {
        handle_error("Accept UDS connection failed");
    }
    printf("Accepted UDS connection %d for client\n", uds_conn_fd);

    int listen_fd = shm_socket(0, shm_config->shm_size, 0);
    if (listen_fd == -1) {
        handle_error("Create listening socket failed");
    }

    if (shm_bind(listen_fd, "server_address", strlen("server_address")) < 0) {
        handle_error("SHM bind error");
    }

    if (shm_listen(listen_fd, 15) == -1) {
        fprintf(stderr, "Listen socket failed\n");
        cleanup_shared_memory(1);
    }
    printf("Listening socket %d is now listening\n", listen_fd);

    
    int conn_fds[3];
    int i = 0;

    static struct client_watcher client_watchers[3];
    struct ev_loop *loop = EV_DEFAULT;
    // 接受连接并处理请求
    for(i = 0; i < 1; i++) {
        struct sockaddr addr;
        socklen_t addrlen = sizeof(addr);
        conn_fds[i] = shm_accept(listen_fd, &addr, &addrlen);
        if (conn_fds[i] == -1) {
        fprintf(stderr, "Accept connection %d failed\n", conn_fds[i]);
            cleanup_shared_memory(1);
        }
        printf("Accepted SHM connection %d for client %d\n", conn_fds[i], i);

        // Initialize watcher for this client
        client_watchers[i].client_idx = i;
        client_watchers[i].shm_conn_fd = conn_fds[i];
        client_watchers[i].usd_fd = uds_conn_fd;
        client_watchers[i].request_count = 0;
        client_watchers[i].response_count = 0;
        client_watchers[i].request_bytes = 0;
        client_watchers[i].response_bytes = 0;
        client_watchers[i].read_ptr = (ssize_t *)malloc(sizeof(ssize_t));
        client_watchers[i].write_ptr = (ssize_t *)malloc(sizeof(ssize_t));
        client_watchers[i].config = config;
        // Set up the IO watcher for the UDS socket
        ev_io_init(&client_watchers[i].io_watcher_read, handle_read, client_watchers[i].usd_fd, EV_READ);
        client_watchers[i].io_watcher_read.data = &client_watchers[i];
        ev_io_start(loop, &client_watchers[i].io_watcher_read);

        ev_io_init(&client_watchers[i].io_watcher_write, handle_write, client_watchers[i].usd_fd, EV_WRITE);
        client_watchers[i].io_watcher_write.data = &client_watchers[i];
    }

    printf("Server setup complete. Running event loop.\n");

    ev_timer_init(&client_watchers[0].timer_watcher, stats_thread_func, 0.01, 1);
    client_watchers[0].timer_watcher.data = &client_watchers[0];
    ev_timer_start(loop, &client_watchers[0].timer_watcher);

    ev_run(loop, 0);

    // Cleanup
    for(i = 0; i < 1; i++) {
        shm_close(conn_fds[i]);
    }

    close(uds_listen_fd);

    return 0;
}
