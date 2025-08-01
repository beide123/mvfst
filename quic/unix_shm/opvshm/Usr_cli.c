#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ev.h>
#include <shm_sock.h>

#define BUF_SIZE 1024 * 64
#define MAX_CLIENTS 100

const char file_name[1024] = "CHUNK_9999K.mp4";

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
    int connection_idx; // Index for fds, srv_to_cli_pipefds, etc.
    int shm_fd;         // The shared memory socket descriptor for this connection
    int usd_fd;         // The UDS socket descriptor for this connection
    int response_count; // To track responses for this connection
    int request_count; // To track requests for this connection
    size_t response_bytes;
    size_t request_bytes;
    ssize_t *read_ptr;
    ssize_t *write_ptr;
    config_t *config;
};

#define UDS_PATH "/tmp/app_srv.sock"

#define REQUEST_COUNT 100000

size_t response_count; // To track responses for this connection
size_t request_count; // To track requests for this connection
size_t response_bytes;
size_t request_bytes;

size_t last_total_requests = 0;
size_t last_total_responses = 0;
size_t last_total_rspbytes = 0;
size_t last_total_reqbytes = 0;

// 全局随机数缓存
static uint8_t random_cache[1024 * 1024];  // 1MB缓存
static int cache_offset = 0;
static uint64_t rng_state = 0;

// 初始化时填充缓存
void init_random_cache() {
    // 使用时间作为种子
    if (rng_state == 0) {
        rng_state = (uint64_t)time(NULL) ^ (uint64_t)getpid();
    }
    
    uint64_t *ptr = (uint64_t*)random_cache;
    int count = sizeof(random_cache) / 8;
    
    for (int i = 0; i < count; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state >> 17;
        ptr[i] = rng_state;
    }
}

void handle_error(const char *message) {
    fprintf(stderr, "%s\n", message);
    cleanup_shared_memory(1);
}

// 从配置文件读取配置信息
int read_cli_config(const char *filename, config_t *config) {
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

void handle_write(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct client_watcher *watcher = (struct client_watcher *)w->data;
    if(EV_ERROR & revents) {
        handle_error("Error event");
    }
    
    if(watcher->request_count == REQUEST_COUNT) {
        ev_io_stop(loop, w);
        return;
    }

    char request[1024];
    
    // 从缓存获取随机长度
    if (cache_offset + 4 > sizeof(random_cache)) {
        init_random_cache();  // 重新填充
        cache_offset = 0;
    }
    
    int len_rand = (int)(*(uint64_t*)(random_cache + cache_offset) & 0xFFFFFFFF);
    cache_offset += 8;
    int request_size = 100 + (abs(len_rand) % 901);
    
    // 从缓存复制随机数据
    if (cache_offset + request_size > sizeof(random_cache)) {
        init_random_cache();
        cache_offset = 0;
    }
    
    memcpy(request, random_cache + cache_offset, request_size);
    cache_offset += request_size;
    request[request_size] = '\0';


    LOG_DEBUG("Sending request %d from connection %d:%s\n", watcher->request_count + 1, watcher->connection_idx + 1, request);
    ssize_t ret = shm_write(watcher->shm_fd, request, request_size);
    if (ret == -1) {
        handle_error("Failed to send request");
    }
    
    ssize_t *ret_ptr = watcher->write_ptr;
    *ret_ptr = ret;
    if(write(watcher->usd_fd, ret_ptr, sizeof(ssize_t)) == -1) {
        handle_error("Failed to send notification");
    }
    
    request_count++;
    request_bytes += ret;
}

void handle_read(struct ev_loop *loop, struct ev_io *w, int revents) {
    
    // Handle read event
    struct client_watcher *watcher = (struct client_watcher *)w->data;
    ssize_t *dummy = watcher->read_ptr;
    if(EV_ERROR & revents) {
        handle_error("Error event");
    }

    ssize_t nread = 0;
    nread = read(watcher->usd_fd, dummy, sizeof(ssize_t));
    if(nread < 0) {
        handle_error("Failed to read from pipe");
    }else if(nread == 0) {
        handle_error("Pipe closed");
    }

    char response[256];
    size_t count = *dummy;
    int ret = shm_read(watcher->shm_fd, response, count);
    if (ret == -1) {
        handle_error("Failed to receive response");
    }else if(ret == 0){
        handle_error("SHM closed");
    }

    LOG_DEBUG("Received response: %s\n", response);
    response_count++;
    response_bytes += ret;
}

void *stats_thread_func(void *arg) {
    struct client_watcher *client_info = (struct client_watcher *)arg;
    config_t *config = client_info->config;

    
    if(client_info->usd_fd < 0){
        return;
    }
    
    int total_requests = 0;
    int total_responses = 0;
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

int main(int argc, char *argv[]) {
    pthread_t *threads;
    
    config_t *config = (config_t *)malloc(sizeof(config_t));

    if (argc < 3 || strcmp(argv[1], "-c") != 0) {
        fprintf(stderr, "Usage: %s -c <config_file>\n", argv[0]);
        exit(1);
    }
    const char *config_file = argv[2];

    if (read_cli_config("config.txt", config) != 0) {
        return -1;
    }

     // Read configuration file
    shm_config_t *shm_config = read_config(config_file);

    // Initialize global shared memory
    shm_init_global(*shm_config);

    // Establish three connections
    int fds[3];

    struct client_watcher watchers[3];

    struct ev_loop *loop = EV_DEFAULT;

    // Create and connect ONE UDS socket for all connections
    int uds_fd = socket(AF_INET, SOCK_STREAM, 6);
    if (uds_fd == -1) {
        handle_error("Failed to create UDS socket");
    }

    struct sockaddr_in uds_addr;
    memset(&uds_addr, 0, sizeof(uds_addr));
    uds_addr.sin_family = AF_INET;
    uds_addr.sin_port = htons(1194);
    uds_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(uds_fd, (struct sockaddr*)&uds_addr, sizeof(struct sockaddr_in)) == -1) {
        handle_error("Failed to connect UDS socket");
    }

    usleep(100000);

    for (int i = 0; i < 1; i++) {
        // Create SHM socket
        fds[i] = shm_socket(i + 1, shm_config->shm_size, 0);
        
        if (fds[i] == -1) {
            handle_error("Failed to create socket");
        }

        if (shm_connect(fds[i], "server_address", strlen("server_address")) == -1) {
            handle_error("Failed to connect socket");
        }

        
        watchers[i].connection_idx = i;
        watchers[i].shm_fd = fds[i];
        watchers[i].request_count = 0;
        watchers[i].response_count = 0;
        watchers[i].request_bytes = 0;
        watchers[i].response_bytes = 0;
        watchers[i].usd_fd = uds_fd;
        watchers[i].read_ptr = (ssize_t *)malloc(sizeof(ssize_t));
        watchers[i].write_ptr = (ssize_t *)malloc(sizeof(ssize_t));

        ev_io_init(&watchers[i].io_watcher_read, handle_read, watchers[i].usd_fd, EV_READ);
        watchers[i].io_watcher_read.data = &watchers[i];
        ev_io_start(loop, &watchers[i].io_watcher_read);

        ev_io_init(&watchers[i].io_watcher_write, handle_write, watchers[i].usd_fd, EV_WRITE);
        watchers[i].io_watcher_write.data = &watchers[i];
        ev_io_start(loop, &watchers[i].io_watcher_write);

        printf("Connected SHM socket %d and UDS socket %d\n", fds[i], uds_fd);
    }

    last_total_requests = 0;
    last_total_responses = 0;
    last_total_rspbytes = 0;
    last_total_reqbytes = 0;

    // 初始化随机数缓存
    init_random_cache();

    // 映射共享内存
    /*void *ptr = mmap(0, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_sem_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    sem_t *sem = (sem_t*)ptr;
    sem_t *sem_server_to_client = (sem_t *)((char*)ptr + sizeof(sem_t));*/
    ev_timer_init(&watchers[0].timer_watcher, stats_thread_func, 0.01, 1);
    watchers[0].timer_watcher.data = &watchers[0];
    ev_timer_start(loop, &watchers[0].timer_watcher);

    // Send 10 requests and receive 10 responses for each connection

    ev_run(loop, 0);

    // Close connections
    close(uds_fd);
    for (int i = 0; i < 1; i++) {
        ev_timer_stop(loop, &watchers[i].timer_watcher);
        ev_io_stop(loop, &watchers[i].io_watcher_read);
        ev_io_stop(loop, &watchers[i].io_watcher_write);
        if (shm_close(fds[i]) == -1) {
            handle_error("Failed to close socket");
        }
    }
    
    
    return 0;
}