#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>

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

// 客户端信息结构体
typedef struct {
    int client_id;
    int sock;
    config_t *config;
    shm_config_t *shm_config;
    char send_buff[BUF_SIZE];
    char recv_buff[BUF_SIZE];
} client_info_t;

sem_t *sem;

sem_t *sem_to_cli;

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

// 线程函数处理每个客户端连接
void *handle_client(void *arg) {
    client_info_t *client_info = (client_info_t *)arg;
    shm_config_t *shm_config = client_info->shm_config;
    char buffer[BUF_SIZE] = {0};
    ssize_t bytes_read, send_bytes;
    long total_bytes = 0;
    time_t start_time, end_time;
    int request_count = 0; // 请求计数

    // 记录开始时间
    start_time = time(NULL);
    char type[8];
    char url[NORMAL_SIZE] = {0};
    char *firstLine = NULL;
    char *host = malloc(NORMAL_SIZE);

    snprintf(host, NORMAL_SIZE, "%s", client_info->config->server_ip);

    while(1){
        sem_wait(sem);
        bytes_read = shm_read(client_info->sock, client_info->recv_buff, BUF_SIZE);
        if(bytes_read < 0){
            perror("shm_read failed");
            break;
        }
        LOG_DEBUG(__func__, "Server read request %s from shm.\n", buffer);
        total_bytes += bytes_read;
        request_count++;

        // Start Generation Here
        // 解析下载请求
        firstLine = strtok(client_info->recv_buff, "\r\n");

        if(firstLine != NULL){
            if(sscanf(firstLine, "%s %s", type, url) == 2){
                if(strcmp(type, "GET") == 0){
                    // 处理GET请求
                    LOG_DEBUG(__func__, "GET request received for URL: %s\n", url);
                    char *head = strtok(url, "//");
                    char *url_host = strtok(NULL, "/");
                    char *url_path = strtok(NULL, "");
                    if(strcmp(url_host, host) == 0){
                        FILE *file = fopen(url_path, "rb");
                        if (!file) {
                            LOG_ERROR(__func__, "Failed to open file: %s\n", url_path);
                            exit(EXIT_FAILURE);
                        }
                        size_t bytes_read = 1024;
                        while(bytes_read == 1024){
                            bytes_read = fread(client_info->send_buff, 1, bytes_read, file);
                            send_bytes = shm_write(client_info->sock, client_info->send_buff, bytes_read);
                            if(send_bytes < 0){
                                perror("shm_write failed");
                                break;
                            }
                            sem_post(sem_to_cli);
                            total_bytes += send_bytes;
                        }
                        fclose(file);
                        char eof[1024];
                        snprintf(eof, sizeof(eof), "%s", "EOF");
                        send_bytes = shm_write(client_info->sock, eof, strlen(eof));
                        LOG_INFO(__func__, "Write EOF to shm.\n");
                        if(send_bytes < 0){
                            perror("shm_write EOF failed");
                            break;
                        }
                        sem_post(sem_to_cli);
                    }
                }
            }
        }
    }

    // 记录结束时间
    end_time = time(NULL);

    double elapsed_time = difftime(end_time, start_time);
    double throughput = (double)(total_bytes * 8) / (1024 * 1024) / elapsed_time;  // MB/s

    printf("Thread for socket %d: Total data received: %ld bytes\n", client_info->sock, total_bytes);
    printf("Thread for socket %d: Elapsed time: %.2f seconds\n", client_info->sock, elapsed_time);
    printf("Thread for socket %d: Throughput: %.2f MB/s\n", client_info->sock, throughput);

    shm_close(client_info->sock);
    free(client_info);
    cleanup_shared_memory(1);
    pthread_exit(NULL);
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

    sem = NULL;
    sem_to_cli = NULL;

    void *ptr = alloc_shm("sem_r", sizeof(sem_t));
    if(ptr == NULL){
        perror("Alloc sem shm failed.");
        exit(EXIT_FAILURE);
    }

    sem = (sem_t *)ptr;
    if (sem_init(sem, 1, 0) == -1) {
        perror("sem_init failed");
        exit(EXIT_FAILURE);
    }

    void *wptr = alloc_shm("sem_w", sizeof(sem_t));
    if(ptr == NULL){
        perror("Alloc sem shm failed.");
        exit(EXIT_FAILURE);
    }

    sem_to_cli = (sem_t *)wptr;
    if (sem_init(sem_to_cli, 1, 0) == -1) {
        perror("sem_init failed");
        exit(EXIT_FAILURE);
    }

    // 1. 创建 shm socket
    if ((server_fd = shm_socket(0, shm_config->shm_size, 0)) < 0) {
        perror("socket failed");
        cleanup_shared_memory(1);
        exit(EXIT_FAILURE);
    }

    // 2. 绑定地址和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config->port);

    if (shm_bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        cleanup_shared_memory(1);
        exit(EXIT_FAILURE);
    }

    // 3. 监听连接
    if (shm_listen(server_fd, 10) < 0) {
        perror("listen failed");
        cleanup_shared_memory(1);
        exit(EXIT_FAILURE);
    }
    //printf("Listening on port %d...\n", config.port);

    // 4. 接受多个客户端连接
    while (client_count < config->conn_num) {
        if ((new_socket = shm_accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
        }
        LOG_INFO(__func__, "Client connected on socket %d\n", new_socket);

        // 为每个客户端创建一个新的线程
        client_info_t *client_info = malloc(sizeof(client_info_t));
        client_info->sock = new_socket;
        client_info->config = config;
        client_info->shm_config = shm_config;
        if (pthread_create(&threads[client_count], NULL, handle_client, (void *)client_info) != 0) {
            perror("Failed to create thread");
            free(client_info);
            cleanup_shared_memory(1);
        }

        client_count++;
    }

    // 等待所有线程完成
    for (int i = 0; i < client_count; i++) {
        pthread_join(threads[i], NULL);
    }

    cleanup_shared_memory(1);
    return 0;
}
