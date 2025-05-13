#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>

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

// 客户端信息结构体
typedef struct {
    int client_id;
    int sock;
    config_t *config;
    shm_config_t *shm_config;
    char file_name[128];
    char send_buff[BUF_SIZE];
    char recv_buff[BUF_SIZE];
} client_info_t;

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

// 线程函数模拟客户端连接
int request_counts[MAX_CLIENTS] = {0}; // 全局变量计数器数组
int response_counts[MAX_CLIENTS] = {0};
size_t response_bytes[MAX_CLIENTS] = {0};
size_t request_bytes[MAX_CLIENTS] = {0};

void *client_thread(void *arg) {
    client_info_t *client_info = (client_info_t *)arg;
    config_t *config = client_info->config;
    shm_config_t *shm_config = client_info->shm_config;
    int sock = client_info->sock;
    int cid = client_info->client_id;
    struct sockaddr_in serv_addr;

    sem_t *sem;

    void *ptr = read_shm("sem_w");

    sem = (sem_t *)ptr;

    // 用于更精确的时间控制
    struct timespec start_time, current_time;
    int duration = 0;

    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    int count = 0;

    while (duration < config->test_duration) {
        while(request_counts[cid] < 1){
            char url[512];
            char buffer[config->packet_length];

            snprintf(url, sizeof(url), "https://%s/%s", client_info->config->server_ip, client_info->file_name);

            snprintf(buffer, sizeof(buffer), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", url, client_info->config->server_ip);
        
            ssize_t bytes_write = shm_write(sock, buffer, strlen(buffer));
            if (bytes_write < 0) {
                if (bytes_write == -1) {
                    LOG_ERROR(__func__, "Send failed");
                    break;
                } else if (bytes_write == -2) {
                    LOG_DETAIL(__func__, "Buffer is full, waiting for space to become available.\n");
                    continue;
                }
            }

            request_counts[cid]++; // 更新计数器
            request_bytes[cid] += bytes_write;
            //count++;
            sem_post(sem); 
        }
        
        // 等待收到响应
        /*sem_wait(sem_from_server);
        char response[config->packet_length];
        ssize_t bytes_received = shm_read(sock, response, config->packet_length);
        if (bytes_received < 0) {
            continue;
        }
        LOG_DEBUG(__func__, "Client receives response from share: %s\n", response);
        response_counts[cid]++; // 更新计数器
        response_bytes[cid] += bytes_received;*/
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        duration = (current_time.tv_sec - start_time.tv_sec) + 
               (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
    }

    client_info->sock = -2;
    // 5. 关闭 socket
    shm_close(sock);
    cleanup_shared_memory(1);
    pthread_exit(NULL);
}

void *receive_response_thread(void *arg) {
    client_info_t *client_info = (client_info_t *)arg;
    config_t *config = client_info->config;
    int cid = client_info->client_id;
    int sock;
    sem_t *sem;

    void *ptr = read_shm("sem_r");
    sem = (sem_t *)ptr;

    FILE *fp = NULL;

    while (1) {
        if (client_info->sock == -1) {
            continue;
        }else if (client_info->sock == -2){
            break;
        }
        // 接收响应并计算往返时间
        sock = client_info->sock;
        char response[config->packet_length];
        fp = fopen(file_name, "a");
        if(fp == NULL){
            LOG_ERROR(__func__, "Failed to open file %s", file_name);
            continue;
        }
        sem_wait(sem);
        ssize_t bytes_received = shm_read(sock, response, config->packet_length);
        if (bytes_received < 0) {
            continue;
        }
        LOG_DEBUG(__func__,"Client receives response from share: %s\n", response);
        size_t bytes_write = fwrite(response, 1, bytes_received, fp);
        if(bytes_write != bytes_received){
            LOG_ERROR(__func__, "Failed to write %d bytes to file %s", bytes_received, file_name);
            continue;
        }
        fclose(fp);
        response_counts[cid]++; // 更新计数器
        response_bytes[cid] += bytes_received;
    }

    // 5. 关闭 socket
    shm_close(client_info->sock);
    pthread_exit(NULL);
}

int shm_client(client_info_t *client_info){
    int domain = client_info->client_id + 1;
    int shm_size = client_info->shm_config->shm_size;
    int sock = shm_socket(domain, shm_size, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return -1;
    }

    // 设置服务器地址
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    //serv_addr.sin_port = htons(client_info->config.port);

    // 将服务器IP地址转换为二进制形式
    /*if (inet_pton(AF_INET, client_info->config.server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sock);
        return -1;
    }*/

    // 连接到服务器
    if (shm_connect(sock, (const char *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }
    LOG_INFO(__func__,"Connected to share client.\n");

    client_info->sock = sock;

    return 0;
}

void *stats_thread_func(void *arg) {
    client_info_t *client_info = (client_info_t *)arg;
    config_t *config = client_info->config;
    int last_total_requests = 0;
    int last_total_responses = 0;
    size_t last_total_rspbytes = 0;
    size_t last_total_reqbytes = 0;

    while (1) {
        if(client_info->sock == -2){
            break;
        }
        sleep(1);
        int total_requests = 0;
        int total_responses = 0;
        size_t total_responses_bytes = 0;
        size_t total_requests_bytes = 0;
        for (int i = 0; i < config->conn_num; i++) {
            total_requests += request_counts[i];
            total_responses += response_counts[i]; // 统计响应
            total_responses_bytes += response_bytes[i];
            total_requests_bytes += request_bytes[i];
        }
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
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    pthread_t *threads;
    client_info_t *client_info;
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

    threads = (pthread_t *)malloc(2 * config->conn_num * sizeof(pthread_t));
    client_info = (client_info_t *)malloc(config->conn_num * sizeof(client_info_t));

    // 创建多个线程，每个线程代表一个客户端连接
    for (int i = 0; i < config->conn_num; i++) {
        client_info[i].client_id = i;
        client_info[i].sock = -1;
        client_info[i].config = config;
        client_info[i].shm_config = shm_config;
        strncpy(client_info[i].file_name, file_name, strlen(file_name));
        client_info[i].file_name[strlen(file_name)] = '\0'; // Ensure null termination
        if(shm_client(&client_info[i]) < 0){
            perror("Connect to shm server failed");
            return -1;
        }
        // 创建一个线程用于发送请求
        if (pthread_create(&threads[i], NULL, client_thread, (void *)&client_info[i]) != 0) {
            perror("Failed to create thread for sending requests");
        }
        // 创建一个线程用于接收响应
        if (pthread_create(&threads[i + config->conn_num], NULL, receive_response_thread, (void *)&client_info[i]) != 0) {
            perror("Failed to create thread for receiving responses");
        }
    }

    pthread_t calc_thread;
    if (pthread_create(&calc_thread, NULL, stats_thread_func, (void *)&client_info[0]) != 0) {
        perror("Failed to create calculation thread");
    }

    // 等待所有线程完成
    for (int i = 0; i < 2 * config->conn_num; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_join(calc_thread, NULL);

    return 0;
}