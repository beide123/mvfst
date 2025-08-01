/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <semaphore.h>

#include <glog/logging.h>

#include <folly/FileUtil.h>
#include <folly/fibers/Baton.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/compression/ZlibCertificateDecompressor.h>
#include <fizz/compression/ZstdCertificateDecompressor.h>

#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/unix_shm/opvshm/LogQuicStats.h>

#include <shm_sock.h>

#include <iomanip>
#include <sstream>

#define SHM_NAME "/my_shared_memory" // 共享内存名称
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

namespace quic::opv_shm {

constexpr size_t kNumTestStreamGroups = 2;

size_t fileCounter = 0;

// Now define ShmMdlwClient
class ShmMdlwClient :  public quic::QuicSocket::ConnectionSetupCallback,
                   public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback,
                   public quic::QuicSocket::WriteCallback,
                   public quic::QuicSocket::DatagramCallback
                   {
 public:
  ShmMdlwClient(
      const std::string& host,
      uint16_t port,
      uint16_t duration,
      bool useDatagrams,
      uint64_t activeConnIdLimit,
      bool enableMigration,
      bool enableStreamGroups,
      std::vector<std::string> alpns,
      bool connectOnly,
      const std::string& clientCertPath,
      const std::string& clientKeyPath)
      : host_(host),
        port_(port),
        duration_(duration),
        useDatagrams_(useDatagrams),
        activeConnIdLimit_(activeConnIdLimit),
        enableMigration_(enableMigration),
        enableStreamGroups_(enableStreamGroups),
        alpns_(std::move(alpns)),
        connectOnly_(connectOnly),
        clientCertPath_(clientCertPath),
        clientKeyPath_(clientKeyPath) {}

  typedef struct {
      char server_ip[16];
      uint16_t port;
      int packet_length;
      int test_duration;
      int conn_num;
  } config_t;

  // 客户端信息结构体
  typedef struct {
      int client_id;
      int sock;
      int shm_sock;
      config_t *config;
      shm_config_t *shm_config;
      char *send_buff;
      char *recv_buff;
  } client_info_t;

  
  class LocalFifoEventHandler : public folly::EventHandler {
  public:
      // 构造函数接收原始的 folly::EventBase* 和一个指向其外部 ShmMdlwClient 实例的指针
      LocalFifoEventHandler(folly::EventBase* evb, ShmMdlwClient* owner)
          : folly::EventHandler(evb), ownerClient_(owner) { // 直接使用 evb 初始化基类
          CHECK(evb);
          CHECK(ownerClient_);
      }

      void handlerReady(uint16_t events) noexcept override {
          if (events & folly::EventHandler::READ) {
              CHECK(ownerClient_);
              ownerClient_->handleShmFifoEvent();
          }
      }

  private:
      ShmMdlwClient* ownerClient_;
  };

  void readAvailable(quic::StreamId streamId) noexcept override {
    LOG(INFO) << "EchoClient readAvailable streamId=" << streamId;
  }

  int read_cli_config(const char *filename, config_t *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        LOG(ERROR) << "Failed to open config file: " << filename;
        return -1;
    }

    // 解析配置文件
    if (fscanf(file, "server_ip=%15s\n", config->server_ip) != 1) {
        LOG(ERROR) << "Failed to parse 'server_ip' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "port=%hu\n", &config->port) != 1) {
        LOG(ERROR) << "Failed to parse 'port' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "packet_length=%d\n", &config->packet_length) != 1) {
        LOG(ERROR) << "Failed to parse 'packet_length' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "test_duration=%d\n", &config->test_duration) != 1) {
        LOG(ERROR) << "Failed to parse 'test_duration' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "conn_num=%d\n", &config->conn_num) != 1) {
        LOG(ERROR) << "Failed to parse 'conn_num' from " << filename;
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
  }

  void SendDataToApp(const char* chunk, size_t dataLength) {
    // filePath parameter is currently unused in SHM context.
    if (!client_info_ || client_info_->shm_sock < 0) {
        LOG(ERROR) << "writeDataToFile: client_info_ or shm_sock is invalid.";
        return;
    }

    ssize_t bytesWrittenToShm = shm_write(client_info_->shm_sock, chunk, dataLength);
    if (bytesWrittenToShm < 0) {
      LOG(ERROR) << "writeDataToFile: shm_write failed: " << strerror(errno);
      return;
    }
    if (static_cast<size_t>(bytesWrittenToShm) != dataLength) {
      LOG(ERROR) << "writeDataToFile: Partial shm_write. Wrote " << bytesWrittenToShm << " out of " << dataLength;
      return;
    }

    std::atomic_thread_fence(std::memory_order_release);

    VLOG(1) << "writeDataToFile: Successfully wrote " << bytesWrittenToShm << " bytes to SHM socket " << client_info_->shm_sock;

    // Notify the SHM client via the persistently open FIFO (shm_write_fd_)
    if (uds_conn_fd_ == -1) { // 检查文件描述符是否有效
        LOG(ERROR) << "writeDataToFile: uds_conn_fd_ is invalid. Cannot write notification to sc_fifo: " << uds_conn_fd_;
        return;
    }

    *notify_buffer_ = bytesWrittenToShm;
    ssize_t written_to_fifo = ::write(uds_conn_fd_, notify_buffer_, sizeof(ssize_t));
    if (written_to_fifo == -1) {
        LOG(ERROR) << "writeDataToFile: Failed to write notification to sc_fifo (fd: " << uds_conn_fd_ 
                   << ", path: " << uds_path_ << "): " << strerror(errno);
        // If EPIPE, the read end of the pipe was closed. Consider closing and reopening shm_write_fd_ on next attempt.
        // For now, just log the error.
    } else {
        VLOG(1) << "writeDataToFile: Successfully wrote notification to sc_fifo (fd: " << uds_conn_fd_ 
                << ", path: " << uds_path_ << ")";
    }
    
    /*
    connManager_->getEventBase()->runInEventBaseThread([this]() {
      sem_post(sem_r);
    });
    */
  }

  void readAvailable(quic::StreamId streamId, int64_t connId) noexcept override {
    auto quicClient_ = connManager_->getConnection(connId);
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }
    bool eof = readData->second;
    auto data = readData->first.get();

    auto current = data->cloneCoalescedAsValue();
    size_t dataLength = current.length();
    
    std::string filePath = "./" + fileName_;
    /*std::ofstream file(filePath, std::ios::binary | std::ios::app);
    if (!file) {
      LOG(ERROR) << "Failed to create file: " << filePath;
      return;
    }*/
    if (recvOffsets_.find(connId) == recvOffsets_.end() || recvOffsets_[connId].find(streamId) == recvOffsets_[connId].end()) {
        recvOffsets_[connId][streamId] = 0; 
    }

    const char* active = (const char*)current.data();

    if (memcmp(active, "HTTP/1.1", 8) == 0) {
      LOG(INFO) << "HTTP/1.1 response received";
      size_t ac_header_len = strlen("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
      activePath_[connId] = true;
      active += ac_header_len;
      dataLength -= ac_header_len;
    }

    if (dataLength > 0) {
        auto dataCopy = folly::IOBuf::copyBuffer(active, dataLength);
        VLOG(2) << "Read available data= " << dataCopy->toString();
        connManager_->getEventBase()->runInEventBaseThread(
          [this, data = std::move(dataCopy), dataLength, connId]() {
            VLOG(2) << "Merge data is " << data->toString();
            connManager_->mergeData(data.get(), dataLength, connId, frameLabel_);
          });
    }

    recvOffsets_[connId][streamId] += dataLength;
    
    // 如果接收到 EOF，关闭当前文件并创建新文件
    if(eof){
        LOG(INFO) << "Stream " << streamId << " has reached EOF.";
    }
  }

  void readAvailableWithGroup(
      quic::StreamId streamId,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient readAvailableWithGroup streamId=" << streamId
              << " groupId=" << groupId;
  }

  void readError(quic::StreamId streamId, QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient failed read from stream=" << streamId
               << ", error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void timeoutExpired() noexcept {
    auto connIds = connManager_->getAllConnectionIds();
    for (auto& connId : connIds) {
      if (auto client = connManager_->getConnection(connId)) {
        client->closeNow(none);
      }
    }
  }

  void onMultiNewBidirectionalStream(int64_t connId, StreamId id) noexcept override {
    LOG(INFO) << "EchoClient" << connId << "new bidirectional stream=" << id;
    connManager_->getConnection(connId)->setReadCallback(id, this);
  }

  void onNewBidirectionalStream(StreamId id) noexcept override {
    LOG(INFO) << "EchoClient new bidirectional stream=" << id;
  }

  void onNewUnidirectionalStream(StreamId id) noexcept override {
    LOG(INFO) << "EchoClient unidirectional stream=" << id;
  } 

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode /*error*/) noexcept override {
    VLOG(10) << "EchoClient got StopSending stream id=" << id;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "MdlwClient::onConnectionEnd() noexcept called";
  }

  void onConnectionEnd(QuicError /*error*/) noexcept override {
    LOG(INFO) << "MdlwClient connection end";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient error: " << toString(error.code)
               << "; errStr=" << error.message;
    startDone_.post();
  }

  void onTransportReady() noexcept override {
    if (!connectOnly_) {
      startDone_.post();
    }
  }

  void onReplaySafe() noexcept override {
    if (connectOnly_) {
      VLOG(3) << "Connected successfully";
      startDone_.post();
    }
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "EchoClient socket is write ready with maxToSend="
              << maxToSend;
    //sendMessage(id, pendingOutput_[id], 0);
  }

  void onMultiStreamWriteReady(int64_t connId, quic::StreamId id, uint64_t maxToSend) noexcept
    override {
    pushMessage(id, pendingOutputs_[connId][id], 0, connId, maxToSend);
    //sendMessage(id, pendingOutputs_[connId][id], 0, connId);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "EchoClient write error with stream=" << id
               << " error=" << toString(error);
  }

  void onDatagramsAvailable(int64_t connId) noexcept override {
    auto client = connManager_->getConnection(connId);
    auto res = client->readDatagrams();
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient failed reading datagrams on connection " << connId 
                 << ", error=" << res.error();
      return;
    }
    for (const auto& datagram : *res) {
      LOG(INFO) << "Client received datagram on connection " << connId << " ="
                << datagram.bufQueue().front()->cloneCoalesced()->to<std::string>();
    }
  }

  void onDatagramsAvailable() noexcept override {

  }

  void handleShmFifoEvent() {
    VLOG(1) << "handleShmFifoEvent triggered for fd: " << uds_conn_fd_;
    size_t headerSize = strlen("FRAME") + sizeof(uint64_t) + sizeof(size_t);
    // 1. 从通知 FIFO (shm_listen_fd_) 读取一个字节，以清除事件并确认通知。
    ssize_t nread = ::read(uds_conn_fd_, recv_length_, sizeof(ssize_t));

    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG(ERROR) << "handleShmFifoEvent: Error reading from notification FIFO fd " << uds_conn_fd_
                       << ": " << strerror(errno) << " (errno: " << errno << ")";
        }
        shm_fifo_handler_->unregisterHandler();
        ::close(uds_conn_fd_);
        uds_conn_fd_ = -1;
        return;
    } else if (nread == 0) {
        // FIFO 的写入端已关闭。这可能表示 SHM 客户端已终止。
        LOG(ERROR) << "handleShmFifoEvent: read 0 bytes from notification UDS fd " << uds_conn_fd_
                  << ", peer (SHM client) likely closed the write end of the UDS.";
        
        if (shm_fifo_handler_ && shm_fifo_handler_->isHandlerRegistered()) {
            shm_fifo_handler_->unregisterHandler();
        }
        return;
    } else {
        // 成功从 FIFO 读取到通知字节。
        if(*recv_length_ > 0){
          VLOG(1) << "handleShmFifoEvent: Successfully read " << nread 
                  << " byte(s) from notification UDS fd " << uds_conn_fd_ << ". Proceeding to read from SHM.";
        }else{
          return;
        }
    }
    
    // 检查 client_info_ 和 shm_sock 是否有效
    if (!client_info_ || client_info_->shm_sock < 0) {
        LOG(ERROR) << "handleShmFifoEvent: client_info_ or client_info_->shm_sock is invalid. Cannot read from SHM.";
        return;
    }

    // --- 开始原 ReadDataFromShm() 的核心逻辑 (单次执行版本) ---
    VLOG(1) << "handleShmFifoEvent: Attempting to read data from SHM socket " << client_info_->shm_sock;
    
    char* rspbuf = client_info_->recv_buff + headerSize + batch_bytes_;

    size_t len = *recv_length_;
    ssize_t bytes_read_from_shm = shm_read(client_info_->shm_sock, rspbuf, len); // -1 for null terminator

    if (bytes_read_from_shm < 0) {
        LOG(ERROR) << "handleShmFifoEvent: shm_read from socket " << client_info_->shm_sock << " failed: " << strerror(errno);
        // 这里可能也需要错误处理，比如关闭连接
        return;
    } else if (bytes_read_from_shm == 0) {
        LOG(ERROR) << "handleShmFifoEvent: shm_read 0 bytes from socket " << client_info_->shm_sock << ". SHM Client might have closed connection.";
        // 处理连接关闭的情况
        return;
    }

    auto sequenceNumber = connManager_->getSequenceNumber();

    memcpy(client_info_->recv_buff, "FRAME", strlen("FRAME"));

    memcpy(client_info_->recv_buff + strlen("FRAME"), &sequenceNumber, sizeof(uint64_t));

    memcpy(client_info_->recv_buff + strlen("FRAME") + sizeof(uint64_t), &bytes_read_from_shm, sizeof(size_t));

    client_info_->recv_buff[headerSize + bytes_read_from_shm] = '\0'; // 确保字符串结束
    VLOG(1) << "handleShmFifoEvent: Read " << bytes_read_from_shm << " bytes from SHM" ;
    

    scheduleRequests(client_info_->recv_buff, headerSize + bytes_read_from_shm, request_shm_counts_);

    connManager_->setSequenceNumber(sequenceNumber + 1);

    VLOG(1) << "handleShmFifoEvent: Request scheduled based on data from SHM. Current request_shm_counts_: " << this->request_shm_counts_;
  }

  bool activateConnections(){
    std::vector<int64_t> ConnIds = connManager_->getAllConnectionIds();
    for (auto& connId : ConnIds) {
      auto client = connManager_->getConnection(connId);
      if (!client) {
        LOG(ERROR) << "Failed to get client for connection ID: " << connId;
        continue;
      }
      folly::Expected<StreamId, LocalErrorCode> stream;
      do {
        stream = client->createBidirectionalStream();
      } while (!stream.hasValue());
      // Set the read callback
      auto streamId = stream.value();
      client->setReadCallback(streamId, this);
      LOG(INFO) << "Client " << connId << " Created stream ID: " << streamId;
      connManager_->buildClientStreamsMap(connId, streamId);
      // Send an activation request to the server for each connection to establish the stream
      std::string acivRequest = "ACTIVATE\r\n\r\n";
      client->getEventBase()->runInEventBaseThread([this, streamId, client, acivRequest = std::move(acivRequest)]() {
          auto req = folly::IOBuf::copyBuffer(acivRequest);
          auto res = client->writeChain(streamId, std::move(req), false, nullptr);
          if (res.hasError()) {
            LOG(ERROR) << "Error sending activation request: " << toString(res.error());
          }
      });
    }

    bool isAllActive = false;
    while(!isAllActive){
      isAllActive = true;
      for(auto& connId : ConnIds ){
        isAllActive &= activePath_[connId];
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    return isAllActive;
  }

  void scheduleRequests(const char *request, size_t req_len, uint64_t& i) {
    auto client_pair = connManager_->getBestConnection();
    auto connId = client_pair.first;
    auto client = client_pair.second;
    if (!client) {
      LOG(ERROR) << "No available connection to send data";
      return;
    }
    auto streamId = connManager_->getClientStream(connId);

    // Copy the buffer here with explicit length to avoid race condition and strlen issues.
    auto data_to_send = folly::IOBuf::copyBuffer(request, req_len);

    // Submit the send task to EventBaseThread
    client->getEventBase()->runInEventBaseThread(
        [this, data = std::move(data_to_send), connId, i, streamId]() mutable {
          // Save the request content to the pending send map
          auto& pendingOutput_ = pendingOutputs_[connId];
          pendingOutput_[streamId].append(std::move(data));

          // Send the request
          sendMessage(streamId, pendingOutput_[streamId], i, connId);
          //client->notifyPendingWriteOnStream(streamId, this);
        });
    ++i;
    
  }

  void generateRequests(size_t numRequests) {
    size_t i = 0;
    
    if(!activateConnections()){
      LOG(ERROR) << "Failed to activate connections";
      return;
    }
    
    auto start = std::chrono::steady_clock::now();

    std::string url = "https://" + host_ + "/" + fileName_; //+ std::to_string(i);
    std::string request = "GET " + url + " HTTP/1.1\r\nHost: " + host_ + "\r\n\r\n";
    
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < duration_) {
        size_t batchStart = i;
       
        while (i < numRequests && i < batchStart + 1000) {
            // Construct the request content
            auto client_pair = connManager_->getBestConnection();
            auto connId = client_pair.first;
            auto client = client_pair.second;
            if (!client) {
              LOG(ERROR) << "No available connection to send data";
              return;
            }
            auto streamId = connManager_->getClientStream(connId);
            //LOG(INFO) << "Submitting task: index=" << i;
            // Submit the send task to EventBaseThread
            client->getEventBase()->runInEventBaseThread([this, request = std::move(request), connId, i, streamId]() {
                // Save the request content to the pending send map
                auto& pendingOutput_ = pendingOutputs_[connId];
                pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(request));

                // Send the request
                sendMessage(streamId, pendingOutput_[streamId], i, connId);
            });
            ++i;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Wait 10ms after each batch
        if (std::cin.eof()) {
          break; // Exit the loop
        }
    }
  }

  void AcceptShmConnection(){
    if (!client_info_) {
        LOG(ERROR) << "client_info_ is not initialized in AcceptShmConnection.";
        // Consider exiting or throwing an exception if this is a fatal state
        exit(EXIT_FAILURE); 
        return;
    }
    if (!client_info_->config) {
        LOG(ERROR) << "client_info_->config is not initialized in AcceptShmConnection.";
        exit(EXIT_FAILURE);
        return;
    }
    if (!client_info_->shm_config) {
        LOG(ERROR) << "client_info_->shm_config is not initialized in AcceptShmConnection.";
        exit(EXIT_FAILURE);
        return;
    }
    int cid = client_info_->client_id;
    config_t *config = client_info_->config;
    shm_config_t *shm_config = client_info_->shm_config;

    int listen_fd = -1;

    int conn_fds[3];
    int i = 0;
   
    int server_fd = -1;
    sockaddr_in address;

    activateConnections();

    // 1. 创建 shm socket
    if ((server_fd = shm_socket(0, shm_config->shm_size, 0)) < 0) {
        LOG_ERROR(__func__, "socket failed");
        cleanup_shared_memory(1);
        exit(EXIT_FAILURE);
    }

    // 2. 绑定地址和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config->port);

    if (shm_bind(server_fd, (const char*)&address, sizeof(address)) < 0) {
        LOG(ERROR) << "shm_bind failed";
        cleanup_shared_memory(1);
        exit(EXIT_FAILURE);
    }

    // 3. 监听连接
    if (shm_listen(server_fd, 10) < 0) {
        LOG(ERROR) << "shm_listen failed";
        cleanup_shared_memory(1);
        exit(EXIT_FAILURE);
    }

    socklen_t addrlen = sizeof(address);
    int sock = shm_accept(server_fd, (struct sockaddr *)&address, &addrlen);

    client_info_->shm_sock = sock;

    VLOG(1) << "AcceptShmConnection: shm_sock: " << sock;

    connManager_->setShmSocket(sock);
  }

  size_t calculateThroughput(std::chrono::steady_clock::time_point& lastTime, size_t& lastTotalBytes, size_t& lastTotalBytes_conn0, size_t& lastTotalBytes_conn1) {
    auto currentTime = std::chrono::steady_clock::now();
    size_t currentTotalBytes_conn0 = 0;
    size_t currentTotalBytes_conn1 = 0;

    currentTotalBytes_conn0 += recvOffsets_[0][0];
    currentTotalBytes_conn0 += sendOffsets_[0][0];
    currentTotalBytes_conn1 += recvOffsets_[1][0];
    currentTotalBytes_conn1 += sendOffsets_[1][0];
    size_t currentTotalBytes = currentTotalBytes_conn0 + currentTotalBytes_conn1;

    // Calculate the time difference
    std::chrono::duration<double> elapsed = currentTime - lastTime;

    // Print the throughput every second
    if (elapsed.count() >= 1.0) {
        float throughput = (float)(currentTotalBytes - lastTotalBytes) * 8 / 1024 / 1024; // Current throughput, converted to Mbps
        float throughput_conn0 = (float)(currentTotalBytes_conn0 - lastTotalBytes_conn0) * 8 / 1024 / 1024; // 当前秒的吞吐量，换算成Mbps
        float throughput_conn1 = (float)(currentTotalBytes_conn1 - lastTotalBytes_conn1) * 8 / 1024 / 1024; 
        float sendThroughput = (float)(sendOffsets_[0][0] + sendOffsets_[1][0] - lastSendOffsets_) * 8 / 1024 / 1024;
        float recvThroughput = (float)(recvOffsets_[0][0] + recvOffsets_[1][0] - lastRecvOffsets_) * 8 / 1024 / 1024;
        LOG(INFO) << "The Download Throughput: " << throughput << " Mbps\n"
                  << "send Throughput: " << sendThroughput << " Mbps\n"
                  << "recv Throughput: " << recvThroughput << " Mbps\n"
                  << " -----conn0: " << throughput_conn0 << " Mbps\n"
                  << " -----conn1: " << throughput_conn1 << " Mbps\n";
        // Update the last bytes and time
        lastTotalBytes = currentTotalBytes;
        lastTotalBytes_conn0 = currentTotalBytes_conn0;
        lastTotalBytes_conn1 = currentTotalBytes_conn1;
        lastSendOffsets_ = sendOffsets_[0][0] + sendOffsets_[1][0];
        lastRecvOffsets_ = recvOffsets_[0][0] + recvOffsets_[1][0];
        lastTime = currentTime;
    }
    return 0; 
  }

  void start(std::string token) {
    // networkThread and mergeDataThread are local ScopedEventBaseThreads.
    // Their EventBases run in their own separate threads.
    folly::ScopedEventBaseThread networkThread("EchoClientThread");
    auto evb = networkThread.getEventBase();
    auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
    folly::ScopedEventBaseThread mergeDataThread("MergeDataThread");
    auto mev = mergeDataThread.getEventBase();
    auto mEvb = std::make_shared<FollyQuicEventBase>(mev);
    
    // Get the current thread's class structure and generate an event base
    folly::EventBase *currentEvb = new folly::EventBase();
    shmEvb_ = std::make_shared<FollyQuicEventBase>(currentEvb); 
    

    LOG(INFO) << "Event base for the current thread is ready to use.";

    connManager_ = std::make_shared<CliConnection>();
    connManager_->setEventBase(mEvb);
    mptcp_sock_ = new struct mptcp_sock();
    mptcp_sock_->connManager = connManager_;
    fileName_ = "CHUNK_9999K.mp4";
    frameLabel_ = "FRAME";
    connManager_->setScheduler("rr", mptcp_sock_);
    connManager_->setDataCallback([this](const char* data, size_t dataLength) {
      this->SendDataToApp(data, dataLength);
    });

    std::vector<folly::SocketAddress> localAddresses; // store different local addresses

    config_t *config = (config_t *)malloc(sizeof(config_t));
    if (read_cli_config("config.txt", config) != 0) {
        LOG(ERROR) << "Read config file failed.";
        exit(EXIT_FAILURE);
    }
    
    for (int i = 0; i < 2; ++i) {
      folly::SocketAddress localAddr("30.1." + std::to_string(i + 2) + ".100", 6666); // bind to different interface port
      localAddresses.push_back(localAddr);
    }

    host_ = std::string(config->server_ip);
    port_ = config->port;

    /*for (int i = 0; i < 2; ++i) {
      folly::SocketAddress localAddr("127.0.0.1", port_ + i); // bind to different interface port
      localAddresses.push_back(localAddr);
    }*/ 

    int64_t idx = 0;

    for (const auto& localAddr : localAddresses) {
      evb->runInEventBaseThreadAndWait([&, localAddr] {
        auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb);
        sock->bind(localAddr);
        auto fizzCLientCtx = createFizzClientContext();
        auto fizzClientContext =
            FizzClientQuicHandshakeContext::Builder()
                .setCertificateVerifier(test::createTestCertificateVerifier())
                .setFizzClientContext(std::move(fizzCLientCtx))
                .build();
        std::shared_ptr<quic::QuicClientTransport> quicClient_;
        quicClient_ = std::make_shared<quic::QuicClientTransport>(
            qEvb, std::move(sock), std::move(fizzClientContext));
        quicClient_->setHostname("echo.com");

        folly::SocketAddress addr(host_.c_str(), port_);

        quicClient_->addNewPeerAddress(addr);
        if (!token.empty()) {
          quicClient_->setNewToken(token);
        }
        if (useDatagrams_) {
          auto res = quicClient_->setDatagramCallback(this);
          CHECK(res.hasValue()) << res.error();
        }

        TransportSettings settings;
        settings.datagramConfig.enabled = useDatagrams_;
        settings.selfActiveConnectionIdLimit = activeConnIdLimit_;
        settings.disableMigration = !enableMigration_;
        settings.batchingMode = QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO;
        settings.maxBatchSize = 128;
        
        
        settings.initCwndInMss = 50;
        

        settings.idleTimeout = std::chrono::milliseconds(600000);
        
        if (enableStreamGroups_) {
          settings.notifyOnNewStreamsExplicitly = true;
          settings.advertisedMaxStreamGroups = kNumTestStreamGroups;
        }
        quicClient_->setTransportSettings(settings);

        quicClient_->setTransportStatsCallback(
            std::make_shared<LogQuicStats>("client"));

        LOG(INFO) << "EchoClient " << localAddr.describe() << " connecting to " << addr.describe();
        quicClient_->start(this, this);

        quicClient_->setClientConnIdx(idx);

        quicClient_->setMultiPath(true);

        activePath_[idx] = false;

        connManager_->addConnection(idx, quicClient_);

        idx++;
      });
    }
 
    // 启动状态打印线程
    std::thread([this]() {
        std::chrono::steady_clock::time_point lastTime = std::chrono::steady_clock::now();
        size_t lastTotalBytes = 0;
        size_t lastTotalBytes_conn0 = 0;
        size_t lastTotalBytes_conn1 = 0;
        while (running_) {
            // 在这里输出性能指标，例如吞吐量
            calculateThroughput(lastTime, lastTotalBytes, lastTotalBytes_conn0, lastTotalBytes_conn1);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }).detach();

    /*Shm init*/
    
    const char *config_file = "srv.conf";
    // Read configuration file
    shm_config_t *shm_config = read_config(config_file);

    // Initialize global shared memory
    shm_init_global(*shm_config);

    notify_buffer_ = (ssize_t *)malloc(sizeof(ssize_t));
    recv_length_ = (ssize_t *)malloc(sizeof(ssize_t));

    pthread_t shm_thread[MAX_CLIENTS], tcp_thread[MAX_CLIENTS];
    client_info_t client_info[MAX_CLIENTS];

     // 映射共享内存
    /*void *ptr = alloc_shm("sem_r", sizeof(sem_t));
    if(ptr == NULL){
        LOG_ERROR(__func__, "Alloc sem_r shm failed.");
        exit(EXIT_FAILURE);
    }

    sem_r = (sem_t *)ptr;*/

    /*init sem_r(process-shared read data from shm, default value = 0)*/
    /*if (sem_init(sem_r, 1, 0) == -1) {
        perror("sem_r init failed");
        exit(EXIT_FAILURE);
    }

    void *wptr = alloc_shm("sem_w", sizeof(sem_t));
    if(wptr == NULL){
        perror("Alloc sem_w shm failed.");
        exit(EXIT_FAILURE);
    }

    sem_w = (sem_t *)wptr;*/

    /*init sem_w(process-shared write data into shm, default value = 0)*/
    /*if (sem_init(sem_w, 1, 0) == -1) {
        perror("sem_w init failed");
        exit(EXIT_FAILURE);
    }*/
    

    startDone_.wait();

    client_info_ = (client_info_t *)malloc(sizeof(client_info_t));

    client_info_->sock = -1;
    client_info_->client_id = 0;
    client_info_->config = config;
    client_info_->shm_config = shm_config;
    client_info_->recv_buff = (char *)malloc(sizeof(char) * BUFFER_SIZE * 10 * 2);
    client_info_->send_buff = (char *)malloc(sizeof(char) * BUFFER_SIZE);

    uds_conn_fd_ = ::socket(AF_INET, SOCK_STREAM, 6);
    if (uds_conn_fd_ == -1) {
        LOG(ERROR) << "Failed to create UDS socket: " << strerror(errno);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(uds_path_.c_str());
    server_addr.sin_port = htons(1194);

    if (::bind(uds_conn_fd_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOG(ERROR) << "Failed to bind UDS socket: " << strerror(errno);
        ::close(uds_conn_fd_);
        exit(EXIT_FAILURE);
    }
    
    if (::listen(uds_conn_fd_, 15) < 0) {
        LOG(ERROR) << "Failed to listen on UDS socket: " << strerror(errno);
        ::close(uds_conn_fd_);
        exit(EXIT_FAILURE);
    }

    socklen_t addrlen = sizeof(struct sockaddr_in);
    uds_conn_fd_ = ::accept(uds_conn_fd_, (struct sockaddr *)&server_addr, &addrlen);

    if (uds_conn_fd_ < 0) {
        LOG(ERROR) << "Failed to accept UDS connection: " << strerror(errno);
        ::close(uds_conn_fd_);
        exit(EXIT_FAILURE);
    }

    int flags = fcntl(uds_conn_fd_, F_GETFL, 0);
    if (flags < 0) {
        LOG(ERROR) << "Failed to get socket flags: " << strerror(errno);
        ::close(uds_conn_fd_);
        exit(EXIT_FAILURE);
    }

    if (fcntl(uds_conn_fd_, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG(ERROR) << "Failed to set socket to non-blocking: " << strerror(errno);
        ::close(uds_conn_fd_);
        exit(EXIT_FAILURE);
    }

    LOG(INFO) << "Accept UDS "<< uds_conn_fd_ << " connection success";

    // Call AcceptShmConnection() HERE, before shm_sock is used for FIFO paths
    AcceptShmConnection();

    LOG(INFO) << "Listening UDS " << uds_path_ << " opened with fd: " << uds_conn_fd_;

    try {
        shm_fifo_handler_ = std::make_unique<LocalFifoEventHandler>(currentEvb, this);
        // 1. 先调用 changeHandlerFD 设置要监听的文件描述符
        shm_fifo_handler_->changeHandlerFD(folly::NetworkSocket::fromFd(uds_conn_fd_));
        // 2. 然后再调用 registerHandler 注册事件
        shm_fifo_handler_->registerHandler(folly::EventHandler::READ | folly::EventHandler::PERSIST);
        LOG(INFO) << "Event handler registered for listening UDS fd: " << uds_conn_fd_;
    } catch (const std::exception& e) {
        LOG(ERROR) << "Exception while setting up event handler for listening UDS: " << e.what();
        exit(EXIT_FAILURE);
    }

    currentEvb->loopForever();

    // loop until Ctrl+D
    //generateRequests(1);

    LOG(INFO) << "EchoClient stopping client";
  }

  ~ShmMdlwClient() override = default;

 private:

  [[nodiscard]] quic::StreamGroupId getNextGroupId() {
    return streamGroups_[(curGroupIdIdx_++) % kNumTestStreamGroups];
  }

  void pushMessage(quic::StreamId id, BufQueue& data, size_t idx, int64_t connId, uint64_t maxToSend) {
    const folly::IOBuf* currentData = data.front();
    size_t dataLen = currentData->computeChainDataLength();
    size_t lenToSend = std::min(dataLen, maxToSend);
    
    auto message = currentData->clone();
    message->trimEnd(dataLen - lenToSend);

    auto quicClient_ = connManager_->getConnection(connId);
    auto res = quicClient_->writeChain(id, std::move(message), false);
    if(res.hasError()){
      LOG(ERROR) << "EchoClient writeChain error=" << uint32_t(res.error());
    }else{
      data.trimStart(lenToSend);
      sendOffsets_[connId][id] += lenToSend;
      if(!data.empty()){
        quicClient_->notifyPendingWriteOnStream(id, this);
      }
    }
  }

  void sendMessage(quic::StreamId id, BufQueue& data, size_t idx, int64_t connId) {
    auto message = data.move();
    auto quicClient_ = connManager_->getConnection(connId);
    VLOG(2) << "EchoClient " << connId << " wrote idx = \"" << idx << "\" data= " << [&]() {
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');
            auto str = message->clone()->to<std::string>();
            for (size_t i = 0; i < str.length(); ++i) {
                if (i > 0) ss << " ";
                ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(str[i]));
            }
            return ss.str();
        }();

    auto start = std::chrono::steady_clock::now();
    auto res = useDatagrams_
        ? quicClient_->writeDatagram(message->clone())
        : quicClient_->writeChain(id, message->clone(), false);
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient writeChain error=" << uint32_t(res.error());
    } else {
      auto str = message->to<std::string>();
      /*LOG(INFO) << "EchoClient " << connId << " wrote idx = \"" << idx << str << "\""
                << ", len=" << str.size() << " on stream=" << id
                << ", pendingOutput_ queue length=" << pendingOutputs_[connId][id].chainLength();*/
      // sent whole message
      pendingOutputs_[connId].erase(id);
      sendOffsets_[connId][id] += str.size();

      send_count_++;

      if(send_count_ % 100000 == 0){
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        LOG(INFO) << "EchoClient send " << send_count_ << " messages, cost " << duration << "us, average " << duration / send_count_ << "us/message";
      }
    }
  }

  std::shared_ptr<fizz::client::FizzClientContext> createFizzClientContext() {
    auto fizzCLientCtx = std::make_shared<fizz::client::FizzClientContext>();

    // ALPNs.
    fizzCLientCtx->setSupportedAlpns(std::move(alpns_));

    if (!clientCertPath_.empty() && !clientKeyPath_.empty()) {
      // Client cert.
      std::string certData;
      folly::readFile(clientCertPath_.c_str(), certData);
      std::string keyData;
      folly::readFile(clientKeyPath_.c_str(), keyData);
      auto cert = fizz::openssl::CertUtils::makeSelfCert(certData, keyData);

      auto certManager = std::make_shared<fizz::client::CertManager>();
      certManager->addCert(std::move(cert));
      fizzCLientCtx->setClientCertManager(std::move(certManager));
    }

    // Compression settings.
    auto mgr = std::make_shared<fizz::CertDecompressionManager>();
    mgr->setDecompressors(
        {std::make_shared<fizz::ZstdCertificateDecompressor>(),
         std::make_shared<fizz::ZlibCertificateDecompressor>()});
    fizzCLientCtx->setCertDecompressionManager(std::move(mgr));

    return fizzCLientCtx;
  }

  bool timerScheduled_{false};
  std::string host_;
  uint16_t port_;
  uint16_t duration_;
  bool useDatagrams_;
  uint64_t activeConnIdLimit_;
  bool enableMigration_;
  bool enableStreamGroups_;
  bool running_ = true;
  std::map<uint64_t, std::map<quic::StreamId, BufQueue>> pendingOutputs_;
  std::map<uint64_t, std::map<quic::StreamId, uint64_t>> recvOffsets_;
  std::map<uint64_t, std::map<quic::StreamId, uint64_t>> sendOffsets_;
  uint64_t lastSendOffsets_{0};
  uint64_t lastRecvOffsets_{0};
  std::map<uint64_t, volatile bool> activePath_;
  folly::fibers::Baton startDone_;
  std::array<StreamGroupId, kNumTestStreamGroups> streamGroups_;
  size_t curGroupIdIdx_{0};
  std::vector<std::string> alpns_;
  bool connectOnly_{false};
  std::string clientCertPath_;
  std::string clientKeyPath_;
  std::string fileName_;
  std::string frameLabel_;
  std::shared_ptr<CliConnection> connManager_;
  struct mptcp_sock* mptcp_sock_;
  client_info_t *client_info_{nullptr};
  
  int uds_conn_fd_{-1};
  const std::string uds_path_{"127.0.0.1"};
  std::shared_ptr<FollyQuicEventBase> shmEvb_{nullptr};
  std::unique_ptr<folly::EventHandler> shm_fifo_handler_{nullptr};
  uint64_t batch_num_{0};
  size_t batch_bytes_{0};
  uint64_t request_shm_counts_{0};
  uint64_t response_shm_counts_{0};
  ssize_t *notify_buffer_{nullptr};
  ssize_t *recv_length_{nullptr};
  uint64_t send_count_{0};
};

} // namespace quic::opv_shm
