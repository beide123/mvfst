/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocket.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/common/BufUtil.h>

#include <shm_sock.h>

#include <future>
#include <random>
#include <semaphore.h>
#include <fstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <folly/io/async/EventHandler.h>

namespace quic::opv_shm {

class DlwHandler : public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback,
                    public quic::QuicSocket::DatagramCallback {
 public:
  using StreamData = std::pair<BufQueue, bool>;

  explicit DlwHandler(
      folly::EventBase* evbIn,
      bool useDatagrams = false,
      bool disableRtx = false)
      : evb(evbIn), useDatagrams_(useDatagrams), disableRtx_(disableRtx) {}

  void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
    sock = socket;
    if (useDatagrams_) {
      auto res = sock->setDatagramCallback(this);
      CHECK(res.hasValue()) << res.error();
    }
  }

  void setHandlers(folly::Synchronized<std::vector<std::unique_ptr<DlwHandler>>>* handlers, struct mptcp_sock* mptcp_sock) {
    handlers_ = handlers;
    mptcp_sock_ = mptcp_sock;
  }

  class FifoEventHandler : public folly::EventHandler {
    public:
      explicit FifoEventHandler(folly::EventBase* evb, DlwHandler* handler)
          : folly::EventHandler(evb), handler_(handler) {}

      void handlerReady(uint16_t events) noexcept override {
        if (events & folly::EventHandler::READ) {
          handler_->handleFifoReadEvent();
        }
      }

    private:
      DlwHandler* handler_;
  };

  void setShmConfig(int64_t client_id, std::shared_ptr<client_info_t> client_info, int shm_fifo_write_fd, int shm_fifo_read_fd){
    client_info_ = client_info;
    shm_fifo_write_fd_ = shm_fifo_write_fd;
    shm_fifo_read_fd_ = shm_fifo_read_fd;
    connId_ = client_id;

    // 5. Register the event handler for the listen FIFO
    try {
        shm_fifo_read_handler_ = std::make_unique<FifoEventHandler>(evb, this);
        shm_fifo_read_handler_->changeHandlerFD(folly::NetworkSocket::fromFd(shm_fifo_read_fd_));
        shm_fifo_read_handler_->registerHandler(folly::EventHandler::READ | folly::EventHandler::PERSIST);
        LOG(INFO) << "Event handler registered for listen FIFO fd: " << shm_fifo_read_fd_;
    } catch (const std::exception& e) {
        LOG(ERROR) << "Exception while setting up event handler for listening FIFO: " << e.what();
        // Consider this a fatal error for this handler's SHM functionality
        return;
    }

  }

  void handleFifoReadEvent() {
      VLOG(4) << "Fifo read event triggered.";
      const size_t bufferSize = 1024;
              
      std::vector<char> buffer(bufferSize);

      size_t headerSize = strlen("Frame") + sizeof(uint64_t) + sizeof(size_t);

      std::streamsize toatlBytes = 0;

      auto connManager = std::dynamic_pointer_cast<SrvConnection>(mptcp_sock_->connManager);

      std::shared_ptr<quic::QuicSocket> dis_sock;
      
      // 1. Read the notification byte from the listen FIFO to clear the event
      ssize_t bytes_read = ::read(shm_fifo_read_fd_, recv_length_, sizeof(ssize_t));
      if (bytes_read <= 0) {
          if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
              // This can happen, just wait for the next event
              return;
          }
          LOG(ERROR) << "Failed to read from listen FIFO or peer closed. Error: " << strerror(errno);
          // Consider unregistering the handler here if the pipe is broken
          return;
      }


      // 2. Read the request data from shared memory
      if (!client_info_) {
          LOG(ERROR) << "client_info is null, cannot read from SHM.";
          return;
      }

      size_t len = *recv_length_;
      ssize_t shm_bytes_read = shm_read(client_info_->shm_sock, client_info_->recv_buff, len);
      if (shm_bytes_read <= 0) {
          LOG(ERROR) << "shm_read failed or returned 0 bytes.";
          return;
      }
      client_info_->recv_buff[shm_bytes_read] = '\0'; // Null-terminate the string

      char* rspbuf = new char[headerSize + bufferSize];

      auto sequenceNumber = connManager->getSequenceNumber();

      memcpy(rspbuf, "FRAME", strlen("FRAME"));
      memcpy(rspbuf + strlen("FRAME"), &sequenceNumber, sizeof(uint64_t));

      memcpy(rspbuf + strlen("FRAME") + sizeof(sequenceNumber), &shm_bytes_read, sizeof(size_t));

      memcpy(rspbuf + headerSize, client_info_->recv_buff, shm_bytes_read);

      auto rsp = folly::IOBuf::copyBuffer(rspbuf, headerSize + shm_bytes_read);

      auto connPair = connManager->getBestConnection();
      auto connId = connPair.first;
      dis_sock = connPair.second;

      // 3. Find an active stream to send the data on.
      // This logic might need to be adapted based on how you manage streams.
      // For now, we'll assume there's a known stream ID stored in client_info.
      
      quic::StreamId id = connManager->getClientStream(connId);

      auto start_time = std::chrono::steady_clock::now();

      VLOG(5) << "Sequence Number: " << *reinterpret_cast<const uint64_t*>(rspbuf + strlen("FRAME")) 
      << "Offset: " << *reinterpret_cast<const size_t*>(rspbuf + strlen("FRAME") + sizeof(uint64_t));
      
      auto res = dis_sock->writeChain(id, std::move(rsp), false, nullptr);
      while(res.hasError()) {
          LOG(INFO) << "Writing file chunk to " << dis_sock->getPeerAddress().describe();
          LOG(ERROR) << "Write error: " << toString(res.error());
          auto rw = folly::IOBuf::copyBuffer(rspbuf, headerSize + shm_bytes_read);
          res = sock->writeChain(id, std::move(rw), false, nullptr);
          auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time);
          if (elapsed.count() >= 2) {
              LOG(ERROR) << "Timeout: failed to write file chunk after 2 seconds";
              return; // Exit the loop if timeout
          }
      }
      toatlBytes += shm_bytes_read;
      currentBytes_ += shm_bytes_read;
      connManager->setSequenceNumber(sequenceNumber + 1);
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id;
    sock->setReadCallback(id, this);
  }

  void onMultiNewBidirectionalStream(int64_t connId, quic::StreamId id) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id;
  }

  void onNewBidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got bidirectional stream group id=" << groupId;
    CHECK(streamGroupsData_.find(groupId) == streamGroupsData_.cend());
    streamGroupsData_.emplace(groupId, PerStreamData{});
    if (disableRtx_) {
      QuicStreamGroupRetransmissionPolicy policy;
      policy.disableRetransmission = true;
      sock->setStreamGroupRetransmissionPolicy(groupId, policy);
    }
  }

  void onNewBidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id
              << " in group=" << groupId;
    sock->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got unidirectional stream id=" << id;
    sock->setReadCallback(id, this);
  }

  void onNewUnidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got unidirectional stream group id=" << groupId;
    CHECK(streamGroupsData_.find(groupId) == streamGroupsData_.cend());
    streamGroupsData_.emplace(groupId, PerStreamData{});
  }

  void onNewUnidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "Got unidirectional stream id=" << id
              << " in group=" << groupId;
    sock->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    LOG(INFO) << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "Socket closed";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "Socket error=" << toString(error.code) << " "
               << error.message;
  }

  DlwHandler* getAvailableHandlers() {
    DlwHandler* selected = this;
    if (handlers_) {
      handlers_->withRLock([&](const auto& handlers) {
        if (!handlers.empty()) {
          thread_local std::random_device rd;
          thread_local std::mt19937 gen(rd());
          std::uniform_int_distribution<size_t> dist(0, handlers.size() - 1);
                    // 在锁的范围内获取选定的 handler
          selected = handlers[dist(gen)].get();
        }
      });
    }
    return selected;
  }

  void readAvailable(quic::StreamId id) noexcept override {
    //LOG(INFO) << "read available for stream id=" << id;

    auto res = sock->read(id, 0);
    if (res.hasError()) {
      LOG(ERROR) << "Got error=" << toString(res.error());
      sock->setReadCallback(id, nullptr);
      return;
    }
    if (input_.find(id) == input_.end()) {
      input_.emplace(id, std::make_pair(BufQueue(), false));
    }
    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    VLOG(1) << "Got len=" << dataLen << " eof=" << uint32_t(eof)
              << " total=" << input_[id].first.chainLength() + dataLen;
    VLOG(2) << " data="
            << ((data) ? data->clone()->to<std::string>() : std::string());
    input_[id].first.append(std::move(data));
    input_[id].second = eof;
    if (dataLen > 0) {
      //echo(id, input_[id]);
      //handleMP4Request(id, input_[id]);
      handleReqToShm(id, input_[id]);
      //LOG(INFO) << "uninstalling read callback";
      //sock->setReadCallback(id, this);
    }
  }

  void readAvailable(quic::StreamId id, int64_t connId) noexcept override {
    LOG(INFO) << "read available for stream id=" << id << " connId=" << connId;
  }

  void readAvailableWithGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "read available for stream id=" << id
              << "; groupId=" << groupId;

    auto it = streamGroupsData_.find(groupId);
    CHECK(it != streamGroupsData_.end());

    auto res = sock->read(id, 0);
    if (res.hasError()) {
      LOG(ERROR) << "Got error=" << toString(res.error());
      return;
    }

    auto& streamData = it->second;
    if (streamData.find(id) == streamData.end()) {
      streamData.emplace(id, std::make_pair(BufQueue(), false));
    }

    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    LOG(INFO) << "Got len=" << dataLen << " eof=" << uint32_t(eof)
              << " total=" << input_[id].first.chainLength() + dataLen
              << " data="
              << ((data) ? data->clone()->to<std::string>() : std::string());

    streamData[id].first.append(std::move(data));
    streamData[id].second = eof;
    if (eof) {
      echo(id, streamData[id]);
    }
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id
               << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void readErrorWithGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId,
      QuicError error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id << "; group=" << groupId
               << " error=" << toString(error);
  }

  void onDatagramsAvailable() noexcept override {
    auto res = sock->readDatagrams();
    if (res.hasError()) {
      LOG(ERROR) << "readDatagrams() error: " << res.error();
      return;
    }
    LOG(INFO) << "received " << res->size() << " datagrams";
    echoDg(std::move(res.value()));
  }

  void onDatagramsAvailable(int64_t connId) noexcept override {
    LOG(INFO) << "Datagrams available for connId=" << connId;
  } 

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "socket is write ready with maxToSend=" << maxToSend;
    echo(id, input_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "write error with stream=" << id
               << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb;
  }

  folly::EventBase* evb;
  std::shared_ptr<quic::QuicSocket> sock;

 private:
  static int requestCnt;

  void echo(quic::StreamId id, StreamData& data) {
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    auto echoedData = folly::IOBuf::copyBuffer("echo ");
    echoedData->prependChain(data.first.move());
    auto res = sock->writeChain(id, std::move(echoedData), true, nullptr);
    if (res.hasError()) {
      LOG(ERROR) << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  void handleMP4Request(quic::StreamId id, StreamData& data) {

    // 将接收到的数据转换为字符串（假设数据是包含路径的）
    auto receivedData = data.first.move();
    auto eof = data.second;
    // 解析HTTP/1.1格式的receivedData
    std::string httpData = receivedData->moveToFbString().toStdString();
    size_t pos = 0;
    size_t act = 0, start = 0;
    std::string filePath;

    if(firstRequest_){
        firstRequest_ = false;
        startThroughputThread();
    }

    while((pos = httpData.find("\r\n\r\n", start)) != std::string::npos){
        std::string requestData = httpData.substr(start, pos - start + 4);
        start = pos + 4;
        
        std::istringstream iss(requestData);
        std::string firstLine;
        std::getline(iss, firstLine);
        
        std::string requestType;
        std::istringstream issFirstLine(firstLine);
        issFirstLine >> requestType;
        
        if(requestType == "ACTIVATE"){
            LOG(INFO) << "ACTIVATE request from " << sock->getPeerAddress().describe() << " received";
            auto rsp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            auto rspBuf = folly::IOBuf::copyBuffer(rsp);
            auto res = sock->writeChain(id, std::move(rspBuf), false, nullptr);
            if (res.hasError()) {
                LOG(ERROR) << "Error sending EOF: " << toString(res.error());
            }else{
                LOG(INFO) << "ACTIVATE request completed";
            }
        }else if (requestType == "GET") {
            // 提取url
            std::string url;
            issFirstLine >> url;

            const std::string prefix = "https://" + sock->getLocalAddress().getAddressStr() + "/";
            if (url.find(prefix) != 0) {
                LOG(ERROR) << "Invalid request URL: " << url;
                auto errorResponse = folly::IOBuf::copyBuffer("Invalid MP4 request");
                sock->writeChain(id, std::move(errorResponse), true, nullptr);
                continue;
            }
            
            filePath = url.substr(prefix.size());
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                LOG(ERROR) << "Failed to open file: " << filePath;
                auto errorResponse = folly::IOBuf::copyBuffer("File not found");
                sock->writeChain(id, std::move(errorResponse), true, nullptr);
                continue;
            }

            const size_t bufferSize = 1024;
            uint64_t sequenceNumber = 0;
            
            std::vector<char> buffer(bufferSize);
           
            size_t headerSize = strlen("Frame") + sizeof(uint64_t) + sizeof(size_t);

            std::streamsize toatlBytes = 0;

            auto connManager = std::dynamic_pointer_cast<SrvConnection>(mptcp_sock_->connManager);

            std::shared_ptr<quic::QuicSocket> dis_sock;

            while (file) {
               
                char* rspbuf = new char[headerSize + bufferSize];

                memcpy(rspbuf, "FRAME", strlen("FRAME"));
                memcpy(rspbuf + strlen("FRAME"), &sequenceNumber, sizeof(uint64_t));

                // 复制偏移量
                file.read(rspbuf + headerSize, bufferSize);
                std::streamsize bytesRead = file.gcount();

                memcpy(rspbuf + strlen("FRAME") + sizeof(sequenceNumber), &bytesRead, sizeof(size_t));

                auto rsp = folly::IOBuf::copyBuffer(rspbuf, headerSize + bytesRead);
                
                if (bytesRead > 0) {
                    dis_sock = connManager->getBestConnection().second;
                    auto start_time = std::chrono::steady_clock::now();
                    VLOG(5) << "Sequence Number: " << *reinterpret_cast<const uint64_t*>(rspbuf + strlen("FRAME")) 
                    << "Offset: " << *reinterpret_cast<const size_t*>(rspbuf + strlen("FRAME") + sizeof(uint64_t));
                    
                    auto res = dis_sock->writeChain(id, std::move(rsp), false, nullptr);
                    while(res.hasError()) {
                        LOG(INFO) << "Writing file chunk to " << dis_sock->getPeerAddress().describe();
                        LOG(ERROR) << "Write error: " << toString(res.error());
                        auto rw = folly::IOBuf::copyBuffer(rspbuf, headerSize + bytesRead);
                        res = sock->writeChain(id, std::move(rw), false, nullptr);
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time);
                        if (elapsed.count() >= 2) {
                            LOG(ERROR) << "Timeout: failed to write file chunk after 2 seconds";
                            return; // Exit the loop if timeout
                        }
                    }
                    toatlBytes += bytesRead;
                    currentBytes_ += bytesRead;
                    sequenceNumber++;
                }
            }

            LOG(INFO) << " file send totalBytes: " << toatlBytes;

            /*auto eof = folly::IOBuf::create(0);
            //eof->append(0);
            auto res = sock->writeChain(id, std::move(eof), false, nullptr);
            if (res.hasError()) {
                LOG(ERROR) << "Error sending EOF: " << toString(res.error());
            }else{
                //LOG(INFO) << "file download completed: " << filePath;
                VLOG(4) << "Sent " << toatlBytes << " bytes of file data for request " << ++requestCnt;
            }*/
        }else{
            LOG(ERROR) << "Invalid request type: " << requestType;
            continue;
        }
        
    }
    
    if (eof) {
        auto eof = folly::IOBuf::create(0);
        auto res = sock->writeChain(id, std::move(eof), true, nullptr);
        if (res.hasError()) {
            LOG(ERROR) << "Error sending EOF: " << toString(res.error());
        }else{
            LOG(INFO) << "file download completed: " << filePath;
        }
    }

    // 清除 EOF 标志
    data.second = false;
  }

  void shmRecv(quic::StreamId id) {
    size_t bytesRead = 0;
    const size_t bufferSize = 1024;
    uint64_t sequenceNumber = 0;
            
    std::vector<char> buffer(bufferSize);

    size_t headerSize = strlen("Frame") + sizeof(uint64_t) + sizeof(size_t);

    std::streamsize toatlBytes = 0;

    auto connManager = std::dynamic_pointer_cast<SrvConnection>(mptcp_sock_->connManager);

    std::shared_ptr<quic::QuicSocket> dis_sock;
    while(1){
        sem_wait(sem_w_);
        
        bytesRead = shm_read(client_info_->shm_sock, client_info_->recv_buff, sizeof(client_info_->recv_buff));
        if(bytesRead < 0){
            perror("shm_read failed");
            break;
        }
        VLOG(5) << "Server read request " << client_info_->recv_buff << " from shm.";

        if(bytesRead == 3 && client_info_->recv_buff[0] == 'E'){
            if(strncmp(client_info_->recv_buff, "EOF", bytesRead) == 0){
                LOG(INFO) << "End of file received";
                break;
            }
        }

        char* rspbuf = new char[headerSize + bufferSize];

        memcpy(rspbuf, "FRAME", strlen("FRAME"));
        memcpy(rspbuf + strlen("FRAME"), &sequenceNumber, sizeof(uint64_t));

        memcpy(rspbuf + strlen("FRAME") + sizeof(sequenceNumber), &bytesRead, sizeof(size_t));

        memcpy(rspbuf + headerSize, client_info_->recv_buff, bytesRead);

        auto rsp = folly::IOBuf::copyBuffer(rspbuf, headerSize + bytesRead);

        dis_sock = connManager->getBestConnection().second;

        auto start_time = std::chrono::steady_clock::now();

        VLOG(5) << "Sequence Number: " << *reinterpret_cast<const uint64_t*>(rspbuf + strlen("FRAME")) 
        << "Offset: " << *reinterpret_cast<const size_t*>(rspbuf + strlen("FRAME") + sizeof(uint64_t));
        
        auto res = dis_sock->writeChain(id, std::move(rsp), false, nullptr);
        while(res.hasError()) {
            LOG(INFO) << "Writing file chunk to " << dis_sock->getPeerAddress().describe();
            LOG(ERROR) << "Write error: " << toString(res.error());
            auto rw = folly::IOBuf::copyBuffer(rspbuf, headerSize + bytesRead);
            res = sock->writeChain(id, std::move(rw), false, nullptr);
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time);
            if (elapsed.count() >= 2) {
                LOG(ERROR) << "Timeout: failed to write file chunk after 2 seconds";
                return; // Exit the loop if timeout
            }
        }
        toatlBytes += bytesRead;
        currentBytes_ += bytesRead;
        sequenceNumber++;
        
    }
  }

  void SendDataToApp(const char* data, size_t dataLength) {
    // Safely write the data to shared memory
    ssize_t send_bytes = shm_write(client_info_->shm_sock, data, dataLength);
    
    if (send_bytes < 0) {
        LOG(ERROR) << "Send request to shm failed: " << strerror(errno);
        return; // Exit on failure
    }

    if (static_cast<size_t>(send_bytes) != dataLength) {
        LOG(WARNING) << "Partial write to shm. Wrote " << send_bytes << " of " << dataLength;
    }
  
    VLOG(1) << "Send " << send_bytes << " bytes request to shm success. Notifying other process.";

    std::atomic_thread_fence(std::memory_order_release);

    memset(notify_buffer_, 0, sizeof(ssize_t));

    *notify_buffer_ = send_bytes; // 'R' for Request
    if (::write(shm_fifo_write_fd_, notify_buffer_, sizeof(ssize_t)) <= 0) {
        LOG(ERROR) << "Failed to write notification to FIFO '"
                    << shm_fifo_write_fd_ << "'. Error: " << strerror(errno);
    }
  }

  void handleReqToShm(quic::StreamId id, StreamData& data) {
      // 将接收到的数据转换为字符串（假设数据是包含路径的）
      auto receivedData = data.first.move();
      auto eof = data.second;
      // 解析HTTP/1.1格式的receivedData
      std::string httpData = receivedData->moveToFbString().toStdString();

      auto connManager = std::dynamic_pointer_cast<SrvConnection>(mptcp_sock_->connManager);

      if(firstRequest_){
        firstRequest_ = false;
        auto connManager = std::dynamic_pointer_cast<SrvConnection>(mptcp_sock_->connManager);
        connManager->buildClientStreamsMap(connId_, id);
        connManager->setDataCallback([this](const char* data, size_t dataLength) {
          this->SendDataToApp(data, dataLength);
        });
        startThroughputThread();
      }

      size_t pos = 0;
      size_t act = 0, start = 0;

      const std::string activateHeader = "ACTIVATE\r\n\r\n";

      if (httpData.rfind(activateHeader, 0) == 0) {
        LOG(INFO) << "ACTIVATE request from " << sock->getPeerAddress().describe() << " received";
        auto rsp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        auto rspBuf = folly::IOBuf::copyBuffer(rsp);
        auto res = sock->writeChain(id, std::move(rspBuf), false, nullptr);
        if (res.hasError()) {
            LOG(ERROR) << "Error sending ACTIVATE response: " << toString(res.error());
        } else {
            LOG(INFO) << "ACTIVATE request completed";
        }
        // Advance position past the header
        pos = activateHeader.length();
      }

      if (pos < httpData.length()) {
        std::string requestData = httpData.substr(pos);
        
        // Safely write the data to shared memory
        /*ssize_t send_bytes = shm_write(client_info_->shm_sock, requestData.c_str(), requestData.length());
        
        if (send_bytes < 0) {
            LOG(ERROR) << "Send request to shm failed: " << strerror(errno);
            return; // Exit on failure
        }

        if (static_cast<size_t>(send_bytes) != requestData.length()) {
            LOG(WARNING) << "Partial write to shm. Wrote " << send_bytes << " of " << requestData.length();
        }
      
        VLOG(1) << "Send " << send_bytes << " bytes request to shm success. Notifying other process.";

        std::atomic_thread_fence(std::memory_order_release);

        *notify_buffer_ = send_bytes; // 'R' for Request
        if (::write(uds_conn_fd_, notify_buffer_, sizeof(ssize_t)) <= 0) {
            LOG(ERROR) << "Failed to write notification to FIFO '"
                        << uds_conn_fd_ << "'. Error: " << strerror(errno);
        }*/

        auto rsp = folly::IOBuf::copyBuffer(requestData.c_str(), requestData.length());
        VLOG(1) << "Merge " << requestData.length() << " bytes data " << " to connManager";
        connManager->mergeData(rsp.get(), requestData.length(), connId_, frameLabel_);
        
        currentBytes_ += requestData.length();
      }

  }


  void handleShmRequest(quic::StreamId id, StreamData& data) {

    // 将接收到的数据转换为字符串（假设数据是包含路径的）
    auto receivedData = data.first.move();
    auto eof = data.second;
    // 解析HTTP/1.1格式的receivedData
    std::string httpData = receivedData->moveToFbString().toStdString();
    size_t pos = 0;
    size_t act = 0, start = 0;
    std::string filePath;

    if(firstRequest_){
        firstRequest_ = false;
        startThroughputThread();
    }

    client_info_->stream_id = id;

    while((pos = httpData.find("\r\n\r\n", start)) != std::string::npos){
        std::string requestData = httpData.substr(start, pos - start + 4);
        start = pos + 4;
        
        std::istringstream iss(requestData);
        std::string firstLine;
        std::getline(iss, firstLine);
        
        std::string requestType;
        std::istringstream issFirstLine(firstLine);
        issFirstLine >> requestType;
        
        if(requestType == "ACTIVATE"){
            LOG(INFO) << "ACTIVATE request from " << sock->getPeerAddress().describe() << " received";
            auto rsp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            auto rspBuf = folly::IOBuf::copyBuffer(rsp);
            auto res = sock->writeChain(id, std::move(rspBuf), false, nullptr);
            if (res.hasError()) {
                LOG(ERROR) << "Error sending EOF: " << toString(res.error());
            }else{
                LOG(INFO) << "ACTIVATE request completed";
            }
        }else if (requestType == "GET") {
            snprintf(client_info_->send_buff, sizeof(client_info_->send_buff), "%s", requestData.c_str());

            ssize_t send_bytes = -1;
            send_bytes = shm_write(client_info_->shm_sock, client_info_->send_buff, requestData.length());
            if (send_bytes < 0) {
                if (send_bytes == -1) {
                    LOG(ERROR) << "Send request to shm failed";
                    break;  // 发送失败，退出循环
                } else if (send_bytes == -2) {
                    // 这里可以添加一些延时或其他逻辑，等待再次尝试发送
                    LOG(ERROR) << "Send request to shm temporarily failed, retrying...";
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            } else {
                VLOG(1) << "Send request to shm success";
                sem_post(sem_r_);  // 发送成功后，发布信号量
            }

            shmRecv(id);

        }else{
            LOG(ERROR) << "Invalid request type: " << requestType;
            continue;
        }
        
    }
    
    if (eof) {
        auto eof = folly::IOBuf::create(0);
        auto res = sock->writeChain(id, std::move(eof), true, nullptr);
        if (res.hasError()) {
            LOG(ERROR) << "Error sending EOF: " << toString(res.error());
        }else{
            LOG(INFO) << "file download completed: " << filePath;
        }
    }

    // 清除 EOF 标志
    data.second = false;
  }

  void echoDg(std::vector<quic::ReadDatagram> datagrams) {
    CHECK_GT(datagrams.size(), 0);
    for (const auto& datagram : datagrams) {
      auto echoedData = folly::IOBuf::copyBuffer("echo ");
      echoedData->prependChain(datagram.bufQueue().front()->cloneCoalesced());
      auto res = sock->writeDatagram(std::move(echoedData));
      if (res.hasError()) {
        LOG(ERROR) << "writeDatagram error=" << toString(res.error());
      }
    }
  }

  void calculateThroughput() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      auto throughput = (currentBytes_ - previousBytes_) * 8 / 1024 / 1024; // in MB
      LOG(INFO) << "Current throughput: " << throughput << " MB/s";
      previousBytes_ = currentBytes_;
    }
  }

  std::thread throughputThread;

  void startThroughputThread() {
    throughputThread = std::thread(&DlwHandler::calculateThroughput, this);
  }

  void stopThroughputThread() {
    if (throughputThread.joinable()) {
      throughputThread.join();
    }
  }

  bool useDatagrams_;
  using PerStreamData = std::map<quic::StreamId, StreamData>;
  PerStreamData input_;
  std::map<quic::StreamGroupId, PerStreamData> streamGroupsData_;
  bool disableRtx_{false};
  folly::Synchronized<std::vector<std::unique_ptr<DlwHandler>>>* handlers_;
  static std::mt19937 randomGen_;  // 只声明，不初始化
  bool firstRequest_{true};
  std::streamsize currentBytes_{0};
  std::streamsize previousBytes_{0};

  int64_t connId_{-1};
  std::string frameLabel_{"FRAME"};

  struct mptcp_sock* mptcp_sock_;
  sem_t *sem_r_{nullptr};
  sem_t *sem_w_{nullptr};

  std::shared_ptr<client_info_t> client_info_{nullptr};
  
  int shm_fifo_write_fd_{-1}; // FIFO for writing notifications to the other process
  
  int shm_fifo_read_fd_{-1}; // FIFO for listening for requests from the other process

  ssize_t *notify_buffer_{nullptr};
  ssize_t *recv_length_{nullptr};
  
  // EventHandler for the listening FIFO
  std::unique_ptr<folly::EventHandler> shm_fifo_read_handler_{nullptr};
};

int DlwHandler::requestCnt = 0;  // 在类外初始化静态成员  

} // namespace quic::download
