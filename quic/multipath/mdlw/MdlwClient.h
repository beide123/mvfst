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

#include <glog/logging.h>

#include <folly/FileUtil.h>
#include <folly/fibers/Baton.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/compression/ZlibCertificateDecompressor.h>
#include <fizz/compression/ZstdCertificateDecompressor.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/multipath/mdlw/LogQuicStats.h>

namespace quic::multipath {

constexpr size_t kNumTestStreamGroups = 2;

size_t fileCounter = 0;

class MdlwClient :  public quic::QuicSocket::ConnectionSetupCallback,
                   public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback,
                   public quic::QuicSocket::WriteCallback,
                   public quic::QuicSocket::DatagramCallback,
                   folly::HHWheelTimer::Callback {
 public:
  MdlwClient(
      const std::string& host,
      uint16_t port,
      uint16_t duration,
      std::chrono::milliseconds transportTimerResolution,
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
        fEvb_(transportTimerResolution),
        duration_(duration),
        useDatagrams_(useDatagrams),
        activeConnIdLimit_(activeConnIdLimit),
        enableMigration_(enableMigration),
        enableStreamGroups_(enableStreamGroups),
        alpns_(std::move(alpns)),
        connectOnly_(connectOnly),
        clientCertPath_(clientCertPath),
        clientKeyPath_(clientKeyPath) {}

  void readAvailable(quic::StreamId streamId) noexcept override {
    LOG(INFO) << "EchoClient readAvailable streamId=" << streamId;
  }

  void readAvailable(quic::StreamId streamId, int64_t connId) noexcept override {
    auto quicClient_ = connManager_->getConnection(connId);
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }
    bool eof = readData->second;
    auto copy = readData->first.get();

    size_t dataLength = copy->length();

    std::string filePath;

    if (recvOffsets_[connId].find(streamId) == recvOffsets_[connId].end()) {
        recvOffsets_[connId][streamId] = 0; // 初始化
        // 创建文件
        filePath = "./received_data_" + std::to_string(connId) + ".txt";
        std::ofstream file(filePath, std::ios::binary);
        if (!file) {
            LOG(ERROR) << "Failed to open file for writing: " << filePath;
            return;
        }
        file.close();
    }

    auto current = copy;
    while (current){
        size_t dataLength = current->length();

        if(dataLength > 0){
            // 将数据追加到文件中
            // **遍历整个 IOBuf 链，逐块写入数据**
            size_t written = 0;
            filePath = "./received_data_conn" + std::to_string(connId) + ".txt";
            std::ofstream file(filePath, std::ios::binary | std::ios::app);
            if (!file) {
              LOG(ERROR) << "Failed to open file for appending: " << filePath;
              return;
            }
            
            file.write(reinterpret_cast<const char*>(current->data()), dataLength);
            written += dataLength;

            file.close();
            // 更新偏移量
            recvOffsets_[connId][streamId] += written;
        
            //LOG(INFO) << "Stream " << streamId << ": Successfully wrote " << written << " bytes.";
            /*LOG(INFO) << "Client received data on stream=" << streamId
                      << ", total received=" << recvOffsets_[streamId] << " bytes";*/
            
        }else{
            // 创建新文件
            filePath = "./received_data_" + std::to_string(fileCounter++) + "_new.txt";
            std::ofstream newFile(filePath, std::ios::binary);
            if (!newFile) {
                LOG(ERROR) << "Failed to open new file for writing: " << filePath;
                return;
            }
            newFile.close();
        }

        if (current->next() == copy) { // 避免循环链
            break;
        }
        
        current = current->next();

    }
    
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

  void timeoutExpired() noexcept override {
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
    LOG(INFO) << "EchoClient connection end";
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

  /*void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "EchoClient socket is write ready with maxToSend="
              << maxToSend;
    sendMessage(id, pendingOutput_[id], 0);
  }*/

  void onMultiStreamWriteReady(int64_t connId, quic::StreamId id, uint64_t maxToSend) noexcept
    override {
    sendMessage(id, pendingOutputs_[connId][id], 0, connId);
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

  void generateRequests(size_t numRequests) {
    size_t i = 0;
    
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
      // 设置流的读回调
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
    
    auto start = std::chrono::steady_clock::now();

    std::string url = "https://" + host_ + "/BBRtestfile_1000M"; //+ std::to_string(i);
    std::string request = "GET " + url + " HTTP/1.1\r\nHost: " + host_ + "\r\n\r\n";
    
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < duration_) {
        size_t batchStart = i;
       
        while (i < numRequests && i < batchStart + 1000) {
            // 构造请求内容
            auto client_pair = connManager_->getBestConnection();
            auto connId = client_pair.first;
            auto client = client_pair.second;
            if (!client) {
              LOG(ERROR) << "No available connection to send data";
              return;
            }
            auto streamId = connManager_->getClientStream(connId);
            //LOG(INFO) << "Submitting task: index=" << i;
            // 将发送任务交给 EventBaseThread
            client->getEventBase()->runInEventBaseThread([this, request = std::move(request), connId, i, streamId]() {
                // 保存请求内容到待发送的 map
                auto& pendingOutput_ = pendingOutputs_[connId];
                pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(request));

                // 实际发送请求
                sendMessage(streamId, pendingOutput_[streamId], i, connId);
            });
            ++i;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 每批发送后等待10ms
        if (std::cin.eof()) {
          break; // 退出循环
        }
    }
  }

  size_t calculateThroughput(std::chrono::steady_clock::time_point& lastTime, size_t& lastTotalBytes, size_t& lastTotalBytes_conn0, size_t& lastTotalBytes_conn1) {
    auto currentTime = std::chrono::steady_clock::now();
    size_t currentTotalBytes_conn0 = 0;
    size_t currentTotalBytes_conn1 = 0;

    currentTotalBytes_conn0 += recvOffsets_[0][0];
    currentTotalBytes_conn1 += recvOffsets_[1][0];
    size_t currentTotalBytes = currentTotalBytes_conn0 + currentTotalBytes_conn1;

    // 计算时间差
    std::chrono::duration<double> elapsed = currentTime - lastTime;

    // 每秒打印吞吐量
    if (elapsed.count() >= 1.0) {
        float throughput = (float)(currentTotalBytes - lastTotalBytes) * 8 / 1024 / 1024; // 当前秒的吞吐量，换算成Mbps
        float throughput_conn0 = (float)(currentTotalBytes_conn0 - lastTotalBytes_conn0) * 8 / 1024 / 1024; // 当前秒的吞吐量，换算成Mbps
        float throughput_conn1 = (float)(currentTotalBytes_conn1 - lastTotalBytes_conn1) * 8 / 1024 / 1024; // 当前秒的吞吐量，换算成Mbps
        LOG(INFO) << "The Download Throughput: " << throughput << " Mbps\n"
                  << " -----conn0: " << throughput_conn0 << " Mbps\n"
                  << " -----conn1: " << throughput_conn1 << " Mbps\n";
        // 更新上一次的字节数和时间
        lastTotalBytes = currentTotalBytes;
        lastTotalBytes_conn0 = currentTotalBytes_conn0;
        lastTotalBytes_conn1 = currentTotalBytes_conn1;
        lastTime = currentTime;
    }
    return 0; 
  }

  void start(std::string token) {
    folly::ScopedEventBaseThread networkThread("EchoClientThread");
    auto evb = networkThread.getEventBase();
    auto qEvb = std::make_shared<FollyQuicEventBase>(evb);

    connManager_ = std::make_shared<ConnectionManager>(100);
    

    std::vector<folly::SocketAddress> localAddresses; // store different local addresses
    
    for (int i = 0; i < 2; ++i) {
      folly::SocketAddress localAddr("30.1." + std::to_string(i + 2) + ".100", 6666); // bind to different interface port
      localAddresses.push_back(localAddr);
    }

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

        settings.shouldUseRecvmmsgForBatchRecv = true;
        
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

    startDone_.wait();

    // loop until Ctrl+D
    generateRequests(1);

    LOG(INFO) << "EchoClient stopping client";
  }

  ~MdlwClient() override = default;

 private:

  [[nodiscard]] quic::StreamGroupId getNextGroupId() {
    return streamGroups_[(curGroupIdIdx_++) % kNumTestStreamGroups];
  }

  void sendMessage(quic::StreamId id, BufQueue& data, size_t idx, int64_t connId) {
    auto message = data.move();
    auto quicClient_ = connManager_->getConnection(connId);
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
  folly::fibers::Baton startDone_;
  std::array<StreamGroupId, kNumTestStreamGroups> streamGroups_;
  size_t curGroupIdIdx_{0};
  std::vector<std::string> alpns_;
  bool connectOnly_{false};
  std::string clientCertPath_;
  std::string clientKeyPath_;
  folly::Synchronized<std::queue<std::string>> taskQueue_;
  folly::EventBase fEvb_;
  std::shared_ptr<ConnectionManager> connManager_;
};
} // namespace quic::samples
