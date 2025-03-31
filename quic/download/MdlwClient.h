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
#include <quic/download/dlw/LogQuicStats.h>

namespace quic::download {

constexpr size_t kNumTestStreamGroups = 2;

size_t fileCounter = 0;

class DlwClient :  public quic::QuicSocket::ConnectionSetupCallback,
                   public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback,
                   public quic::QuicSocket::WriteCallback,
                   public quic::QuicSocket::DatagramCallback,
                   folly::HHWheelTimer::Callback {
 public:
  DlwClient(
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
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }
    bool eof = readData->second;
    auto copy = readData->first.get();

    size_t dataLength = copy->length();

    std::string filePath;

    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
        recvOffsets_[streamId] = 0; // 初始化
        // 创建文件
        filePath = "./received_data_" + std::to_string(fileCounter++) + ".txt";
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
            /*filePath = "./received_data_" + std::to_string(fileCounter - 1) + ".txt";
            std::ofstream file(filePath, std::ios::binary | std::ios::app);
            if (!file) {
              LOG(ERROR) << "Failed to open file for appending: " << filePath;
              return;
            }
            
            file.write(reinterpret_cast<const char*>(current->data()), dataLength);*/
            written += dataLength;

            //file.close();
            // 更新偏移量
            recvOffsets_[streamId] += written;
        
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
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", groupId=" << groupId
                 << ", error=" << (uint32_t)readData.error();
    }
    auto copy = readData->first->clone();
    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
      recvOffsets_[streamId] = copy->length();
    } else {
      recvOffsets_[streamId] += copy->length();
    }
    LOG(INFO) << "Client received data=" << copy->to<std::string>()
              << " on stream=" << streamId << ", groupId=" << groupId;
  }

  void readError(quic::StreamId streamId, QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient failed read from stream=" << streamId
               << ", error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void timeoutExpired() noexcept override {
    quicClient_->closeNow(none);
  }

  void readErrorWithGroup(
      quic::StreamId streamId,
      quic::StreamGroupId groupId,
      QuicError error) noexcept override {
    LOG(ERROR) << "EchoClient failed read from stream=" << streamId
               << ", groupId=" << groupId << ", error=" << toString(error);
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewBidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream group=" << groupId;
  }

  void onNewBidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream=" << id
              << " in group=" << groupId;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStreamGroup(
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream group=" << groupId;
  }

  void onNewUnidirectionalStreamInGroup(
      quic::StreamId id,
      quic::StreamGroupId groupId) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream=" << id
              << " in group=" << groupId;
    quicClient_->setReadCallback(id, this);
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

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "EchoClient socket is write ready with maxToSend="
              << maxToSend;
    sendMessage(id, pendingOutput_[id], 0);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "EchoClient write error with stream=" << id
               << " error=" << toString(error);
  }

  void onDatagramsAvailable() noexcept override {
    auto res = quicClient_->readDatagrams();
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient failed reading datagrams; error="
                 << res.error();
      return;
    }
    for (const auto& datagram : *res) {
      LOG(INFO)
          << "Client received datagram ="
          << datagram.bufQueue().front()->cloneCoalesced()->to<std::string>();
    }
  }

  void generateRequests(size_t numRequests) {
    size_t i = 0;
    auto streamId = quicClient_->createBidirectionalStream().value();
    // 设置流的读回调
    quicClient_->setReadCallback(streamId, this);
  
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < duration_) {
        size_t batchStart = i;
        while (i < numRequests && i < batchStart + 1000) {
            // 构造请求内容
            std::string url = "https://127.0.0.1/dlw_10k.txt"; //+ std::to_string(i);
            std::string request = "GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
            //LOG(INFO) << "Submitting task: index=" << i;
            // 将发送任务交给 EventBaseThread
            quicClient_->getEventBase()->runInEventBaseThread([this, request = std::move(request), i, streamId]() {
                // 保存请求内容到待发送的 map
                pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(request));

                // 实际发送请求
                sendMessage(streamId, pendingOutput_[streamId], i);
            });
            ++i;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 每批发送后等待10ms
        if (std::cin.eof()) {
          break; // 退出循环
        }
    }
  }

  size_t calculateThroughput(std::chrono::steady_clock::time_point& lastTime, size_t& lastTotalBytes) {
    auto currentTime = std::chrono::steady_clock::now();
    size_t currentTotalBytes = 0;

    currentTotalBytes += recvOffsets_[0];

    // 计算时间差
    std::chrono::duration<double> elapsed = currentTime - lastTime;

    // 每秒打印吞吐量
    if (elapsed.count() >= 1.0) {
        size_t throughput = (currentTotalBytes - lastTotalBytes) * 8 / 1024 / 1024; // 当前秒的吞吐量，换算成Mbps
        LOG(INFO) << "The Download Throughput: " << throughput << " Mbps";
        // 更新上一次的字节数和时间
        lastTotalBytes = currentTotalBytes;
        lastTime = currentTime;
    }
    return 0; 
  }

  void start(std::string token) {
    folly::ScopedEventBaseThread networkThread("EchoClientThread");
    auto evb = networkThread.getEventBase();
    auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
    folly::SocketAddress addr(host_.c_str(), port_);

    evb->runInEventBaseThreadAndWait([&] {
      auto sock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb);
      auto fizzCLientCtx = createFizzClientContext();
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .setFizzClientContext(std::move(fizzCLientCtx))
              .build();
      quicClient_ = std::make_shared<quic::QuicClientTransport>(
          qEvb, std::move(sock), std::move(fizzClientContext));
      quicClient_->setHostname("echo.com");
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

      LOG(INFO) << "EchoClient connecting to " << addr.describe();
      quicClient_->start(this, this);

    });
 
    // 启动状态打印线程
    std::thread([this]() {
        std::chrono::steady_clock::time_point lastTime = std::chrono::steady_clock::now();
        size_t lastTotalBytes = 0;
        while (running_) {
            // 在这里输出性能指标，例如吞吐量
            calculateThroughput(lastTime, lastTotalBytes);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }).detach();

    startDone_.wait();

    if (connectOnly_) {
      evb->runInEventBaseThreadAndWait(
          [this] { quicClient_->closeNow(folly::none); });

      return;
    }

    std::string message;
    bool closed = false;
    auto client = quicClient_;

    if (enableStreamGroups_) {
      // Generate two groups.
      for (size_t i = 0; i < kNumTestStreamGroups; ++i) {
        auto groupId = quicClient_->createBidirectionalStreamGroup();
        CHECK(groupId.hasValue())
            << "Failed to generate a stream group: " << groupId.error();
        streamGroups_[i] = *groupId;
      }
    }

    auto sendMessageInStream = [&]() {
      if (message == "/close") {
        quicClient_->close(none);
        closed = true;
        return;
      }

      // create new stream for each message
      auto streamId = client->createBidirectionalStream().value();
      client->setReadCallback(streamId, this);
      pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(message));
      sendMessage(streamId, pendingOutput_[streamId], 0);
    };

    auto sendMessageInStreamGroup = [&]() {
      // create new stream for each message
      auto streamId =
          client->createBidirectionalStreamInGroup(getNextGroupId());
      CHECK(streamId.hasValue())
          << "Failed to generate stream id in group: " << streamId.error();
      client->setReadCallback(*streamId, this);
      pendingOutput_[*streamId].append(folly::IOBuf::copyBuffer(message));
      sendMessage(*streamId, pendingOutput_[*streamId], 0);
    };

    // loop until Ctrl+D
    generateRequests(150000);

    LOG(INFO) << "EchoClient stopping client";
  }

  ~DlwClient() override = default;

 private:
  [[nodiscard]] quic::StreamGroupId getNextGroupId() {
    return streamGroups_[(curGroupIdIdx_++) % kNumTestStreamGroups];
  }

  void sendMessage(quic::StreamId id, BufQueue& data, size_t idx) {
    auto message = data.move();
    auto res = useDatagrams_
        ? quicClient_->writeDatagram(message->clone())
        : quicClient_->writeChain(id, message->clone(), false);
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient writeChain error=" << uint32_t(res.error());
    } else {
      auto str = message->to<std::string>();
      /*LOG(INFO) << "EchoClient wrote idx = \"" << idx << str << "\""
                << ", len=" << str.size() << " on stream=" << id
                << ", pendingOutput_ queue length=" << pendingOutput_[id].chainLength();*/
      // sent whole message
      pendingOutput_.erase(id);
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
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  std::map<quic::StreamId, BufQueue> pendingOutput_;
  std::map<quic::StreamId, uint64_t> recvOffsets_;
  folly::fibers::Baton startDone_;
  std::array<StreamGroupId, kNumTestStreamGroups> streamGroups_;
  size_t curGroupIdIdx_{0};
  std::vector<std::string> alpns_;
  bool connectOnly_{false};
  std::string clientCertPath_;
  std::string clientKeyPath_;
  folly::Synchronized<std::queue<std::string>> taskQueue_;
  folly::EventBase fEvb_;
};
} // namespace quic::samples
