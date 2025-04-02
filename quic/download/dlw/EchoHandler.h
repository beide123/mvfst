/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocket.h>

#include <quic/common/BufUtil.h>

#include <future>

namespace quic::download {

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

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id;
    sock->setReadCallback(id, this);
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
    VLOG(4) << "Got len=" << dataLen << " eof=" << uint32_t(eof)
              << " total=" << input_[id].first.chainLength() + dataLen
              << " data="
              << ((data) ? data->clone()->to<std::string>() : std::string());
    input_[id].first.append(std::move(data));
    input_[id].second = eof;
    if (dataLen > 0) {
      //echo(id, input_[id]);
      handleMP4Request(id, input_[id]);
      //LOG(INFO) << "uninstalling read callback";
      sock->setReadCallback(id, this);
    }
  }

  void readAvailable(StreamId streamId, int64_t connId) noexcept {
    LOG(INFO) << "DlwClient:" << connId << " readAvailable streamId=" << streamId;
  }

  void onMultiNewBidirectionalStream(int64_t connId, StreamId id) noexcept {
    LOG(INFO) << "EchoClient:" << connId << " new bidirectional stream=" << id;
  }

  void onDatagramsAvailable(int64_t connId) noexcept override {
    LOG(INFO) << "Datagrams available on connection " << connId;
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
    size_t start = 0;
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
        
        if (requestType != "GET") {
            continue;
        }

        // 提取url
        std::string url;
        issFirstLine >> url;

        const std::string prefix = "https://127.0.0.1/";
        if (url.find(prefix) != 0 || url.find(".mp4") == std::string::npos) {
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

        const size_t bufferSize = 64 * 1024;
        std::vector<char> buffer(bufferSize);

        auto fileChunk = folly::IOBufQueue();

        std::streamsize toatlBytes = 0;
        while (file) {
            file.read(buffer.data(), bufferSize);
            std::streamsize bytesRead = file.gcount();
            if (bytesRead > 0) {
                fileChunk.append(folly::IOBuf::copyBuffer(buffer.data(), bytesRead));
                auto res = sock->writeChain(id, fileChunk.move(), false, nullptr);
                if (res.hasError()) {
                    LOG(ERROR) << "Write error: " << toString(res.error());
                    return;
                }
                toatlBytes += bytesRead;
                currentBytes_ += bytesRead;
            }
        }

        if (!fileChunk.empty()) {
            auto res = sock->writeChain(id, fileChunk.move(), false, nullptr);
            if (res.hasError()) {
                LOG(ERROR) << "Write error: " << toString(res.error());
                return;
            }
        }

        auto eof = folly::IOBuf::create(0);
        auto res = sock->writeChain(id, std::move(eof), false, nullptr);
        if (res.hasError()) {
            LOG(ERROR) << "Error sending EOF: " << toString(res.error());
        }else{
            //LOG(INFO) << "file download completed: " << filePath;
            VLOG(4) << "Sent " << toatlBytes << " bytes of file data for request " << ++requestCnt;
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
  bool firstRequest_{true};
  std::streamsize currentBytes_{0};
  std::streamsize previousBytes_{0};
};

int DlwHandler::requestCnt = 0;  // 在类外初始化静态成员

} // namespace quic::download
