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
#include <quic/api/QuicTransportBase.h>
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
                   public quic::QuicSocket::DatagramCallback
                   {
 public:
  MdlwClient(
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

  void readAvailable(quic::StreamId streamId) noexcept override {
    LOG(INFO) << "EchoClient readAvailable streamId=" << streamId;
  }

  void writeDataToFile(const char* chunk, size_t dataLength, const std::string& filePath) {
    std::ofstream outputFile(filePath, std::ios::app | std::ios::binary);
    if (outputFile.is_open()) {
        outputFile.write(chunk, dataLength);
        outputFile.close();
    } else {
        std::cerr << "Error: Unable to open file for writing." << std::endl;
    }
  }

  bool isTailHasIncompFrame(const std::string& data, int64_t connId, size_t len, size_t& pos){
    // 检查末尾4个字符
    std::string tail = "FRAM";
    for(size_t i = tail.length(); i > 0; i--){
      if(len >= i && data.substr(len-i) == tail.substr(0, i)){
        pos = len - i;
        connManager_->setIncompFrameLen(connId, i);
        VLOG(1) << "Check tail has incomp frame, connId = " << connId
            << ", len = " << len
            << ", data = " << data;
        return true;
      }
    }
    return false;
  }

  bool isHeadMergeToFrame(const std::string& data, int64_t connId, size_t& left){
    size_t incompFrameLen = connManager_->getIncompFrameLen(connId);
    
    std::string head = "FRAME";
    size_t headLen = head.length();
    left = headLen - incompFrameLen;
    
    if(incompFrameLen > 0 && incompFrameLen < headLen){
      std::string prefix = head.substr(0, incompFrameLen);
      if(prefix + data.substr(0, left) == "FRAME"){
        return true;
      }
    }
    return false;
  }

  void processDatafield(int64_t connId, const char* data, size_t dataLength, const std::string& filePath) {
    // 不是帧头 处理数据字段
    uint64_t expectedSequenceNumber = connManager_->getExpectedSequenceNumber();
    uint64_t lastReceivedSeq = connManager_->getLastReceivedSeq(connId);

    if(lastReceivedSeq == expectedSequenceNumber){
        writeDataToFile(data, dataLength, filePath);
        connManager_->setChunkOffset(dataLength);
        VLOG(1) << "Write data seq = " << expectedSequenceNumber 
                << ", dataLength = " << dataLength
                << ", chunkOffset = " << connManager_->getChunkOffset()
                << ", chunkTarget = " << connManager_->getChunkTarget();
        if(connManager_->getChunkOffset() == connManager_->getChunkTarget()){
          expectedSequenceNumber++;
          auto chunkCache = connManager_->getChunkCache();
          while (chunkCache.count(expectedSequenceNumber)) {
              auto chunk = connManager_->getChunkCache(expectedSequenceNumber);
              char* cachedChunkData = chunk->data.get();
              VLOG(1) << "Find cached seq = " << chunk->sequenceNumber
                      << ", cached data ptr = " << (void*)chunk->data.get()
                      << ", cached data length = " << chunk->offset
                      << ", cached target = " << chunk->total;  
                      
              writeDataToFile(cachedChunkData, chunk->offset, filePath);
              VLOG(1) << "Write cached seq =" << expectedSequenceNumber 
                      << ", chunkoffset" << chunk->offset;

              connManager_->setChunkOffset(chunk->offset);
              
              connManager_->setChunkTarget(chunk->total);
              
              if(connManager_->getChunkOffset() == connManager_->getChunkTarget()){
                VLOG(1) << "Write cachedata seq =" << expectedSequenceNumber 
                    << ", dataLength = " << chunk->offset  
                    << ", chunkoffset = " << connManager_->getChunkOffset()
                    << ", chunkTarget = " << connManager_->getChunkTarget();
                connManager_->removeChunkCache(expectedSequenceNumber);
                expectedSequenceNumber++;
              }else {
                VLOG(1) << "Write cachedata seq =" << expectedSequenceNumber 
                    << ", dataLength = " << chunk->offset  
                    << ", chunkoffset = " << connManager_->getChunkOffset()
                    << ", chunkTarget = " << connManager_->getChunkTarget();
                connManager_->emptyChunkCache(expectedSequenceNumber);
                break;
              }
          }
          connManager_->setExpectedSequenceNumber(expectedSequenceNumber);
        }else if(connManager_->getChunkOffset() > connManager_->getChunkTarget()){
          VLOG(1) << "Write data beyond target: " << 
          data + dataLength - (connManager_->getChunkOffset() - connManager_->getChunkTarget());
        }
      }else{
        auto chunkCache = connManager_->getChunkCache();
        VLOG(1) << "lastReceivedSeq = " << lastReceivedSeq << " Address of chunkCache: " << &chunkCache;

        size_t oldLength = connManager_->getChunkCache(lastReceivedSeq)->offset;
        VLOG(1) << "ConnId = " << connId << " Find seq = " << lastReceivedSeq 
        << ", address of chunk = " << connManager_->getChunkCache(lastReceivedSeq)
        << " data ptr = " << (void*)connManager_->getChunkCache(lastReceivedSeq)->data.get()
        << " before merge length = " << connManager_->getChunkCache(lastReceivedSeq)->offset;

        auto old_data_ptr = connManager_->getChunkCache(lastReceivedSeq)->data;
        char* old_data = old_data_ptr.get();
        // 2. 计算新长度
        size_t new_length = oldLength + dataLength; // +1 for null terminator

        // 3. 分配新的内存
        std::shared_ptr<char> new_data_ptr(new char[new_length], std::default_delete<char[]>());

        // 4. 复制现有数据
        if (oldLength > 0) {
            std::memcpy(new_data_ptr.get(), old_data, oldLength);
        }

        // 5. 复制新数据
        std::memcpy(new_data_ptr.get() + oldLength, data, dataLength);

        // 7. 更新 connManager_ 中的 shared_ptr 和 length
        connManager_->getChunkCache(lastReceivedSeq)->data = new_data_ptr;
        connManager_->getChunkCache(lastReceivedSeq)->offset = new_length;

        VLOG(1) << "ConnId = " << connId << " seq = " << lastReceivedSeq 
        << " data ptr = " << (void*)connManager_->getChunkCache(lastReceivedSeq)->data.get()
        << " merged data length = " << connManager_->getChunkCache(lastReceivedSeq)->offset;
      }
    
  }

  void processImcompleteHeader(int64_t connId, const char* data, size_t dataLength) {
    if(dataLength < sizeof(uint64_t)){
        VLOG(1) << "Process imcomplete header seq, connId = " << connId
                << ", dataLength = " << dataLength
                << ", data = " << data;
        std::string imcompSeq(data, dataLength);
        
        connManager_->setImcompSeqLen(connId, dataLength);
        connManager_->setImcompSeq(connId, imcompSeq);
        VLOG(1) << "Process imcomplete header seq, connId = " << connId
                << ", writen offset = " << dataLength
                << ", imcompSeq = " << imcompSeq;
    }else{
        uint64_t sequenceNumber = *reinterpret_cast<const uint64_t*>(data);
        connManager_->setLastReceivedSeq(connId, sequenceNumber);
        data += sizeof(uint64_t);
        VLOG(1) << "Process imcomplete header offset, connId = " << connId
                << ", dataLength = " << dataLength
                << ", sequenceNumber = " << sequenceNumber
                << ", data = " << data;
        std::string imcompOffset(data, dataLength - sizeof(uint64_t));
        
        connManager_->setImcompOffsetLen(connId, dataLength - sizeof(uint64_t));
        connManager_->setImcompOffset(connId, imcompOffset);
        VLOG(1) << "Process imcomplete header offset, connId = " << connId
                << ", writen offset = " << dataLength - sizeof(uint64_t)
                << ", imcompOffset = " << imcompOffset;
    }
  }

  void processHeaderfield(int64_t connId, const char* data, size_t dataLength, const std::string& filePath) {
    // 处理帧头
    // 检查剩余数据长度是否足够
      if (dataLength < sizeof(uint64_t) + sizeof(size_t)) {
          processImcompleteHeader(connId, data, dataLength);
          return;
      }

      uint64_t sequenceNumber = 0;
      size_t targetOffset = 0;
      uint64_t expectedSequenceNumber = connManager_->getExpectedSequenceNumber();
      size_t remaiLen = 0;

      int64_t imcompSeqLen = connManager_->getImcompSeqLen(connId);
      int64_t imcompOffsetLen = connManager_->getImcompOffsetLen(connId);

      if(imcompSeqLen >= 0){
        std::string imcompSeq = connManager_->getImcompSeq(connId);
        size_t remain = sizeof(uint64_t) - imcompSeqLen;
        VLOG(1) << "Process imcomplete seq, connId = " << connId
                << ", writen offset = " << imcompSeqLen
                << ", imcompSeq = " << imcompSeq;
        imcompSeq.append(data, remain);
        VLOG(1) << "Process imcomplete seq, connId = " << connId
                << ", writen offset = " << remain
                << ", imcompSeq = " << imcompSeq;
        sequenceNumber = *reinterpret_cast<const uint64_t*>(imcompSeq.c_str());
        connManager_->setLastReceivedSeq(connId, sequenceNumber);
        data += remain;
        targetOffset = *reinterpret_cast<const size_t*>(data);
        data += sizeof(size_t);
        remaiLen = dataLength - remain - sizeof(size_t);
        connManager_->setImcompSeqLen(connId, -1);
      }else if(imcompOffsetLen >= 0){
        std::string imcompOffset = connManager_->getImcompOffset(connId);
        size_t remain = sizeof(size_t) - imcompOffsetLen;
        VLOG(1) << "Process imcomplete offset, connId = " << connId
                << ", writen offset = " << imcompOffsetLen
                << ", imcompOffset = " << imcompOffset;
        imcompOffset.append(data, remain);
        sequenceNumber = connManager_->getLastReceivedSeq(connId);
        VLOG(1) << "Process imcomplete offset, connId = " << connId
                << ", remain offset = " << remain
                << ", imcompOffset = " << imcompOffset;
        targetOffset = *reinterpret_cast<const size_t*>(imcompOffset.c_str());
        data += remain;
        remaiLen = dataLength - remain;
        connManager_->setImcompOffsetLen(connId, -1);
      }else{
        sequenceNumber = *reinterpret_cast<const uint64_t*>(data);
        data += sizeof(uint64_t);
        targetOffset = *reinterpret_cast<const size_t*>(data);
        data += sizeof(size_t);
        remaiLen = dataLength - sizeof(uint64_t) - sizeof(size_t);
      }
      
      VLOG(1) << "Found frame header: seq=" << sequenceNumber 
              << ", targetOffset=" << targetOffset
              << ", dataLength=" << dataLength;
      
      if(targetOffset < remaiLen){
          LOG(ERROR) << "Data length beyond target, connId = " << connId << "beyond = " << data + targetOffset;
          exit(1);
      }

      if (sequenceNumber == expectedSequenceNumber) {
          // 设置到 connManager 中
          connManager_->setChunkTarget(targetOffset);

          writeDataToFile(data, remaiLen, filePath);
        
          connManager_->setChunkOffset(remaiLen);

          // 写入数据
          VLOG(1) << "Write expected seq = " << sequenceNumber 
                  << ", dataLength = " << remaiLen
                  << ", chunkOffset = " << connManager_->getChunkOffset()
                  << ", chunkTarget = " << connManager_->getChunkTarget();

          connManager_->setLastReceivedSeq(connId, expectedSequenceNumber);
          if(connManager_->getChunkOffset() == connManager_->getChunkTarget()){
            expectedSequenceNumber++;
            // 检查缓存中是否有后续连续的 chunk
            while (connManager_->getChunkCache(expectedSequenceNumber) != nullptr) {
                auto cachedChunk = connManager_->getChunkCache(expectedSequenceNumber);
                char* cachedChunkData = cachedChunk->data.get();
                size_t cachedChunkLen = cachedChunk->offset;

                connManager_->setChunkTarget(cachedChunk->total);
              
                writeDataToFile(cachedChunkData, cachedChunkLen, filePath);
                
                connManager_->setChunkOffset(cachedChunk->offset);

                if(connManager_->getChunkOffset() == connManager_->getChunkTarget()){
                  VLOG(1) << "Write cached seq =" << expectedSequenceNumber 
                      << ", dataLength = " << cachedChunk->offset
                      << ", chunkoffset = " << connManager_->getChunkOffset()
                      << ", chunkTarget = " << connManager_->getChunkTarget();
                  connManager_->removeChunkCache(expectedSequenceNumber);
                  expectedSequenceNumber++;
                }else {
                  VLOG(1) << "Write cached seq =" << expectedSequenceNumber 
                      << ", dataLength = " << cachedChunk->offset
                      << ", chunkoffset = " << connManager_->getChunkOffset()
                      << ", chunkTarget = " << connManager_->getChunkTarget();
                  connManager_->emptyChunkCache(expectedSequenceNumber);
                  break;
                }
                
            }
            connManager_->setExpectedSequenceNumber(expectedSequenceNumber);
            VLOG(1) << "Now the expected seq = " << expectedSequenceNumber;
          }
        
      } else {
          // 不是期望的序列号，放入缓存
          auto chunkCache = connManager_->getChunkCache();
        
          std::shared_ptr<char> dataBuf(new char[remaiLen], std::default_delete<char[]>());

        
          memcpy(dataBuf.get(), data, remaiLen);

          std::shared_ptr<quic::QuicSocket::ChunkData> chunk = std::make_shared<quic::QuicSocket::ChunkData>(
            sequenceNumber,
            targetOffset,
            remaiLen,
            dataBuf 
          );

          connManager_->setChunkCache(sequenceNumber, chunk);

          VLOG(1) << "Address of chunk object = " 
          << (void*)chunk.get() << ", address stored in cache = " 
          << (void*)connManager_->getChunkCache(sequenceNumber).get(); // .get() 获取原始指针

          connManager_->setLastReceivedSeq(connId, sequenceNumber);

          auto cachedChunkPtr = connManager_->getChunkCache(sequenceNumber);
          if (cachedChunkPtr && cachedChunkPtr->data) {
              VLOG(1) << "ConnId = " << connId << " Received unexpected header, seq = " << sequenceNumber 
                      << ", data ptr = " << (void*)cachedChunkPtr->data.get() // 假设 data 是 shared_ptr<char>
                      << ", dataLength = " << cachedChunkPtr->offset;
          } else {
              VLOG(1) << "ConnId = " << connId << " Received unexpected header, seq = " << sequenceNumber 
                      << ", but cached chunk or data pointer is null.";
          }
      }
  }

  void mergeData(folly::IOBuf* data, size_t dataLength, int64_t connId, std::string filePath) {
      static uint64_t expectedSequenceNumber = connManager_->getExpectedSequenceNumber();
      
      const char* originalData = (const char*)data->data();
      
      if (memcmp(originalData, "HTTP/1.1", 8) == 0) {
          LOG(INFO) << "HTTP/1.1 response received";
          size_t ac_header_len = strlen("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
          originalData += ac_header_len;
          dataLength -= ac_header_len;
      }

      std::string currentData(originalData, dataLength);

      size_t start = 0, pos = 0, str_len = strlen("FRAME"), left = 0;

      if(connManager_->isIncompleteFrame(connId)){
        if(isHeadMergeToFrame(currentData, connId, start)){
          pos = currentData.find("FRAME", start);
          if (pos != std::string::npos) {
              // 找到 "Frame"，处理头部字段
              VLOG(1) << "Process head merge to frame, connId = " << connId
                      << ", start = " << start << ", pos = " << pos;
              processHeaderfield(connId, originalData + start, pos - start, filePath);
              connManager_->removeIncompFrameLen(connId);
              start = pos;
          } else {
              // 未找到 "Frame"，根据是否为尾部不完整帧选择处理函数
              if (isTailHasIncompFrame(currentData, connId, dataLength, pos)) {
                  VLOG(1) << "Process tail has incomp frame, connId = " << connId
                          << ", start = " << start << ", pos = " << pos;
                  processHeaderfield(connId, originalData + start, pos - start, filePath);
              } else {
                  processHeaderfield(connId, originalData + start, dataLength - start, filePath);
                  connManager_->removeIncompFrameLen(connId);
                  start = dataLength;
              }
          }
        }else{
          connManager_->removeIncompFrameLen(connId);
        }
      }
    
      // 检查是否是帧头 (0x123456)
      while (start < dataLength) {
        size_t pos = currentData.find("FRAME", start);
        if(pos != std::string::npos){
            if(pos > start){
                if(connManager_->hasImcomp(connId)){
                  processHeaderfield(connId, originalData + start, pos - start, filePath);
                }else{
                  VLOG(1) << "Process datafield, connId = " << connId 
                          << ", start = " << start << ", pos = " << pos
                          << ", dataLength = " << pos - start;
                  processDatafield(connId, originalData + start, pos - start, filePath);
                }
            }
            start = pos + str_len;
            size_t nxt_pos = currentData.find("FRAME", start);
            if(nxt_pos == std::string::npos){
              if(!isTailHasIncompFrame(currentData, connId, start, nxt_pos)){
                nxt_pos = dataLength;
              }
            }
            if(nxt_pos - start > 1040){
              VLOG(1) << "This unormal Frame dataLength = " << nxt_pos - start
                      << ", data = " << currentData.substr(start, dataLength - start);
            }
            processHeaderfield(connId, originalData + start, nxt_pos - start, filePath);
            start = nxt_pos;
        }else if(isTailHasIncompFrame(currentData, connId, dataLength, pos)){
            VLOG(1) << "Tail has incomp frame, connId = " << connId 
                  << "start = " << start << ", pos = " << pos;
            processDatafield(connId, originalData + start, pos - start, filePath);
        }else{
            if(connManager_->hasImcomp(connId)){
              processHeaderfield(connId, originalData + start, dataLength - start, filePath);
            }else{
              processDatafield(connId, originalData + start, dataLength - start, filePath);
            }
          start = dataLength;
        }
     }
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
    std::ofstream file(filePath, std::ios::binary | std::ios::app);
    if (!file) {
      LOG(ERROR) << "Failed to create file: " << filePath;
      return;
    }
    if (recvOffsets_.find(connId) == recvOffsets_.end() || recvOffsets_[connId].find(streamId) == recvOffsets_[connId].end()) {
        recvOffsets_[connId][streamId] = 0; 
    }
    if (dataLength > 0) {
        auto dataCopy = std::make_shared<folly::IOBuf>(std::move(current));
        VLOG(1) << "Read available data= " << dataCopy->toString();
        connManager_->getEventBase()->runInEventBaseThread(
          [this, dataCopy, dataLength, connId, filePath]() {
            mergeData(dataCopy.get(), dataLength, connId, filePath);
          });
        
        recvOffsets_[connId][streamId] += dataLength;
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

    std::string url = "https://" + host_ + "/" + fileName_; //+ std::to_string(i);
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
    folly::ScopedEventBaseThread mergeDataThread("MergeDataThread");
    auto mev = mergeDataThread.getEventBase();
    auto mEvb = std::make_shared<FollyQuicEventBase>(mev);

    connManager_ = std::make_shared<CliConnection>(100, mEvb);
    mptcp_sock_ = new struct mptcp_sock();
    mptcp_sock_->connManager = connManager_;
    fileName_ = "CHUNK_1000K.mp4";

    connManager_->setScheduler("rr", mptcp_sock_);

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
  std::string fileName_;
  std::shared_ptr<CliConnection> connManager_;
  struct mptcp_sock* mptcp_sock_;
};

} // namespace quic::samples
