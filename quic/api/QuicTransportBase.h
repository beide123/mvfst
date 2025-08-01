/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/common/NetworkData.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/NewReno.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/state/StateData.h>

#include <folly/ExceptionWrapper.h>

namespace quic {

/**
 * Base class for the QUIC Transport. Implements common behavior for both
 * clients and servers. QuicTransportBase assumes the following:
 * 1. It is intended to be sub-classed and used via the subclass directly.
 * 2. Assumes that the sub-class manages its ownership via a shared_ptr.
 *    This is needed in order for QUIC to be able to live beyond the lifetime
 *    of the object that holds it to send graceful close messages to the peer.
 */
class QuicTransportBase : public QuicSocket,
                          virtual public QuicTransportBaseLite {
 public:
  QuicTransportBase(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicTransportBase() override;

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

  Optional<ConnectionId> getClientConnectionId() const override;

  void setClientConnIdx(int64_t idx) const override;

  void setMultiPath(bool isMultiPath) const override;

  Optional<ConnectionId> getServerConnectionId() const override;

  Optional<ConnectionId> getClientChosenDestConnectionId() const override;

  const std::shared_ptr<QLogger> getQLogger() const;

  // QuicSocket interface
  bool replaySafe() const override;

  void closeGracefully() override;

  folly::Expected<size_t, LocalErrorCode> getStreamReadOffset(
      StreamId id) const override;
  folly::Expected<size_t, LocalErrorCode> getStreamWriteOffset(
      StreamId id) const override;
  folly::Expected<size_t, LocalErrorCode> getStreamWriteBufferedBytes(
      StreamId id) const override;

  folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const override;

  folly::Expected<uint64_t, LocalErrorCode> getMaxWritableOnStream(
      StreamId id) const override;

  folly::Expected<folly::Unit, LocalErrorCode> setConnectionFlowControlWindow(
      uint64_t windowSize) override;

  folly::Expected<folly::Unit, LocalErrorCode> setStreamFlowControlWindow(
      StreamId id,
      uint64_t windowSize) override;

  void unsetAllReadCallbacks() override;
  void unsetAllPeekCallbacks() override;
  void unsetAllDeliveryCallbacks() override;
  folly::Expected<folly::Unit, LocalErrorCode> pauseRead(StreamId id) override;
  folly::Expected<folly::Unit, LocalErrorCode> resumeRead(StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> setPeekCallback(
      StreamId id,
      PeekCallback* cb) override;

  folly::Expected<folly::Unit, LocalErrorCode> pausePeek(StreamId id) override;
  folly::Expected<folly::Unit, LocalErrorCode> resumePeek(StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> peek(
      StreamId id,
      const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                                const>& peekCallback) override;

  folly::Expected<folly::Unit, LocalErrorCode> consume(
      StreamId id,
      size_t amount) override;

  folly::Expected<folly::Unit, std::pair<LocalErrorCode, Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) override;

  folly::Expected<StreamGroupId, LocalErrorCode>
  createBidirectionalStreamGroup() override;
  folly::Expected<StreamGroupId, LocalErrorCode>
  createUnidirectionalStreamGroup() override;
  folly::Expected<StreamId, LocalErrorCode> createBidirectionalStreamInGroup(
      StreamGroupId groupId) override;
  folly::Expected<StreamId, LocalErrorCode> createUnidirectionalStreamInGroup(
      StreamGroupId groupId) override;
  bool isClientStream(StreamId stream) noexcept override;
  bool isServerStream(StreamId stream) noexcept override;
  StreamDirectionality getStreamDirectionality(
      StreamId stream) noexcept override;

  folly::Expected<folly::Unit, LocalErrorCode> maybeResetStreamFromReadError(
      StreamId id,
      QuicErrorCode error) override;

  folly::Expected<folly::Unit, LocalErrorCode> setPingCallback(
      PingCallback* cb) override;

  void sendPing(std::chrono::milliseconds pingTimeout) override;

  const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  virtual void setAckRxTimestampsEnabled(bool enableAckRxTimestamps);

  void setEarlyDataAppParamsFunctions(
      folly::Function<bool(const Optional<std::string>&, const Buf&) const>
          validator,
      folly::Function<Buf()> getter) final;

  bool isDetachable() override;

  void detachEventBase() override;

  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;

  // Subclass API.

  folly::Expected<Priority, LocalErrorCode> getStreamPriority(
      StreamId id) override;

  /**
   * Register a callback to be invoked when the stream offset was transmitted.
   *
   * Currently, an offset is considered "transmitted" if it has been written to
   * to the underlying UDP socket, indicating that it has passed through
   * congestion control and pacing. In the future, this callback may be
   * triggered by socket/NIC software or hardware timestamps.
   */
  folly::Expected<folly::Unit, LocalErrorCode> registerTxCallback(
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) override;

  /**
   * Reset or send a stop sending on all non-control streams. Leaves the
   * connection otherwise unmodified. Note this will also trigger the
   * onStreamWriteError and readError callbacks immediately.
   */
  void resetNonControlStreams(
      ApplicationErrorCode error,
      folly::StringPiece errorMsg) override;

  virtual void setQLogger(std::shared_ptr<QLogger> qLogger);

  void setLoopDetectorCallback(std::shared_ptr<LoopDetectorCallback> callback) {
    conn_->loopDetectorCallback = std::move(callback);
  }

  /**
   * Set the read callback for Datagrams
   */
  folly::Expected<folly::Unit, LocalErrorCode> setDatagramCallback(
      DatagramCallback* cb) override;

  /**
   * Returns the maximum allowed Datagram payload size.
   * 0 means Datagram is not supported
   */
  FOLLY_NODISCARD uint16_t getDatagramSizeLimit() const override;

  /**
   * Writes a Datagram frame. If buf is larger than the size limit returned by
   * getDatagramSizeLimit(), or if the write buffer is full, buf will simply be
   * dropped, and a LocalErrorCode will be returned to caller.
   */
  folly::Expected<folly::Unit, LocalErrorCode> writeDatagram(Buf buf) override;

  /**
   * Returns the currently available received Datagrams.
   * Returns all datagrams if atMost is 0.
   */
  folly::Expected<std::vector<ReadDatagram>, LocalErrorCode> readDatagrams(
      size_t atMost = 0) override;

  /**
   * Returns the currently available received Datagram IOBufs.
   * Returns all datagrams if atMost is 0.
   */
  folly::Expected<std::vector<Buf>, LocalErrorCode> readDatagramBufs(
      size_t atMost = 0) override;

  /**
   * Set control messages to be sent for socket_ write, note that it's for this
   * specific transport and does not change the other sockets sharing the same
   * fd.
   */
  void setCmsgs(const folly::SocketCmsgMap& options);

  void appendCmsgs(const folly::SocketCmsgMap& options);

  /**
   * Sets the policy per stream group id.
   * If policy == std::nullopt, the policy is removed for corresponding stream
   * group id (reset to the default rtx policy).
   */
  folly::Expected<folly::Unit, LocalErrorCode>
  setStreamGroupRetransmissionPolicy(
      StreamGroupId groupId,
      std::optional<QuicStreamGroupRetransmissionPolicy> policy) noexcept
      override;

  [[nodiscard]] const folly::
      F14FastMap<StreamGroupId, QuicStreamGroupRetransmissionPolicy>&
      getStreamGroupRetransmissionPolicies() const {
    return conn_->retransmissionPolicies;
  }

  [[nodiscard]] QuicAsyncUDPSocket* getUdpSocket() const {
    return socket_.get();
  }

 protected:
  folly::Expected<folly::Unit, LocalErrorCode> pauseOrResumeRead(
      StreamId id,
      bool resume);
  folly::Expected<folly::Unit, LocalErrorCode> pauseOrResumePeek(
      StreamId id,
      bool resume);
  folly::Expected<folly::Unit, LocalErrorCode> setPeekCallbackInternal(
      StreamId id,
      PeekCallback* cb) noexcept;

  void schedulePingTimeout(
      PingCallback* callback,
      std::chrono::milliseconds pingTimeout);

  bool handshakeDoneNotified_{false};

  uint64_t qlogRefcnt_{0};

 private:
  /**
   * Helper to check if using custom retransmission profiles is feasible.
   * Custom retransmission profiles are only applicable when stream groups are
   * enabled, i.e. advertisedMaxStreamGroups in transport settings is > 0.
   */
  [[nodiscard]] bool checkCustomRetransmissionProfilesEnabled() const;
};

// 添加 ConnectionManager 类的声明
class ConnectionManager {
 protected:
  uint64_t capacity_;
  int64_t shm_sock_{-1};
  std::string frameLabel_;
  std::unordered_map<int64_t, StreamId> clientStreams_;
  std::unordered_map<uint64_t, std::shared_ptr<QuicSocket::ChunkData>> chunkCache_;
  
  size_t chunkOffset_{0};
  size_t chunkTarget_{0};
  uint64_t sequenceNumber_{0};
  uint64_t expectedSequenceNumber_{0};
  
  std::unordered_map<int64_t, size_t> incompFrameLabelLen_;
  std::unordered_map<int64_t, int64_t> imcompSeqLen_;
  std::unordered_map<int64_t, int64_t> imcompOffsetLen_;

  std::unordered_map<int64_t, uint64_t> lastReceivedSeq_;

  std::unordered_map<int64_t, std::string> imcompSeq_;
  std::unordered_map<int64_t, std::string> imcompOffset_;

  static constexpr std::size_t kDestroyBatch = 512;
  std::vector<std::shared_ptr<QuicSocket::ChunkData>> pendingDestruction_;

  RingBuffer<char> shmPool_;

  uint64_t duration_ = 0;
  uint64_t count_ = 0;

 public:
  // Add virtual destructor
  virtual ~ConnectionManager() {
    VLOG(1) << "ConnectionManager has been destructed";
  }

  ConnectionManager()
  : shmPool_(10 * 1024 * 1024)
  {
    capacity_ = 100;
    lastReceivedSeq_ = std::unordered_map<int64_t, uint64_t>();
    imcompOffsetLen_ = std::unordered_map<int64_t, int64_t>();
    imcompSeqLen_ = std::unordered_map<int64_t, int64_t>();
    imcompOffset_ = std::unordered_map<int64_t, std::string>();
    imcompSeq_ = std::unordered_map<int64_t, std::string>();
    incompFrameLabelLen_ = std::unordered_map<int64_t, size_t>();
    chunkCache_ =  std::unordered_map<uint64_t, std::shared_ptr<QuicSocket::ChunkData>>();
    reserverChunkCache();
  }

  virtual std::vector<int64_t> getAllConnectionIds() = 0;

  virtual bool empty() = 0;

  virtual uint64_t getsize() = 0;

  std::function<void(const char*, size_t)> dataCallback_;

  void setShmSocket(int64_t shm_sock) {
    shm_sock_ = shm_sock;
  }

  int64_t getShmSocket() {
    return shm_sock_;
  }

  void setDataCallback(std::function<void(const char*, size_t)> dataCallback) {
    dataCallback_ = dataCallback;
  }

  void sendDataToApp(const char* data, size_t dataLength) {
    if(dataCallback_) {
      dataCallback_(data, dataLength);
    }else{
      LOG(ERROR) << "sendDataToApp callback is not set";
    }
  }

  bool isTailHasIncompFrame(const std::string& data, int64_t connId, size_t len, size_t start, size_t& pos, bool hasLabel){
    // 检查末尾4个字符
    std::string tail = frameLabel_.substr(0, 4);
    size_t headLen = sizeof(uint64_t) + sizeof(size_t);
    for(size_t i = tail.length(); i > 0; i--){
      if(len >= i && data.substr(len - i) == tail.substr(0, i)){
        pos = len - i;
        if(hasLabel && (start + headLen >= pos)){
          return false;
        }
        setIncompFrameLabelLen(connId, i);
        VLOG(1) << "Check tail has incomp frame label 'FRAME', connId = " << connId
            << ", start = " << start
            << ", pos = " << pos
            << ", data = " << data.substr(pos);
        return true;
      }
    }
    return false;
  }


  bool isHeadMergeToFrame(const std::string& data, int64_t connId, size_t& left){
    size_t incompFrameLabelLen = getIncompFrameLabelLen(connId);
    
    std::string head = frameLabel_;
    size_t headLen = head.length(), leftLen = headLen - incompFrameLabelLen;

    VLOG(1) << "Check if head merge to frame, connId = " << connId
            << ", incompFrameLabelLen = " << incompFrameLabelLen
            << ", left = " << left
            << ", data = " << data.substr(0, leftLen);
    
    if(incompFrameLabelLen > 0 && incompFrameLabelLen < headLen){
      std::string prefix = head.substr(0, incompFrameLabelLen);
      if(prefix + data.substr(0, leftLen) == head){
        left = leftLen;
        VLOG(1) << "Can merge head to frame, connId = " << connId
                << ", left = " << left;
        return true;
      }
    }
    
    return false;
  }

  void processImcompleteHeader(int64_t connId, const char* data, size_t dataLength) {
    if(dataLength < sizeof(uint64_t)){
        VLOG(1) << "Detect imcomplete header seq, connId = " << connId
                << ", dataLength = " << dataLength
                << ", data = " << std::string(data, dataLength);
        std::string imcompSeq(data, dataLength);
        setImcompSeqLen(connId, dataLength);
        setImcompSeq(connId, imcompSeq);

        std::string imcompOffset("");
        setImcompOffsetLen(connId, 0);
        setImcompOffset(connId, imcompOffset);
        VLOG(1) << "Detect imcomplete header seq, connId = " << connId
                << ", writen offset = " << dataLength
                << ", imcompSeq = " << imcompSeq;
    }else{
        uint64_t sequenceNumber = *reinterpret_cast<const uint64_t*>(data);
        setLastReceivedSeq(connId, sequenceNumber);
        data += sizeof(uint64_t);
        VLOG(1) << "Detect imcomplete header offset, connId = " << connId
                << ", dataLength = " << dataLength
                << ", sequenceNumber = " << sequenceNumber
                << ", data = " << std::string(data, dataLength - sizeof(uint64_t));
        std::string imcompOffset(data, dataLength - sizeof(uint64_t));
        
        setImcompOffsetLen(connId, dataLength - sizeof(uint64_t));
        setImcompOffset(connId, imcompOffset);
        VLOG(1) << "Detect imcomplete header offset, connId = " << connId
                << ", writen offset = " << dataLength - sizeof(uint64_t)
                << ", imcompOffset = " << imcompOffset;
    }
  }

  void processDatafield(int64_t connId, const char* data, size_t dataLength) {
    // 不是帧头 处理数据字段
    uint64_t expectedSequenceNumber = getExpectedSequenceNumber();
    uint64_t lastReceivedSeq = getLastReceivedSeq(connId);

    if(lastReceivedSeq == expectedSequenceNumber){
        sendDataToApp(data, dataLength);
        setChunkOffset(dataLength);
        VLOG(1) << "Write data seq = " << expectedSequenceNumber 
                << ", dataLength = " << dataLength
                << ", chunkOffset = " << getChunkOffset()
                << ", chunkTarget = " << getChunkTarget();
        if(getChunkOffset() == getChunkTarget()){
          expectedSequenceNumber++;
          auto& chunkCache = getChunkCache();
          auto it = chunkCache.find(expectedSequenceNumber);
          while (it != chunkCache.end()) {
              auto chunk = it->second;
              char* cachedChunkData = chunk->data.get();
              VLOG(1) << "Find cached seq = " << chunk->sequenceNumber
                      << ", cached data ptr = " << (void*)chunk->data.get()
                      << ", cached data length = " << chunk->offset
                      << ", cached target = " << chunk->total;  
              
              sendDataToApp(cachedChunkData, chunk->offset);
              
              VLOG(1) << "Write cached seq =" << expectedSequenceNumber 
                      << ", chunkoffset" << chunk->offset;

              setChunkOffset(chunk->offset);
              
              setChunkTarget(chunk->total);
              
              if(getChunkOffset() == getChunkTarget()){
                VLOG(1) << "Write cachedata seq =" << expectedSequenceNumber 
                    << ", dataLength = " << chunk->offset  
                    << ", chunkoffset = " << getChunkOffset()
                    << ", chunkTarget = " << getChunkTarget();
                chunkCache.erase(it);
                expectedSequenceNumber++;
                it = chunkCache.find(expectedSequenceNumber);
              }else {
                VLOG(1) << "Write cachedata seq =" << expectedSequenceNumber 
                    << ", dataLength = " << chunk->offset  
                    << ", chunkoffset = " << getChunkOffset()
                    << ", chunkTarget = " << getChunkTarget();
                chunkCache.erase(it);
                break;
              }
          }
          setExpectedSequenceNumber(expectedSequenceNumber);
        }else if(getChunkOffset() > getChunkTarget()){
          VLOG(1) << "Write data beyond target: " << 
          data + dataLength - (getChunkOffset() - getChunkTarget());
        }
      }else{
        auto& chunkCache = getChunkCache();
        VLOG(1) << "lastReceivedSeq = " << lastReceivedSeq << " Address of chunkCache: " << &chunkCache;

        auto it = chunkCache.find(lastReceivedSeq);
        if(it == chunkCache.end()){
          LOG(ERROR) << "Chunk not found in cache, connId = " << connId << " seq = " << lastReceivedSeq;
          exit(1);
        }

        size_t oldLength = it->second->offset;
        size_t total = it->second->total;
        VLOG(1) << "ConnId = " << connId << " Find seq = " << lastReceivedSeq 
        << ", address of chunk = " << it->second
        << " data ptr = " << (void*)it->second->data.get()
        << " before merge length = " << it->second->offset;

        /*auto old_data_ptr = getChunkCache(lastReceivedSeq)->data;
        char* old_data = old_data_ptr.get();*/
        // 2. 计算新长度
        size_t new_length = oldLength + dataLength; // +1 for null terminator

        /*std::shared_ptr<char[]> new_data_ptr(new char[new_length]);

        if(oldLength > 0){
          std::memcpy(new_data_ptr.get(), old_data, oldLength);
        }

        std::memcpy(new_data_ptr.get() + oldLength, data, dataLength);
       
        // 7. 更新 connManager_ 中的 shared_ptr 和 length
        getChunkCache(lastReceivedSeq)->data = new_data_ptr;*/
        auto chunk = it->second;
        if(new_length <= total){
          std::memcpy(chunk->data.get() + oldLength, data, dataLength);
        }else{
          LOG(ERROR) << "Data length beyond target, connId = " << connId << "right length = " << total << "new_length = " << new_length;
          exit(1);
        }
        chunk->offset = new_length;

        VLOG(1) << "ConnId = " << connId << " seq = " << lastReceivedSeq 
        << " data ptr = " << (void*)chunk->data.get()
        << " merged data length = " << chunk->offset;
      }
    
  }

  void processHeaderfield(int64_t connId, const char* data, size_t dataLength) {
      // Process frame header
      // Check if the remaining frame header length is sufficient
      uint64_t sequenceNumber = 0;
      size_t targetOffset = 0;
      uint64_t expectedSequenceNumber = getExpectedSequenceNumber();
      size_t remaiLen = 0;

      if(hasImcompSeqOrLen(connId)){
        int64_t imcompSeqLen = getImcompSeqLen(connId);
        int64_t imcompOffsetLen = getImcompOffsetLen(connId);

        if(imcompSeqLen >= 0){
          std::string imcompSeq = getImcompSeq(connId);
          size_t remain = sizeof(uint64_t) - imcompSeqLen;
          if(remain <= dataLength){
              imcompSeq.append(data, remain);
              VLOG(1) << "Process imcomplete seq, connId = " << connId
                      << ", writen offset = " << remain
                      << ", imcompSeq = " << imcompSeq;
              sequenceNumber = *reinterpret_cast<const uint64_t*>(imcompSeq.c_str());
              data += remain;
              dataLength -= remain;
              setLastReceivedSeq(connId, sequenceNumber);
              setImcompSeqLen(connId, -1);
          }else{
              imcompSeq.append(data, dataLength);
              setImcompSeq(connId, imcompSeq);
              setImcompSeqLen(connId, imcompSeqLen + dataLength);
              return;
          }
        }
        
        if(imcompOffsetLen >= 0){
          std::string imcompOffset = getImcompOffset(connId);
          size_t remain = sizeof(size_t) - imcompOffsetLen;
          VLOG(1) << "Process imcomplete offset, connId = " << connId
                  << ", dataLength bytes = " << imcompOffsetLen
                  << ", imcompOffset = " << imcompOffset;
          if(remain <= dataLength){
            imcompOffset.append(data, remain);
            sequenceNumber = getLastReceivedSeq(connId);
            
            targetOffset = *reinterpret_cast<const size_t*>(imcompOffset.c_str());
            data += remain;
            dataLength -= remain;
            VLOG(1) << "Process imcomplete offset, connId = " << connId
                    << ", sequenceNumber = " << sequenceNumber
                    << ", targetOffset = " << targetOffset;

            setImcompOffsetLen(connId, -1);
          }else{
            imcompOffset.append(data, dataLength);
            setImcompOffset(connId, imcompOffset);
            setImcompOffsetLen(connId, imcompOffsetLen + dataLength);
            return;
          }
        }
      }else{
        if (dataLength < sizeof(uint64_t) + sizeof(size_t)) {
            processImcompleteHeader(connId, data, dataLength);
            return;
        }

        if(sequenceNumber == 0){
          sequenceNumber = *reinterpret_cast<const uint64_t*>(data);
          data += sizeof(uint64_t);
          dataLength -= sizeof(uint64_t);
        }

        if(targetOffset == 0){  
          targetOffset = *reinterpret_cast<const size_t*>(data);
          data += sizeof(size_t);
          dataLength -= sizeof(size_t);
        }
      }
      
      remaiLen = dataLength;
      
      
      VLOG(1) << "Found frame header: seq=" << sequenceNumber 
              << ", targetOffset=" << targetOffset
              << ", dataLength=" << dataLength;
      
      if(targetOffset < remaiLen){
          LOG(ERROR) << "Data length beyond target, connId = " << connId << "beyond = " << data + targetOffset;
          exit(1);
      }

      if (sequenceNumber == expectedSequenceNumber) {
          // 设置到 connManager 中
          setChunkTarget(targetOffset);

          sendDataToApp(data, remaiLen);
        
          setChunkOffset(remaiLen);

          // 写入数据
          VLOG(1) << "Write expected seq = " << sequenceNumber 
                  << ", dataLength = " << remaiLen
                  << ", chunkOffset = " << getChunkOffset()
                  << ", chunkTarget = " << getChunkTarget();

          setLastReceivedSeq(connId, expectedSequenceNumber);
          if(getChunkOffset() == getChunkTarget()){
            expectedSequenceNumber++;
            // 检查缓存中是否有后续连续的 chunk
            auto& chunkCache = getChunkCache();
            auto it = chunkCache.find(expectedSequenceNumber);
            while (it != chunkCache.end()) {
                auto cachedChunk = it->second;
                char* cachedChunkData = cachedChunk->data.get();
                size_t cachedChunkLen = cachedChunk->offset;

                setChunkTarget(cachedChunk->total);
              
                sendDataToApp(cachedChunkData, cachedChunkLen);
                
                setChunkOffset(cachedChunk->offset);

                if(getChunkOffset() == getChunkTarget()){
                  VLOG(1) << "Write cached seq =" << expectedSequenceNumber 
                      << ", dataLength = " << cachedChunk->offset
                      << ", chunkoffset = " << getChunkOffset()
                      << ", chunkTarget = " << getChunkTarget();
                  chunkCache.erase(it);
                  expectedSequenceNumber++;
                  it = chunkCache.find(expectedSequenceNumber);
                }else {
                  VLOG(1) << "Write cached seq =" << expectedSequenceNumber 
                      << ", dataLength = " << cachedChunk->offset
                      << ", chunkoffset = " << getChunkOffset()
                      << ", chunkTarget = " << getChunkTarget();
                  chunkCache.erase(it);
                  break;
                }
                
            }
            setExpectedSequenceNumber(expectedSequenceNumber);
            VLOG(1) << "Now the expected seq = " << expectedSequenceNumber;
          }
        
      } else {
          // not expected sequence number, put into cache
          auto& pool = getShmPool();

          std::shared_ptr<quic::QuicSocket::ChunkData> chunk = std::make_shared<quic::QuicSocket::ChunkData>(
            sequenceNumber,
            targetOffset,
            remaiLen,
            pool,
            data
          );

          setChunkCache(sequenceNumber, chunk);

          VLOG(1) << "Address of chunk object = " 
          << (void*)chunk.get() << ", address stored in cache = " 
          << (void*)getChunkCache(sequenceNumber).get(); // .get() 获取原始指针

          setLastReceivedSeq(connId, sequenceNumber);

          auto cachedChunkPtr = getChunkCache(sequenceNumber);
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

  void mergeData(folly::IOBuf* data, size_t dataLength, int64_t connId, std::string frameLabel) {
      static uint64_t expectedSequenceNumber = getExpectedSequenceNumber();
      
      const char* originalData = (const char*)data->data();

      std::string currentData(originalData, dataLength);

      size_t start = 0, pos = 0, str_len = strlen(frameLabel.c_str()), left = 0;

      frameLabel_ = frameLabel;

      if(isIncompleteFrameLabel(connId)){
        //Check if the head can merge to frame label "FRAME"
        if(isHeadMergeToFrame(currentData, connId, start)){
          //Merge successfully, find the next frame header position
          pos = currentData.find(frameLabel_, start);
          if (pos != std::string::npos) {
              // Find the next frame header, process the data ahead of it
              VLOG(1) << "Process frame head merge to frame, connId = " << connId
                      << ", start = " << start << ", pos = " << pos;
              processHeaderfield(connId, originalData + start, pos - start);
              removeIncompFrameLabelLen(connId);
              start = pos;
          } else {
              // Not found next "Frame" label, choose the processing function based on tail completion
              if (isTailHasIncompFrame(currentData, connId, dataLength, start, pos, true)) {
                  VLOG(1) << "Process frame head merge with incomp tail, connId = " << connId
                          << ", start = " << start << ", pos = " << pos;
                  processHeaderfield(connId, originalData + start, pos - start);
              } else {
                  VLOG(1) << "Process frame head merge without tail, connId = " << connId
                          << ", start = " << start << ", pos = " << pos;
                  processHeaderfield(connId, originalData + start, dataLength - start);
                  removeIncompFrameLabelLen(connId);
              }
              start = dataLength;
          }
        }else{
          //Merge failed, write the last stored string into file
          size_t lastLen = getIncompFrameLabelLen(connId);
          const char* last = frameLabel_.c_str();
          processDatafield(connId, last, lastLen);
          removeIncompFrameLabelLen(connId);
        }
      }
    
      while (start < dataLength) {
        //Find next frame header position
        size_t pos = currentData.find(frameLabel_, start);
        if(pos != std::string::npos){
            if(pos > start){
                /*Find the next frame header "FRAME" Process data ahead of it */
              
                if(hasImcompSeqOrLen(connId)){
                  //Last frame header has imcomplete sequence number or offset, merge it
                  processHeaderfield(connId, originalData + start, pos - start);
                }else{
                  //Process datafield
                  VLOG(1) << "Process datafield, connId = " << connId 
                          << ", start = " << start << ", pos = " << pos
                          << ", dataLength = " << pos - start;
                  processDatafield(connId, originalData + start, pos - start);
                }
            }

            //Start to process the next frame header, strip the "FRAME" label
            start = pos + str_len;
            
            //Find the next frame header position
            size_t nxt_pos = currentData.find(frameLabel_, start);

            if(nxt_pos == std::string::npos){
              //No next frame header, check if the tail has incompleted label "FRAME"
              if(!isTailHasIncompFrame(currentData, connId, dataLength, start, nxt_pos, true)){
                /*There's no frame label "FRAME" in the tail part, set the position of data to be processed as the end, 
                  else use the nxt_pos as the position*/
                nxt_pos = dataLength;
              }
            }
            
            processHeaderfield(connId, originalData + start, nxt_pos - start);

            if(isIncompleteFrameLabel(connId)){
              start = dataLength;
            }else{
              start = nxt_pos;
            }

        }else if(isTailHasIncompFrame(currentData, connId, dataLength, start, pos, false)){
            //Tail has incomp frame label "FRAME", process the data before it
            VLOG(1) << "Tail has incomp frame label, connId = " << connId 
                  << "start = " << start << ", pos = " << pos;
            //The label start position is pos, process the data before it
            if(hasImcompSeqOrLen(connId)){
              /*Last frame header has imcomplete sequence number or offset, merge it and process the data between the 
              start and the tail frame label*/
              processHeaderfield(connId, originalData + start, pos - start);
            }else{
              //Process datafield
              processDatafield(connId, originalData + start, pos - start);
            }
            //The whole data is finished, set the start to dataLength
            start = dataLength;
        }else{
            //No Frame labelor tail, just process the data
            if(hasImcompSeqOrLen(connId)){
              //Process the data with imcomplete sequence number or offset
              processHeaderfield(connId, originalData + start, dataLength - start);
            }else{
              //Process the datafield
              processDatafield(connId, originalData + start, dataLength - start);
            }
            start = dataLength;
        }
     }
  }

  // Build clientStreams_ mapping
  void buildClientStreamsMap(int64_t connectionId, StreamId stream_id) {
    if (clientStreams_.find(connectionId) == clientStreams_.end()) {
      clientStreams_[connectionId] = stream_id;
    }else
      LOG(INFO) << "Connection" << connectionId << "has already created stream" ;
  }

  StreamId getClientStream(int64_t connectionId) {
    auto it = clientStreams_.find(connectionId);
    if (it != clientStreams_.end()) {
      return it->second;
    }
    return StreamId(-1);
  }

  std::unordered_map<uint64_t, std::shared_ptr<QuicSocket::ChunkData>>& getChunkCache() {
    return chunkCache_;
  }

  void setExpectedSequenceNumber(uint64_t expectedSequenceNumber) {
    expectedSequenceNumber_ = expectedSequenceNumber;
  }

  uint64_t getExpectedSequenceNumber() {
    return expectedSequenceNumber_;
  }

  uint64_t getSequenceNumber() {
    return sequenceNumber_;
  }

  void setSequenceNumber(uint64_t sequenceNumber) {
    sequenceNumber_ = sequenceNumber;
  }

  size_t getChunkOffset() {
    return chunkOffset_;
  }

  void setChunkOffset(size_t chunkOffset) {
    chunkOffset_ += chunkOffset;
  }

  size_t getChunkTarget() {
    return chunkTarget_;
  }

  void setChunkTarget(size_t chunkTarget) {
    chunkTarget_ += chunkTarget;
  } 

  uint64_t getLastReceivedSeq(int64_t connectionId) {
    return lastReceivedSeq_[connectionId];
  }

  void setLastReceivedSeq(int64_t connectionId, uint64_t lastReceivedSeq) {
    lastReceivedSeq_[connectionId] = lastReceivedSeq;
  }

  int64_t getImcompOffsetLen(int64_t connectionId) {
    auto it = imcompOffsetLen_.find(connectionId);
    if(it != imcompOffsetLen_.end()) {
      return it->second;
    }
    return -1;
  }

  int64_t getImcompSeqLen(int64_t connectionId) {
    auto it = imcompSeqLen_.find(connectionId);
    if(it != imcompSeqLen_.end()) {
      return it->second;
    }
    return -1;
  }

  bool hasImcompSeqOrLen(int64_t connectionId) {
    return getImcompOffsetLen(connectionId) > -1
    || getImcompSeqLen(connectionId) > -1;
  }

  void setImcompOffsetLen(int64_t connectionId, int64_t len) {
    imcompOffsetLen_[connectionId] = len;
  }

  void setImcompSeqLen(int64_t connectionId, int64_t len) {
    imcompSeqLen_[connectionId] = len;
  }

  std::string getImcompOffset(int64_t connectionId) {
    return imcompOffset_[connectionId];
  }

  void setImcompOffset(int64_t connectionId, std::string imcompOffset) {
    imcompOffset_[connectionId] = imcompOffset;
  }

  std::string getImcompSeq(int64_t connectionId) {
    return imcompSeq_[connectionId];
  } 

  void setImcompSeq(int64_t connectionId, std::string imcompSeq) {
    imcompSeq_[connectionId] = imcompSeq;
  }

  size_t getIncompFrameLabelLen(int64_t connectionId) {
    return incompFrameLabelLen_[connectionId];
  }

  void setIncompFrameLabelLen(int64_t connectionId, size_t incompFrameLen) {
    incompFrameLabelLen_[connectionId] = incompFrameLen;
  }

  RingBuffer<char>& getShmPool() {
    return shmPool_;
  }

  void removeIncompFrameLabelLen(int64_t connectionId) {
    auto it = incompFrameLabelLen_.find(connectionId);
    if(it != incompFrameLabelLen_.end()) {
      incompFrameLabelLen_.erase(it);
    }
  }

  bool isIncompleteFrameLabel(int64_t connectionId) {
    auto it = incompFrameLabelLen_.find(connectionId);
    if(it != incompFrameLabelLen_.end()) {
      return true;
    }
    return false;
  }

  void reserverChunkCache() {
      size_t capacity = 1 << 21;
      chunkCache_.reserve(capacity);
      chunkCache_.max_load_factor(0.75f);
      pendingDestruction_.reserve(kDestroyBatch);
  }

  void setChunkCache(uint64_t sequenceNumber, std::shared_ptr<QuicSocket::ChunkData> chunk) {
    chunkCache_[sequenceNumber] = std::move(chunk);
    if (chunkCache_.size() > chunkCache_.bucket_count() * 0.75f * 0.95f) {  // 95%水位触发
        size_t newBucketCount = chunkCache_.bucket_count() * 2;     // 翻倍扩容
        chunkCache_.reserve(newBucketCount);
    }
  }

  void removeChunkCache(uint64_t sequenceNumber) {
    auto it = chunkCache_.find(sequenceNumber);
    if (it != chunkCache_.end()) {
        /* delay destroy */
        /*pendingDestruction_.push_back(std::move(it->second));
        if (pendingDestruction_.size() >= kDestroyBatch) {
            pendingDestruction_.clear();    // trigger batch destroy
        }*/
        chunkCache_.erase(it);
    }
  }

  void emptyChunkCache(uint64_t sequenceNumber) {
    auto it = chunkCache_.find(sequenceNumber);
    if (it != chunkCache_.end()) {
      it->second->reset();
    }
  }

  std::shared_ptr<QuicSocket::ChunkData> getChunkCache(uint64_t sequenceNumber) {
    auto it = chunkCache_.find(sequenceNumber);
    if (it != chunkCache_.end()) {
      return it->second;
    }
    return nullptr;
  }
};

struct sock{
public:
    sock() {
        this->id = -1;
        this->rtt = 0;
        this->cwnd = 0;
        this->ssthresh = 0;
        this->unacked = 0;
        this->mss = 0;
        this->is_idle = true;
        this->last_used_time = 0;
        this->transport = nullptr;
    }

    void setConnStatus(int64_t id) {
        if (!transport) return;
        auto state = transport->getState();
        if (!state) return;

        this->id = id;
        this->rtt = state->lossState.srtt.count();

        if (state->congestionController) {
            this->cwnd = state->congestionController->getCongestionWindow();

            CongestionControllerStats stats;
            state->congestionController->getStats(stats);
            switch (state->congestionController->type()) {
                case CongestionControlType::Cubic:
                    this->ssthresh = stats.cubicStats.ssthresh;
                    break;
                default:
                    this->ssthresh = 0;
            }
        } else {
            this->cwnd = 0;
            this->ssthresh = 0;
        }

        this->unacked = state->lossState.inflightBytes;
        this->mss = state->udpSendPacketLen;
        this->is_idle = (this->unacked == 0);

        if (state->lossState.lastAckedTime.has_value()) {
            auto duration_since_epoch = state->lossState.lastAckedTime.value().time_since_epoch();
            this->last_used_time = std::chrono::duration_cast<std::chrono::milliseconds>(duration_since_epoch).count();
        } else {
            this->last_used_time = 0;
        }
    }

    bool isIdle() {
        // 检查未确认字节是否为0
        bool noUnacked = (getUnacked() == 0);
        
        // 检查是否有可写流
        bool noPendingSend = true;
        auto state = transport ? transport->getState() : nullptr;
        if (state && state->streamManager) {
            // 使用 streamManager->hasWritable() 判断是否有待发送的数据
            noPendingSend = !state->streamManager->hasWritable();
        }

        // 只有当没有未确认字节且没有待发送数据时，才认为空闲
        this->is_idle = noUnacked && noPendingSend;
        return this->is_idle;
    }

    void setIdle(bool isIdle) {
        this->is_idle = isIdle;
    }

    void setLastUsedTime(uint64_t lastUsedTime) {
        this->last_used_time = lastUsedTime;
    }

    int64_t getConnId() {
        return this->id;
    }

    void setTransport(std::shared_ptr<QuicTransportBase> transport) {
        this->transport = transport;
    }
    
    // 添加获取RTT的方法
    uint64_t getRtt() {
        auto state = transport->getState();
        if (!state) return 0;
        this->rtt = state->lossState.srtt.count();
        return this->rtt;
    }
    
    // 添加获取拥塞窗口的方法
    uint64_t getCwnd() {
        auto state = transport->getState();
        if (!state) return 0;
        this->cwnd = state->congestionController->getCongestionWindow();
        return this->cwnd;
    }

    // 添加获取未确认字节数的方法
    uint64_t getUnacked() {
        auto state = transport->getState();
        if (!state) return 0;
        this->unacked = state->lossState.inflightBytes;
        return this->unacked;
    }

    bool isGood() {
        return this->transport && this->transport->good();
    }

    bool isPendingSend() {
        uint64_t minCwndBytes = 0;
        auto state = this->transport->getState();
        if (state->udpSendPacketLen > 0) { 
             minCwndBytes = state->transportSettings.minCwndInMss * state->udpSendPacketLen;
        } else {
             minCwndBytes = state->transportSettings.minCwndInMss * kDefaultUDPSendPacketLen;
        }
        uint64_t currentCwndBytes = this->getCwnd(); 
        if (currentCwndBytes < minCwndBytes) {
            LOG(ERROR) << "Subflow " << id << " Cwnd too small (" << currentCwndBytes << " < " << minCwndBytes << " bytes)";
            return false;
        }
        return true;
    }

    bool isLastUsedTime() {
        auto state = transport->getState();
        if (!state || !state->lossState.lastAckedTime.has_value()) {
            // 如果没有收到过ACK，或者无法获取状态，可以认为它不活跃（或根据需求处理）
            LOG(ERROR) << "Subflow " << id << " has no lastAckedTime or state";
            return false; // 或者 true，取决于如何定义从未收到ACK的情况
        }

        auto lastAck = state->lossState.lastAckedTime.value(); // steady_clock::time_point
        auto steady_now = std::chrono::steady_clock::now();
        
        auto idle_duration = steady_now - lastAck; // 计算steady_clock的差值
        auto idle_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(idle_duration);

        VLOG(2) << "Subflow " << id << " steady_now: " << steady_now.time_since_epoch().count() 
                 << " last ack: " << lastAck.time_since_epoch().count() 
                 << " idle duration ms: " << idle_duration_ms.count();
                 
        const uint64_t maxIdleTimeMs = 10000 * 60; 
        if (idle_duration_ms.count() > maxIdleTimeMs) {
            LOG(ERROR) << "Subflow " << id << " inactive for too long (" << idle_duration_ms.count() << "ms)";
            return false;
        }     
        return true;
    }
    // 添加获取 transport 的方法
    std::shared_ptr<QuicTransportBase> getTransport() {
        return this->transport;
    }

    // Get last used time in milliseconds since epoch (for external use if needed, maybe rename)
    // Note: This interpretation might be misleading if lastAckedTime is steady_clock based.
    uint64_t getLastUsedTimeMsSinceEpoch() { // Renamed for clarity
        auto state = transport->getState();
        if (!state) return 0;
        if (state->lossState.lastAckedTime.has_value()) {
            // WARNING: Converting steady_clock to system_clock equivalent is complex
            // and potentially inaccurate. This provides the millisecond count
            // since steady_clock's epoch, NOT system_clock's epoch.
            // For comparing durations, use the steady_clock approach in isLastUsedTime().
            auto duration_since_steady_epoch = state->lossState.lastAckedTime.value().time_since_epoch();
            return std::chrono::duration_cast<std::chrono::milliseconds>(duration_since_steady_epoch).count();
        } else {
            return 0;
        }
    }

private:
    int64_t id;
    uint64_t rtt;
    uint64_t cwnd;
    uint64_t ssthresh;
    uint64_t unacked;
    uint64_t mss;
    bool is_idle;
    uint64_t last_used_time;
    std::shared_ptr<QuicTransportBase> transport;
};

struct subflow_send_info {
	struct sock *ssk;
	uint64_t linger_time;
};

#define MPTCP_SCHED_SIZE 10

// 定义mptcp_subflow_context结构体
struct mptcp_subflow_context {
  public:
    int16_t subflow_id;
    struct sock *ssk;
    bool backup;
    bool request_bkup;
    int stale_count;
    mptcp_subflow_context(int subflow_id) {
        this->subflow_id = subflow_id;
        this->ssk = new struct sock();
        this->backup = false;
        this->request_bkup = false;
        this->stale_count = 0;
    }
    uint8_t mptcp_sched[MPTCP_SCHED_SIZE] __attribute__((aligned(8)));
};

struct mptcp_sock {
public:
    virtual ~mptcp_sock() = default;
    mptcp_sock() {
        connManager = nullptr;
        connStates = std::unordered_map<int64_t, std::shared_ptr<struct mptcp_subflow_context>>();
    }
    std::shared_ptr<ConnectionManager> connManager;
    
    std::unordered_map<int64_t, std::shared_ptr<struct mptcp_subflow_context>> connStates;
    void updateConnStatus(int64_t id, std::shared_ptr<QuicTransportBase> transport) {
        auto connStatus = std::make_shared<struct mptcp_subflow_context>(id);
    
        connStatus->ssk->setTransport(transport);
        connStatus->ssk->setConnStatus(id);
        connStates[id] = connStatus;
    }
};

} // namespace quic
