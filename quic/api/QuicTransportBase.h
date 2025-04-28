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
 public:
  // Add virtual destructor
  virtual ~ConnectionManager() = default;

  ConnectionManager(uint64_t capacity) : capacity_(capacity) 
  {
    lastReceivedSeq_ = std::unordered_map<int64_t, uint64_t>();
    imcompOffsetLen_ = std::unordered_map<int64_t, int64_t>();
    imcompSeqLen_ = std::unordered_map<int64_t, int64_t>();
    imcompOffset_ = std::unordered_map<int64_t, std::string>();
    imcompSeq_ = std::unordered_map<int64_t, std::string>();
    incompFrameLen_ = std::unordered_map<int64_t, size_t>();
    chunkCache_ =  std::unordered_map<uint64_t, std::shared_ptr<QuicSocket::ChunkData>>();
  }

  virtual std::vector<int64_t> getAllConnectionIds() = 0;

  virtual bool empty() = 0;

  virtual uint64_t getsize() = 0;

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

  bool hasImcomp(int64_t connectionId) {
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

  size_t getIncompFrameLen(int64_t connectionId) {
    return incompFrameLen_[connectionId];
  }

  void setIncompFrameLen(int64_t connectionId, size_t incompFrameLen) {
    incompFrameLen_[connectionId] = incompFrameLen;
  }

  void removeIncompFrameLen(int64_t connectionId) {
    auto it = incompFrameLen_.find(connectionId);
    if(it != incompFrameLen_.end()) {
      incompFrameLen_.erase(it);
    }
  }

  bool isIncompleteFrame(int64_t connectionId) {
    auto it = incompFrameLen_.find(connectionId);
    if(it != incompFrameLen_.end()) {
      return true;
    }
    return false;
  }

  void setChunkCache(uint64_t sequenceNumber, std::shared_ptr<QuicSocket::ChunkData> chunk) {
    chunkCache_[sequenceNumber] = chunk;
  }

  void removeChunkCache(uint64_t sequenceNumber) {
    chunkCache_.erase(sequenceNumber);
  }

  void emptyChunkCache(uint64_t sequenceNumber) {
    auto it = chunkCache_.find(sequenceNumber);
    if (it != chunkCache_.end()) {
      it->second->offset = 0;
      it->second->total = 0;
    }
  }

  std::shared_ptr<QuicSocket::ChunkData> getChunkCache(uint64_t sequenceNumber) {
    auto it = chunkCache_.find(sequenceNumber);
    if (it != chunkCache_.end()) {
      return it->second;
    }
    return nullptr;
  }

 protected:
  uint64_t capacity_;
  std::unordered_map<int64_t, StreamId> clientStreams_;
  std::unordered_map<uint64_t, std::shared_ptr<QuicSocket::ChunkData>> chunkCache_;
  
  size_t chunkOffset_{0};
  size_t chunkTarget_{0};
  uint64_t expectedSequenceNumber_{0};
  
  std::unordered_map<int64_t, size_t> incompFrameLen_;
  std::unordered_map<int64_t, int64_t> imcompSeqLen_;
  std::unordered_map<int64_t, int64_t> imcompOffsetLen_;

  std::unordered_map<int64_t, uint64_t> lastReceivedSeq_;

  std::unordered_map<int64_t, std::string> imcompSeq_;
  std::unordered_map<int64_t, std::string> imcompOffset_;
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
    }

    void setConnStatus(int64_t id, std::shared_ptr<QuicTransportBase> transport) {
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
            this->last_used_time = state->lossState.lastAckedTime.value().time_since_epoch().count();
        } else {
            this->last_used_time = 0;
        }
    }

    bool isIdle() {
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

private:
    int64_t id;
    uint64_t rtt;
    uint64_t cwnd;
    uint64_t ssthresh;
    uint64_t unacked;
    uint64_t mss;
    bool is_idle;
    uint64_t last_used_time;
};

struct subflow_send_info {
	struct sock *ssk;
	uint64_t linger_time;
};

struct mptcp_sock {
public:
    virtual ~mptcp_sock() = default;
    mptcp_sock() {
        connManager = nullptr;
        connStates = std::unordered_map<int64_t, std::shared_ptr<struct sock>>();
    }
    std::shared_ptr<ConnectionManager> connManager;
    
    std::unordered_map<int64_t, std::shared_ptr<struct sock>> connStates;
    void updateConnStatus(int64_t id, std::shared_ptr<QuicTransportBase> transport) {
        auto connStatus = std::make_shared<struct sock>();
        connStatus->setConnStatus(id, transport);
        connStates[id] = connStatus;
    }
};

} // namespace quic
