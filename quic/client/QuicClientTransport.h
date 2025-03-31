/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/client/QuicClientTransportLite.h>

namespace quic {

class QuicClientTransport : public QuicTransportBase,
                            public QuicClientTransportLite {
 public:
  QuicClientTransport(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false)
      : QuicTransportBaseLite(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicTransportBase(evb, nullptr, useConnectionEndWithErrorCallback),
        QuicClientTransportLite(
            evb,
            nullptr,
            std::move(handshakeFactory),
            connectionIdSize,
            useConnectionEndWithErrorCallback),
        wrappedObserverContainer_(this) {
    conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  }

  // Testing only API:
  QuicClientTransport(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize,
      PacketNum startingPacketNum,
      bool useConnectionEndWithErrorCallback = false)
      : QuicTransportBaseLite(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicTransportBase(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicClientTransportLite(
            evb,
            std::move(socket),
            std::move(handshakeFactory),
            connectionIdSize,
            startingPacketNum,
            useConnectionEndWithErrorCallback),
        wrappedObserverContainer_(this) {
    conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  }

  virtual ~QuicClientTransport() override;

  /**
   * Returns an un-connected QuicClientTransportLite which is self-owning.
   * The transport is cleaned up when the app calls close() or closeNow() on the
   * transport, or on receiving a terminal ConnectionCallback supplied on
   * start().
   * The transport is self owning in this case is to be able to
   * deal with cases where the app wants to dispose of the transport, however
   * the peer is still sending us packets. If we do not keep the transport alive
   * for this period, the kernel will generate unwanted ICMP echo messages.
   */
  template <class TransportType = QuicClientTransport>
  static std::shared_ptr<TransportType> newClient(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> sock,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false) {
    auto client = std::make_shared<TransportType>(
        evb,
        std::move(sock),
        std::move(handshakeFactory),
        connectionIdSize,
        useConnectionEndWithErrorCallback);
    client->setSelfOwning();
    return client;
  }

 protected:
  // From QuicSocket
  [[nodiscard]] virtual SocketObserverContainer* getSocketObserverContainer()
      const override {
    return wrappedObserverContainer_.getPtr();
  }

 private:
  // Container of observers for the socket / transport.
  //
  // This member MUST be last in the list of members to ensure it is destroyed
  // first, before any other members are destroyed. This ensures that observers
  // can inspect any socket / transport state available through public methods
  // when destruction of the transport begins.
  const WrappedSocketObserverContainer wrappedObserverContainer_;
};

class ConnectionManager {
 public:
  ConnectionManager(uint64_t capacity) : capacity_(capacity) {}
  // Add connection
  void addConnection(int64_t connectionId, std::shared_ptr<QuicClientTransport> connection) {
    if (connectionId > -1) {
        if (connections_.size() >= capacity_) {
            LOG(ERROR) << "ConnectionManager capacity is full";
            return;
        }
        connections_[connectionId] = connection; // 更新索引
    }else 
        LOG(ERROR) << "ConnIdx is empty" ;
  }

  std::vector<int64_t> getAllConnectionIds() {
    std::vector<int64_t> allConnectionIds;
    for (const auto& pair : connections_) {
      allConnectionIds.push_back(pair.first);
    }
    return allConnectionIds;
  }

  // Get connection
  std::shared_ptr<QuicClientTransport> getConnection(int64_t& connectionId) {
    auto it = connections_.find(connectionId);
    if (it != connections_.end()) {
      return it->second;
    }
    return nullptr; // Connection not exist
  }

  // Build clientStreams_ mapping
  void buildClientStreamsMap(int64_t connectionId, StreamId stream_id) {
    if (clientStreams_.find(connectionId) == clientStreams_.end()) {
      clientStreams_[connectionId] = stream_id;
    }else
      LOG(INFO) << "Connection" << connectionId << "has already created stream" ;
  }

  StreamId getClientStream(int64_t connectionId){
    auto it = clientStreams_.find(connectionId);
    if (it != clientStreams_.end()) {
      return it->second;
    }
    return StreamId(-1);
  }

  // Destroy connection
  void removeConnection(int64_t connectionId) {
    connections_.erase(connectionId);
  }

  std::pair<int64_t, std::shared_ptr<QuicClientTransport>> getBestConnection() {
    if (connections_.empty()) {
      return std::make_pair(int64_t(), nullptr);
    }
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(0, connections_.size() - 1);

    auto it = connections_.begin();
    std::advance(it, dis(gen));
    return std::make_pair(it->first, it->second);
  }

 private:
  uint64_t capacity_; 
  std::unordered_map<int64_t, std::shared_ptr<QuicClientTransport>> connections_;
  std::unordered_map<int64_t, StreamId> clientStreams_;
};

} // namespace quic
