/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Synchronized.h>
#include <glog/logging.h>

#include <quic/common/test/TestUtils.h>
#include <quic/multipath/mdlw/EchoHandler.h>
#include <quic/multipath/mdlw/LogQuicStats.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace quic::multipath {

class DlwServerTransportFac : public quic::QuicServerTransportFactory {
 public:
  ~DlwServerTransportFac() override {
    draining_ = true;
    echoHandlers_.withWLock([](auto& echoHandlers) {
      while (!echoHandlers.empty()) {
        auto& handler = echoHandlers.back();
        handler->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
            [&] {
              // The evb should be performing a sequential consistency atomic
              // operation already, so we can bank on that to make sure the
              // writes propagate to all threads.
              echoHandlers.pop_back();
            });
      }
    });
  }

  explicit DlwServerTransportFac(
      bool useDatagrams = false,
      bool disableRtx = false)
      : useDatagrams_(useDatagrams), disableRtx_(disableRtx) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> sock,
      const folly::SocketAddress&,
      QuicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    CHECK_EQ(evb, sock->getEventBase());
    if (draining_) {
      return nullptr;
    }
    auto echoHandler =
        std::make_unique<DlwHandler>(evb, useDatagrams_, disableRtx_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), echoHandler.get(), echoHandler.get(), ctx);
    echoHandler->setQuicSocket(transport);
    echoHandlers_.withWLock([&](auto& echoHandlers) {
      echoHandlers.push_back(std::move(echoHandler));
    });
    return transport;
  }

 private:
  bool useDatagrams_;
  folly::Synchronized<std::vector<std::unique_ptr<DlwHandler>>> echoHandlers_;
  bool draining_{false};
  bool disableRtx_{false};
};

class MdlwServer {
 public:
  explicit MdlwServer(
      std::vector<std::string> alpns,
      const std::string& host = "::1",
      uint16_t port = 6666,
      bool useDatagrams = false,
      uint64_t activeConnIdLimit = 10,
      bool enableMigration = true,
      bool enableStreamGroups = false,
      bool disableRtx = false)
      : host_(host), port_(port), alpns_(std::move(alpns)) {
    TransportSettings settings;
    settings.datagramConfig.enabled = useDatagrams;
    settings.selfActiveConnectionIdLimit = activeConnIdLimit;
    settings.disableMigration = !enableMigration;

    if (enableStreamGroups) {
      settings.notifyOnNewStreamsExplicitly = true;
      settings.advertisedMaxStreamGroups = 1024;
    }
    if (disableRtx) {
      if (!enableStreamGroups) {
        LOG(FATAL) << "disable_rtx requires use_stream_groups to be enabled";
      }
    }
    
    for(int i = 0; i < 1; ++i) {
      auto server_ = QuicServer::createQuicServer(std::move(settings));
      server_->setQuicServerTransportFactory(
          std::make_unique<DlwServerTransportFac>(useDatagrams, disableRtx));
      server_->setTransportStatsCallbackFactory(
          std::make_unique<LogQuicStatsFac>());
      auto serverCtx = quic::test::createServerCtx();
      serverCtx->setClock(std::make_shared<fizz::SystemClock>());
      serverCtx->setSupportedAlpns(std::move(alpns_));
      server_->setFizzContext(serverCtx);
      servers_.push_back(server_);
    }
  }

  ~MdlwServer() {
    for(auto server_ : servers_) {
      server_->shutdown();
    }
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    int i = 1;
    for(auto server_ : servers_) {
      //folly::SocketAddress addr1("30.1." + std::to_string(i + 1) + ".100", port_);
      folly::SocketAddress addr1(host_, port_);
      server_->start(addr1, 1);
      i++; 
      LOG(INFO) << "Echo server" << i << " started at: " << addr1.describe();
    }
    eventbase_.loopForever();
  }

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventbase_;
  std::vector<std::shared_ptr<quic::QuicServer>> servers_;
  std::vector<std::string> alpns_;
};
} // namespace quic::samples
