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
#include <quic/shm_mp/shmdlw/EchoHandler.h>
#include <quic/shm_mp/shmdlw/LogQuicStats.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

#include <semaphore.h>
#include <shm_sock.h>

namespace quic::shm_mp {

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

  std::shared_ptr<folly::Synchronized<std::vector<std::unique_ptr<DlwHandler>>>> 
  getHandlers() {
    return std::make_shared<folly::Synchronized<std::vector<std::unique_ptr<DlwHandler>>>>(std::move(echoHandlers_));
  }

  explicit DlwServerTransportFac(
      bool useDatagrams = false,
      bool disableRtx = false,
      struct mptcp_sock* mptcp_sock = nullptr,
      config_t *config = nullptr,
      shm_config_t *shm_config = nullptr,
      sem_t *sem_r = nullptr,
      sem_t *sem_w = nullptr)
      : useDatagrams_(useDatagrams), disableRtx_(disableRtx), mptcp_sock_(mptcp_sock), 
      config_(config), shm_config_(shm_config), sem_r_(sem_r), sem_w_(sem_w){}

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
    echoHandler->setShmConfig(connNum_, config_, shm_config_, sem_r_, sem_w_);
    auto connManager = std::dynamic_pointer_cast<SrvConnection>(mptcp_sock_->connManager);
    connManager->addConnection(connNum_, transport);
    echoHandler->setHandlers(&echoHandlers_, mptcp_sock_);
    echoHandlers_.withWLock([&](auto& echoHandlers) {
      echoHandlers.push_back(std::move(echoHandler));
    });
    
    connNum_++;

    return transport;
  }

 private:
  bool useDatagrams_;
  folly::Synchronized<std::vector<std::unique_ptr<DlwHandler>>> echoHandlers_;
  bool draining_{false};
  bool disableRtx_{false};
  struct mptcp_sock* mptcp_sock_;
  uint64_t connNum_{0};
  config_t *config_{nullptr};
  shm_config_t *shm_config_{nullptr};
  sem_t *sem_r_{nullptr};
  sem_t *sem_w_{nullptr};
};

class ShmMdlwServer {
 public:
  explicit ShmMdlwServer(
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

    mptcp_sock_ = new struct mptcp_sock();

    config_t *config = (config_t *)malloc(sizeof(config_t));
    const char *config_file = "cli.conf";
    shm_config_t *shm_config = read_config(config_file);
    shm_init_global(*shm_config);

    if (read_cli_config("config.txt", config) != 0) {
        LOG(ERROR) << "Failed to read config file";
        exit(EXIT_FAILURE);
    }

    void *ptr = read_shm("sem_r");
    if(ptr == NULL){
        LOG(ERROR) << "Read sem_r shm failed.";
        exit(EXIT_FAILURE);
    }

    sem_t *sem_r = (sem_t *)ptr;

    void *wptr = read_shm("sem_w");
    if(wptr == NULL){
        LOG(ERROR) << "Read sem_w shm failed.";
        exit(EXIT_FAILURE);
    }

    sem_t *sem_w = (sem_t *)wptr;
    
    for(int i = 0; i < 1; ++i) {
      auto server_ = QuicServer::createQuicServer(std::move(settings));
      server_->setQuicServerTransportFactory(
          std::make_unique<DlwServerTransportFac>(useDatagrams, disableRtx, mptcp_sock_, config, shm_config, sem_r, sem_w));
      server_->setTransportStatsCallbackFactory(
          std::make_unique<LogQuicStatsFac>());
      auto serverCtx = quic::test::createServerCtx();
      serverCtx->setClock(std::make_shared<fizz::SystemClock>());
      serverCtx->setSupportedAlpns(std::move(alpns_));
      server_->setFizzContext(serverCtx);
      servers_.push_back(server_);
    }
  }

  ~ShmMdlwServer() {
    for(auto server_ : servers_) {
      server_->shutdown();
    }
  }

  int read_cli_config(const char *filename, config_t *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        LOG_ERROR(__func__, "Failed to open config file");
        return -1;
    }

    // 解析配置文件
    fscanf(file, "server_ip=%15s\n", config->server_ip);
    fscanf(file, "port=%d\n", &config->port);
    fscanf(file, "packet_length=%d\n", &config->packet_length);
    fscanf(file, "test_duration=%d\n", &config->test_duration);
    fscanf(file, "conn_num=%d\n", &config->conn_num);

    fclose(file);
    return 0;
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    int i = 1;
    auto connManager = std::make_shared<SrvConnection>(10, nullptr);
    connManager->setScheduler("rr", mptcp_sock_);
    mptcp_sock_->connManager = connManager;

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
  struct mptcp_sock* mptcp_sock_;
};
} // namespace quic::samples
