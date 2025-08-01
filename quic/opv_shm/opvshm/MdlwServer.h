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
#include <quic/opv_shm/opvshm/EchoHandler.h>
#include <quic/opv_shm/opvshm/LogQuicStats.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

#include <semaphore.h>
#include <shm_sock.h>

namespace quic::opv_shm {

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
      std::shared_ptr<client_info_t> client_info = nullptr,
      int shm_fifo_write_fd = -1,
      int shm_fifo_read_fd = -1)
      : useDatagrams_(useDatagrams), disableRtx_(disableRtx), mptcp_sock_(mptcp_sock), 
        client_info_(client_info), shm_fifo_write_fd_(shm_fifo_write_fd), shm_fifo_read_fd_(shm_fifo_read_fd) {}

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
    echoHandler->setShmConfig(connNum_, client_info_, shm_fifo_write_fd_, shm_fifo_read_fd_);
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
  std::shared_ptr<client_info_t> client_info_{nullptr};
  int shm_fifo_write_fd_{-1};
  int shm_fifo_read_fd_{-1};
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

    settings.idleTimeout = std::chrono::milliseconds(600000);

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

    client_info_ = std::make_shared<client_info_t>();
    client_info_->client_id = -1;
    client_info_->config = config;

    int cid = 1;
    int shm_sock_id = shm_socket(cid, shm_config->shm_size, 0);
    if (shm_sock_id == -1) {
        LOG(ERROR) << "Failed to create shm socket";
        exit(EXIT_FAILURE);
    }
    LOG(INFO) << "Successfully created shm socket " << shm_sock_id;

    // 创建shm连接
    struct sockaddr_in server_addr;
    if (shm_connect(shm_sock_id, NULL, sizeof(server_addr)) == -1) {
        LOG(ERROR) << "Failed to create shm connection";
        exit(EXIT_FAILURE);
    }
    LOG(INFO) << "Successfully created shm connection " << shm_sock_id;

    client_info_->shm_sock = shm_sock_id;

    initShmAndFifo();
    
    for(int i = 0; i < 1; ++i) {
      auto server_ = QuicServer::createQuicServer(std::move(settings));
      server_->setQuicServerTransportFactory(
          std::make_unique<DlwServerTransportFac>(useDatagrams, disableRtx, mptcp_sock_, client_info_, shm_fifo_write_fd_, shm_fifo_read_fd_));
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
        LOG(ERROR) << "Failed to open config file: " << filename;
        return -1;
    }

    // 解析配置文件
    if (fscanf(file, "server_ip=%15s\n", config->server_ip) != 1) {
        LOG(ERROR) << "Failed to parse 'server_ip' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "port=%d\n", &config->port) != 1) {
        LOG(ERROR) << "Failed to parse 'port' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "packet_length=%d\n", &config->packet_length) != 1) {
        LOG(ERROR) << "Failed to parse 'packet_length' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "test_duration=%d\n", &config->test_duration) != 1) {
        LOG(ERROR) << "Failed to parse 'test_duration' from " << filename;
        fclose(file);
        return -1;
    }
    if (fscanf(file, "conn_num=%d\n", &config->conn_num) != 1) {
        LOG(ERROR) << "Failed to parse 'conn_num' from " << filename;
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
  }

  void initShmAndFifo() {

    // 1. Check if client_info and its shm_sock are valid
    if (!client_info_ || client_info_->shm_sock < 0) {
      LOG(ERROR) << "client_info or shm_sock is not valid. Cannot initialize SHM transport.";
      return;
    }

    // 2. Set FIFO paths based on the other process's logic
    std::string shm_fifo_write_path_ = "/tmp/qs_fifo_" + std::to_string(client_info_->shm_sock);
    std::string shm_fifo_read_path_ = "/tmp/sq_fifo_" + std::to_string(client_info_->shm_sock);

    // 3. Open the write FIFO (qs_fifo)
    // The other process is expected to have created this FIFO for reading.
    // We add a small delay to give the other process a chance to create it.
    auto start_time = std::chrono::steady_clock::now();
    while(shm_fifo_write_fd_ == -1) {
      shm_fifo_write_fd_ = ::open(shm_fifo_write_path_.c_str(), O_WRONLY | O_NONBLOCK);
      if (shm_fifo_write_fd_ == -1) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
        if (elapsed >= 5) {
          LOG(ERROR) << "Timeout waiting for write FIFO '" << shm_fifo_write_path_ << "' to be ready after 5 seconds";
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }

    // 4. Open the read FIFO (sq_fifo)
    start_time = std::chrono::steady_clock::now();
    while(shm_fifo_read_fd_ == -1) {
      shm_fifo_read_fd_ = ::open(shm_fifo_read_path_.c_str(), O_RDONLY | O_NONBLOCK);
      if (shm_fifo_read_fd_ == -1) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
        if (elapsed >= 5) {
          LOG(ERROR) << "Timeout waiting for read FIFO '" << shm_fifo_read_path_ << "' to be ready after 5 seconds";
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }

    LOG(INFO) << "SHM transport initialized. Socket: " << client_info_->shm_sock
              << ", Write FIFO: " << shm_fifo_write_path_ << " (fd: " << shm_fifo_write_fd_
              << "), Listen FIFO: " << shm_fifo_read_path_ << " (fd: " << shm_fifo_read_fd_
              << ")";
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    int i = 1;
    auto connManager = std::make_shared<SrvConnection>();
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
  std::shared_ptr<client_info_t> client_info_{nullptr};
  int shm_fifo_write_fd_{-1};
  int shm_fifo_read_fd_{-1};
};
} // namespace quic::samples
