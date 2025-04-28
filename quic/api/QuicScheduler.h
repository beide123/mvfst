#pragma once

#include <cstdint>
#include <unordered_map>

#include "QuicTransportBase.h"

namespace quic {

class QuicScheduler {
public:
    virtual ~QuicScheduler() = default;
    
    // get next connection id to send data
    virtual int64_t getNextConnectionId(struct mptcp_sock* mptcp_sock) = 0;
    
    // get idle connection id for retransmission
    virtual int64_t getIdleConnectionId(struct mptcp_sock* mptcp_sock) = 0;
    
    // update connection status
    virtual void updateConnectionStatus(struct sock* sock, bool isIdle) = 0;
};

class RoundRobinScheduler : public QuicScheduler {
public:
    RoundRobinScheduler() : currentIndex_(-1) {}
    
    int64_t getIdleConnectionId(struct mptcp_sock* msk) override {
        // 查找第一个空闲的连接
        auto ids = msk->connManager->getAllConnectionIds();
        auto states = msk->connStates;

        if (ids.empty()) return -1;
        for (const auto& id : ids) {
            VLOG(1) << "RoundRobinScheduler get idle connection id: " << id
                    << " isIdle: " << states[id]->isIdle();
            if (states[id]->isIdle()) {
                VLOG(1) << "RoundRobinScheduler get idle connection id: " << id;
                return id;
            }
        }
        return -1;
    }

    void updateConnectionStatus(struct sock* sock, bool isIdle) override {
        // 更新连接状态，例如更新其活跃度等
        // 这里可以维护一个内部状态表
        if(sock == nullptr) return;
        if(sock->isIdle()) {
            sock->setIdle(isIdle);
        }
        uint64_t lastUsedTime = std::chrono::system_clock::now().time_since_epoch().count();
        sock->setLastUsedTime(lastUsedTime);
    }

    struct sock *mptcp_rr_subflow_get_send(struct mptcp_sock *msk) {
        auto ids = msk->connManager->getAllConnectionIds();
        auto states = msk->connStates;
        if(ids.empty()) return nullptr;

        if(currentIndex_ == -1) {
            auto idleId = getIdleConnectionId(msk);
            if(idleId == -1) {
                currentIndex_ = 0;
            }else{
                currentIndex_ = idleId;
            }
        }else{
            currentIndex_ = (currentIndex_ + 1) % ids.size();
        }

        VLOG(1) << "RoundRobinScheduler get send connection id: " << currentIndex_;

        updateConnectionStatus(states[currentIndex_].get(), false);
        
        return states[currentIndex_].get();
    }

    int64_t getNextConnectionId(struct mptcp_sock* msk) override {
        auto conn = mptcp_rr_subflow_get_send(msk);
        if(conn == nullptr) return -1;
        return conn->getConnId();
    }
    
private:
    int64_t currentIndex_;

};

class RandomScheduler : public QuicScheduler {
public:
    RandomScheduler() {}

    void updateConnectionStatus(struct sock* sock, bool isIdle) override {
        // 更新连接状态，例如更新其活跃度等
        // 这里可以维护一个内部状态表
    }

    int64_t getNextConnectionId(struct mptcp_sock* mptcp_sock) override {
        auto connections = mptcp_sock->connManager;
        if (connections->empty()) return -1;
        auto allConnIds = connections->getAllConnectionIds();
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::mt19937 gen(seed);
        std::uniform_int_distribution<> dis(0, allConnIds.size() - 1);
        return allConnIds[dis(gen)];
    }
    
    int64_t getIdleConnectionId(struct mptcp_sock* mptcp_sock) override {
        return -1;
    }
};

} // namespace quic