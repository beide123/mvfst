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

    /*virtual struct sock *mptcp_subflow_tcp_sock(struct mptcp_subflow_context *subflow) = 0;

    virtual bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) = 0;

    virtual void trace_mptcp_subflow_get_send(struct mptcp_subflow_context *subflow) = 0;*/
};

struct rrsched_priv {
    unsigned char quota;
};

#define SSK_MODE_MAX 10

// Define the mptcp_for_each_subflow macro
#define mptcp_for_each_subflow(msk, subflow) \
    for (const auto& subflow_id : msk->connManager->getAllConnectionIds()) \
        for (auto subflow = msk->connStates[subflow_id].get(); subflow; subflow = nullptr)

class RoundRobinScheduler : public QuicScheduler {
public:
    RoundRobinScheduler() : num_segments(10) {}

    static struct rrsched_priv *rrsched_get_priv(struct mptcp_subflow_context *tp)
    {
        return (struct rrsched_priv *)&(tp->mptcp_sched[0]);
    }

    struct sock *
    mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
    {
        return subflow->ssk;
    }

    // Add a tracing function
    void trace_mptcp_subflow_get_send(struct mptcp_subflow_context *subflow) {
        if (!subflow || !subflow->ssk) return;
        
        // Get RTT (in microseconds)
        uint64_t rtt_us = subflow->ssk->getRtt(); 
        // Convert to milliseconds (optional, but easier to read)
        double rtt_ms = static_cast<double>(rtt_us) / 1000.0;

        VLOG(2) << "MPTCP: Selecting subflow " << subflow->subflow_id 
            << " for sending, RTT: " << rtt_ms // Using the converted millisecond value
            << "ms, CWND: " << subflow->ssk->getCwnd() 
            << ", idle: " << (subflow->ssk->isIdle() ? "yes" : "no");
    }

    bool mptcp_subflow_active(struct mptcp_subflow_context *subflow)
    {
        if (!subflow || !subflow->ssk) {
            LOG(ERROR) << "Subflow or ssk or transport is null";
            return false;
        }

        auto ssk = subflow->ssk;
        if (!ssk->isGood()) {
            return false;
        }
        
        if (!ssk->isPendingSend()) {
            return false;
        }

        if(!ssk->isLastUsedTime()) {
            return false;
        }   
        
        return true;
    }
    
    int64_t getIdleConnectionId(struct mptcp_sock* msk) override {
        // Find the first idle connection
        auto ids = msk->connManager->getAllConnectionIds();
        auto states = msk->connStates;

        if (ids.empty()) return -1;
        for (const auto& id : ids) {
            VLOG(2) << "RoundRobinScheduler get idle connection id: " << id
                    << " isIdle: " << states[id]->ssk->isIdle();
            if (states[id]->ssk->isIdle()) {
                VLOG(2) << "RoundRobinScheduler get idle connection id: " << id;
                return id;
            }
        }
        return -1;
    }

    void updateConnectionStatus(struct sock* sock, bool isIdle) override {
        // Update connection status, such as updating its activity level
        // This can maintain an internal state table
        if(sock == nullptr) return;
        if(sock->isIdle()) {
            sock->setIdle(isIdle);
        }
        uint64_t lastUsedTime = std::chrono::system_clock::now().time_since_epoch().count();
        sock->setLastUsedTime(lastUsedTime);
    }

    // Custom implementation to check if the send queue is empty
    bool tcp_rtx_and_write_queues_empty(struct sock *ssk)
    {
        // In QUIC, we can check if there are any unacknowledged bytes
        // If unacked > 0, consider the queue not empty
        return ssk->getUnacked() == 0; // Using the getUnacked() method
    }

    // Custom implementation to check if the subflow is stale
    void mptcp_pm_subflow_chk_stale(struct mptcp_sock *msk, struct mptcp_subflow_context *subflow)
    {
        // If the queue is not empty (there is unacknowledged data), increment stale_count
        // Otherwise, reset stale_count
        if (!tcp_rtx_and_write_queues_empty(subflow->ssk)) {
            subflow->stale_count++;
        } else {
            subflow->stale_count = 0;
        }
        // Here, more complex logic can be added as needed, such as checking idle time
    }

    struct sock *mptcp_rr_subflow_get_retrans(struct mptcp_sock *msk)
    {
        struct sock *backup = NULL, *pick = NULL;
        struct mptcp_subflow_context *subflow;
        int min_stale_count = INT_MAX; // Using INT_MAX instead of the previous implementation

        mptcp_for_each_subflow(msk, subflow) {
            struct sock *ssk = mptcp_subflow_tcp_sock(subflow);

            if (!mptcp_subflow_active(subflow))
                continue;

            /* still data outstanding at TCP level? skip this */
            if (!tcp_rtx_and_write_queues_empty(ssk)) {
                mptcp_pm_subflow_chk_stale(msk, subflow);
                min_stale_count = std::min(min_stale_count, subflow->stale_count);
                continue;
            }

            if (subflow->backup || subflow->request_bkup) {
                if (!backup)
                    backup = ssk;
                continue;
            }

            if (!pick)
                pick = ssk;
        }

        if (pick)
            return pick;

        /* use backup only if there are no progresses anywhere */
        return min_stale_count > 1 ? backup : NULL;
    }

    struct sock *mptcp_rr_subflow_get_send(struct mptcp_sock *msk) {
        struct subflow_send_info send_info[SSK_MODE_MAX];
        struct mptcp_subflow_context *subflow;
        struct sock *ssk;
        int i;
        struct sock *choose_sk = NULL;
        int16_t num_subs = 0, full_subs = 0, choose_sk_id = -1;

restart:
        num_subs = 0;
        full_subs = 0;
        choose_sk = NULL;
        choose_sk_id = -1;
        /* pick the subflow with the lower wmem/wspace ratio */
        for (i = 0; i < SSK_MODE_MAX; ++i) {
            send_info[i].ssk = NULL;
            send_info[i].linger_time = -1;
        }

        mptcp_for_each_subflow(msk, subflow) {
            struct rrsched_priv *rr_p = rrsched_get_priv(subflow);

            trace_mptcp_subflow_get_send(subflow);

            ssk = mptcp_subflow_tcp_sock(subflow);

            if (!mptcp_subflow_active(subflow)){
                LOG(ERROR) << "RoundRobinScheduler subflow " << subflow->subflow_id << " is not active";
                continue;
            }

            num_subs += 1;

            if (rr_p->quota >= 0 && rr_p->quota < num_segments) {
                rr_p->quota += 1;
                choose_sk = ssk;
                choose_sk_id = subflow->subflow_id;
                goto found;
		    }

            if (rr_p->quota >= num_segments)
                full_subs++;

            choose_sk = ssk;
            choose_sk_id = subflow->subflow_id;
        }

        // zero all quota and spread again...
        if (full_subs == num_subs) {
            mptcp_for_each_subflow(msk, subflow) {
                struct rrsched_priv *rr_p = rrsched_get_priv(subflow);
			    rr_p->quota = 0;
            }
            goto restart;
        }

found:
        VLOG(2) << "RoundRobinScheduler choose subflow " << choose_sk_id;
        return choose_sk;
    }

    int64_t getNextConnectionId(struct mptcp_sock* msk) override {
        auto conn = mptcp_rr_subflow_get_send(msk);
        if(conn == nullptr) return -1;
        return conn->getConnId();
    }
    
private:
    int num_segments; // Maximum quota for each connection
};

class RandomScheduler : public QuicScheduler {
public:
    RandomScheduler() {}

    void updateConnectionStatus(struct sock* sock, bool isIdle) override {
        // Update connection status, such as updating its activity level
        // This can maintain an internal state table
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