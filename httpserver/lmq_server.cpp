#include "lmq_server.h"

#include "worktips_common.h"
#include "worktips_logger.h"
#include "worktipsd_key.h"
#include "service_node.h"
#include "request_handler.h"
#include "utils.hpp"

#include <worktipsmq/worktipsmq.h>

namespace worktips {

std::string WorktipsmqServer::peer_lookup(worktipsmq::string_view pubkey_bin) const {

    WORKTIPS_LOG(trace, "[LMQ] Peer Lookup");

    // TODO: don't create a new string here
    boost::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey_bin));

    if (sn) {
        return fmt::format("tcp://{}:{}", sn->ip(), sn->lmq_port());
    } else {
        WORKTIPS_LOG(debug, "[LMQ] peer node not found {}!", pubkey_bin);
        return "";
    }
}

void WorktipsmqServer::handle_sn_data(worktipsmq::Message& message) {

    WORKTIPS_LOG(debug, "[LMQ] handle_sn_data");
    WORKTIPS_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    WORKTIPS_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    std::stringstream ss;

    // We are only expecting a single part message, so consider removing this
    for (auto& part : message.data) {
        ss << part;
    }

    // TODO: proces push batch should move to "Request handler"
    service_node_->process_push_batch(ss.str());

    WORKTIPS_LOG(debug, "[LMQ] send reply");

    // TODO: Investigate if the above could fail and whether we should report
    // that to the sending SN
    message.send_reply();
};

void WorktipsmqServer::handle_sn_proxy_exit(worktipsmq::Message& message) {

    WORKTIPS_LOG(debug, "[LMQ] handle_sn_proxy_exit");
    WORKTIPS_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    WORKTIPS_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    if (message.data.size() != 2) {
        WORKTIPS_LOG(debug, "Expected 2 message parts, got {}",
                 message.data.size());
        return;
    }

    const auto& client_key = message.data[0];
    const auto& payload = message.data[1];

    auto &reply_tag = message.reply_tag;
    auto &origin_pk = message.conn.pubkey();

    // TODO: accept string_view?
    request_handler_->process_proxy_exit(
        std::string(client_key), std::string(payload),
        [this, origin_pk, reply_tag](worktips::Response res) {
            WORKTIPS_LOG(debug, "    Proxy exit status: {}", res.status());

            if (res.status() == Status::OK) {
                this->worktipsmq_->send(origin_pk, "REPLY", reply_tag,
                                    res.message());

            } else {
                // We reply with 2 messages which will be treated as
                // an error (rather than timeout)
                this->worktipsmq_->send(origin_pk, "REPLY", reply_tag,
                                    fmt::format("{}", res.status()),
                                    res.message());
                WORKTIPS_LOG(debug, "Error: status is not OK for proxy_exit: {}", res.status());
            }
        });
}

void WorktipsmqServer::handle_onion_request(worktipsmq::Message& message) {

    WORKTIPS_LOG(debug, "Got an onion request over WORKTIPSMQ");

    auto &reply_tag = message.reply_tag;
    auto &origin_pk = message.conn.pubkey();

    auto on_response = [this, origin_pk, reply_tag](worktips::Response res) mutable {
        WORKTIPS_LOG(trace, "on response: {}", to_string(res));

        std::string status = std::to_string(static_cast<int>(res.status()));

        worktipsmq_->send(origin_pk, "REPLY", reply_tag, std::move(status), res.message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping") {
        // Before 2.0.3 we reply with a bad request, below, but reply here to avoid putting the
        // error message in the log on 2.0.3+ nodes. (the reply code here doesn't actually matter;
        // the ping test only requires that we provide *some* response).
        WORKTIPS_LOG(debug, "Remote pinged me");
        service_node_->update_last_ping(ReachType::ZMQ);
        on_response(worktips::Response{Status::OK, "pong"});
        return;
    }

    if (message.data.size() != 2) {
        WORKTIPS_LOG(error, "Expected 2 message parts, got {}", message.data.size());
        on_response(worktips::Response{Status::BAD_REQUEST, "Incorrect number of messages"});
        return;
    }

    const auto& eph_key = message.data[0];
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext), std::string(eph_key), on_response);
}

void WorktipsmqServer::init(ServiceNode* sn, RequestHandler* rh,
                        const worktipsd_key_pair_t& keypair) {

    using worktipsmq::Allow;
    using worktipsmq::string_view;

    service_node_ = sn;
    request_handler_ = rh;

    auto pubkey = key_to_string(keypair.public_key);
    auto seckey = key_to_string(keypair.private_key);

    auto logger = [](worktipsmq::LogLevel level, const char* file, int line,
                     std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL) \
        case worktipsmq::LogLevel::LMQ_LVL: \
            WORKTIPS_LOG(SS_LVL, "[{}:{}]: {}", file, line, message); \
            break;

        switch(level) {
            LMQ_LOG_MAP(fatal, critical);
            LMQ_LOG_MAP(error, error);
            LMQ_LOG_MAP(warn, warn);
            LMQ_LOG_MAP(info, info);
            LMQ_LOG_MAP(trace, trace);
            default:
                WORKTIPS_LOG(debug, "[{}:{}]: {}", file, line, message);
        };
#undef LMQ_LOG_MAP
    };

    auto lookup_fn = [this](auto pk) { return this->peer_lookup(pk); };

    worktipsmq_.reset(new WorktipsMQ{pubkey,
                             seckey,
                             true /* is service node */,
                             lookup_fn,
                             logger});

    WORKTIPS_LOG(info, "WorktipsMQ is listenting on port {}", port_);

    worktipsmq_->log_level(worktipsmq::LogLevel::info);

    // ============= COMMANDS - BEGIN =============
    //
    worktipsmq_->add_category("sn", worktipsmq::Access{worktipsmq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m); })
        ;

    // +============= COMMANDS - END ==============

    worktipsmq_->set_general_threads(1);

    worktipsmq_->listen_curve(fmt::format("tcp://0.0.0.0:{}", port_));

    worktipsmq_->MAX_MSG_SIZE = 10 * 1024 * 1024; // 10 MB (needed by the fileserver)

    worktipsmq_->start();
}

WorktipsmqServer::WorktipsmqServer(uint16_t port) : port_(port){};
WorktipsmqServer::~WorktipsmqServer() = default;

} // namespace worktips
