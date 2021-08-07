#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <worktipsmq/string_view.h>

namespace worktipsmq {
class WorktipsMQ;
struct Allow;
class Message;
} // namespace worktipsmq

using worktipsmq::WorktipsMQ;

namespace worktips {

struct worktipsd_key_pair_t;
class ServiceNode;
class RequestHandler;

class WorktipsmqServer {

    std::unique_ptr<WorktipsMQ> worktipsmq_;

    // Has information about current SNs
    ServiceNode* service_node_;

    RequestHandler* request_handler_;

    // Get nodes' address
    std::string peer_lookup(worktipsmq::string_view pubkey_bin) const;

    // Handle Session data coming from peer SN
    void handle_sn_data(worktipsmq::Message& message);

    // Handle Session client requests arrived via proxy
    void handle_sn_proxy_exit(worktipsmq::Message& message);

    void handle_onion_request(worktipsmq::Message& message);

    uint16_t port_ = 0;

  public:
    WorktipsmqServer(uint16_t port);
    ~WorktipsmqServer();

    // Initialize worktipsmq
    void init(ServiceNode* sn, RequestHandler* rh,
              const worktipsd_key_pair_t& keypair);

    uint16_t port() { return port_; }

    /// True if WorktipsMQ instance has been set
    explicit operator bool() const { return (bool) worktipsmq_; }
    /// Dereferencing via * or -> accesses the contained WorktipsMQ instance.
    WorktipsMQ& operator*() const { return *worktipsmq_; }
    WorktipsMQ* operator->() const { return worktipsmq_.get(); }
};

} // namespace worktips
