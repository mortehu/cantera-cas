#ifndef CANTERA_RPC_H_
#define CANTERA_RPC_H_

#include <capnp/capability.h>
#include <capnp/rpc-twoparty.capnp.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/rpc.capnp.h>
#include <kj/async-io.h>
#include <kj/debug.h>
#include <kj/io.h>
#include <kj/memory.h>

namespace cantera {
namespace cas_internal {

template <typename Capability>
class RPCServer {
 public:
  typedef decltype(capnp::makeRpcServer(
      std::declval<capnp::TwoPartyVatNetwork&>(),
      std::declval<typename Capability::Client>())) RpcServerType;

  template <typename... Args>
  RPCServer(kj::Own<typename Capability::Server> server,
            kj::Own<kj::AsyncIoStream>&& async_io_stream)
      : async_io_stream_(std::move(async_io_stream)),
        vat_network_(*async_io_stream_, capnp::rpc::twoparty::Side::SERVER),
        rpc_server_(capnp::makeRpcServer(vat_network_, std::move(server))) {}

  KJ_DISALLOW_COPY(RPCServer);
  RPCServer(RPCServer&& rhs) = delete;
  RPCServer& operator=(RPCServer&& rhs) = delete;

 private:
  kj::Own<kj::AsyncIoStream> async_io_stream_;
  capnp::TwoPartyVatNetwork vat_network_;
  RpcServerType rpc_server_;
};

class RPCClient {
 public:
  typedef decltype(capnp::makeRpcClient(
      std::declval<capnp::TwoPartyVatNetwork&>())) ClientType;

  // Constructs an RPC client from an established connection represented by a
  // kj::AsyncIoStream.
  RPCClient(kj::Own<kj::AsyncIoStream>&& async_io_stream)
      : async_io_stream_(std::move(async_io_stream)),
        vat_network_(*async_io_stream_, capnp::rpc::twoparty::Side::CLIENT),
        client_(capnp::makeRpcClient(vat_network_)) {}

  KJ_DISALLOW_COPY(RPCClient);
  RPCClient(RPCClient&& rhs) = delete;
  RPCClient& operator=(RPCClient&& rhs) = delete;

  // Returns a promise that resolves when the connection is lost.
  kj::Promise<void> OnDisconnect() { return vat_network_.onDisconnect(); }

  template <typename Capability>
  typename Capability::Client GetMain() {
    capnp::word scratch[64];
    memset(scratch, 0, sizeof(scratch));
    capnp::MallocMessageBuilder message(scratch);

    auto hostIdOrphan =
        message.getOrphanage().newOrphan<capnp::rpc::twoparty::VatId>();
    auto vatId = hostIdOrphan.get();
    vatId.setSide(capnp::rpc::twoparty::Side::SERVER);
    return client_.bootstrap(vatId).castAs<Capability>();
  }

 private:
  kj::Own<kj::AsyncIoStream> async_io_stream_;
  capnp::TwoPartyVatNetwork vat_network_;
  ClientType client_;
};

template <typename Capability>
class RPCListeningServer {
 public:
  typedef decltype(capnp::makeRpcServer(
      std::declval<capnp::TwoPartyVatNetwork&>(),
      std::declval<typename Capability::Client>())) RpcServerType;

  template <typename... Args>
  RPCListeningServer(kj::AsyncIoContext& async_io,
                     kj::Own<typename Capability::Server> server,
                     kj::Own<kj::ConnectionReceiver> listener)
      : listener_{std::move(listener)}, bootstrap_{std::move(server)} {}

  kj::Promise<void> AcceptLoop() {
    return listener_->accept().then([this](auto&& async_io_stream) {
      auto connection =
          kj::heap<ConnectionState>(std::move(async_io_stream), bootstrap_);
      auto connection_promise = connection->OnDisconnect()
                                    .attach(std::move(connection))
                                    .eagerlyEvaluate(nullptr);
      return this->AcceptLoop().attach(std::move(connection_promise));
    });
  }

 private:
  class ConnectionState {
   public:
    ConnectionState(kj::Own<kj::AsyncIoStream>&& async_io_stream,
                    typename Capability::Client bootstrap)
        : async_io_stream_(std::move(async_io_stream)),
          network_(*async_io_stream_, capnp::rpc::twoparty::Side::SERVER),
          server_(capnp::makeRpcServer(network_, bootstrap)) {}

    kj::Promise<void> OnDisconnect() { return network_.onDisconnect(); }

   private:
    ConnectionState(const ConnectionState&) = delete;
    ConnectionState(ConnectionState&&) = delete;
    ConnectionState& operator=(const ConnectionState&) = delete;
    ConnectionState& operator=(ConnectionState&) = delete;

    kj::Own<kj::AsyncIoStream> async_io_stream_;
    capnp::TwoPartyVatNetwork network_;
    RpcServerType server_;
  };

  kj::Own<kj::ConnectionReceiver> listener_;
  typename Capability::Client bootstrap_;
};

}  // namespace cas_internal
}  // namespace cantera

#endif  // !CANTERA_RPC_H_
