#pragma once

#include <boost/variant/variant.hpp>
#include <memory>
#include <string>

namespace tools {

class wallet_rpc_server;

class t_wallet_daemon final {
private:
  std::unique_ptr<wallet_rpc_server> mp_server;
  t_wallet_daemon(
      wallet_rpc_server * p_server
    );
public:
  static boost::variant<t_wallet_daemon, int> create(
      std::string wallet_file
    , std::string wallet_password
    , std::string daemon_address
    , std::string bind_ip
    , std::string port
    );
  t_wallet_daemon(t_wallet_daemon const & other) = delete;
  t_wallet_daemon & operator=(t_wallet_daemon const & other) = delete;
  t_wallet_daemon(t_wallet_daemon && other);
  t_wallet_daemon & operator=(t_wallet_daemon && other);
  ~t_wallet_daemon();

  int run();
  void stop();
};

}
