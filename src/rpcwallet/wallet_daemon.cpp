#include "rpcwallet/wallet_daemon.h"

#include "common/util.h"
#include "rpcwallet/wallet_return_codes.h"
#include "rpcwallet/wallet_rpc_server.h"

namespace tools {

t_failable<t_wallet_daemon> t_wallet_daemon::create(
    std::string wallet_file
  , std::string wallet_password
  , std::string daemon_address
  , std::string bind_ip
  , std::string port
  )
{
  try
  {
    return t_wallet_daemon{new wallet_rpc_server{
        wallet_file
      , wallet_password
      , daemon_address
      , std::move(bind_ip)
      , std::move(port)
      }};
  }
  catch (error::file_not_found const & e)
  {
    LOG_ERROR("Wallet initialize failed: " << e.what());
    return WALLET_RETURN_MISSING_KEYS_FILE;
  }
  catch (error::invalid_password const & e)
  {
    LOG_ERROR("Wallet initialize failed: " << e.what());
    return WALLET_RETURN_INVALID_PASSPHRASE;
  }
  catch (std::exception const & e)
  {
    LOG_ERROR("Wallet initialize failed: " << e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Wallet initialize failed");
    return 1;
  }
}

t_wallet_daemon::t_wallet_daemon(
    wallet_rpc_server * p_server
  )
  : mp_server{p_server}
{}

t_wallet_daemon::~t_wallet_daemon() = default;

// MSVC is brain-dead and can't default this...
t_wallet_daemon::t_wallet_daemon(t_wallet_daemon && other)
{
  if (this != &other)
  {
    mp_server = std::move(other.mp_server);
    other.mp_server.reset(nullptr);
  }
}

// or this
t_wallet_daemon & t_wallet_daemon::operator=(t_wallet_daemon && other)
{
  if (this != &other)
  {
    mp_server = std::move(other.mp_server);
    other.mp_server.reset(nullptr);
  }
  return *this;
}

int t_wallet_daemon::run()
{
  if (nullptr == mp_server)
  {
    throw std::runtime_error{"Can't run stopped wallet daemon"};
  }

  tools::signal_handler::install(std::bind(&tools::t_wallet_daemon::stop, this));

  try
  {
    mp_server->run();
    return 0;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Wallet daemon exception: " << ex.what());
    return 1;
  }
  catch (...)
  {
    LOG_ERROR("Unknown wallet daemon exception");
    return 1;
  }
}

void t_wallet_daemon::stop()
{
  if (nullptr == mp_server)
  {
    throw std::runtime_error{"Can't stop stopped wallet daemon"};
  }
  mp_server->stop();
  mp_server.reset(nullptr); // Ensure resources are cleaned up before we return
}

} // namespace daemonize
