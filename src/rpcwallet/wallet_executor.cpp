#include "rpcwallet/wallet_executor.h"

#include "common/command_line.h"
#include "cryptonote_config.h"
#include "daemonizer/daemonizer.h"
#include "misc_log_ex.h"
#include "version.h"

#include <string>

namespace tools
{
  namespace
  {
    const command_line::arg_descriptor<std::string>   arg_wallet_file      = {"wallet-file", "Use wallet <arg>", ""};
    const command_line::arg_descriptor<std::string>   arg_daemon_address   = {"daemon-address", "Use daemon instance at <host>:<port>", ""};
    const command_line::arg_descriptor<std::string>   arg_daemon_host      = {"daemon-host", "Use daemon instance at host <arg> instead of localhost", ""};
    const command_line::arg_descriptor<uint16_t>      arg_daemon_port      = {"daemon-port", "Use daemon instance at port <arg> instead of 8081", 0};
    const command_line::arg_descriptor<std::string>   arg_password         = {"password", "Wallet password", "", true};
    const command_line::arg_descriptor<std::string>   arg_rpc_bind_port    = {"rpc-bind-port", "Starts wallet as rpc server for wallet operations, sets bind port for server", "", true};
    const command_line::arg_descriptor<std::string>   arg_rpc_bind_ip      = {"rpc-bind-ip", "Specify ip to bind rpc server", "127.0.0.1"};

    t_failable<t_wallet_daemon> create_daemon(
        boost::program_options::variables_map const & vm
      )
    {
      if(!command_line::has_arg(vm, arg_wallet_file) )
      {
        LOG_PRINT_L0("Wallet file not set");
        return 1;
      }
      if(!command_line::has_arg(vm, arg_daemon_address) )
      {
        LOG_PRINT_L0("Daemon address not set");
        return 1;
      }
      if(!command_line::has_arg(vm, arg_password) )
      {
        LOG_PRINT_L0("Wallet password not set.");
        return 1;
      }

      boost::filesystem::path relative_path_base = daemonizer::get_relative_path_base(vm);

      std::string wallet_file     = boost::filesystem::absolute(command_line::get_arg(vm, arg_wallet_file), relative_path_base).string();
      std::string wallet_password = command_line::get_arg(vm, arg_password);
      std::string daemon_address  = command_line::get_arg(vm, arg_daemon_address);
      std::string daemon_host = command_line::get_arg(vm, arg_daemon_host);
      uint16_t daemon_port = command_line::get_arg(vm, arg_daemon_port);
      std::string bind_ip = command_line::get_arg(vm, arg_rpc_bind_ip);
      std::string bind_port = command_line::get_arg(vm, arg_rpc_bind_port);
      if (daemon_host.empty())
        daemon_host = "localhost";
      if (!daemon_port)
        daemon_port = RPC_DEFAULT_PORT;
      if (daemon_address.empty())
        daemon_address = std::string("http://") + daemon_host + ":" + std::to_string(daemon_port);

      LOG_PRINT_L0(CRYPTONOTE_NAME << " wallet v" << PROJECT_VERSION_LONG);
      return t_wallet_daemon::create(
        wallet_file
      , wallet_password
      , daemon_address
      , bind_ip
      , bind_port
      );
    }

    std::string const BASE_NAME = "BitMonero Wallet Daemon";

    std::string daemon_name(
        boost::program_options::variables_map const & vm
      )
    {
      return BASE_NAME + " - " + command_line::get_arg(vm, arg_rpc_bind_ip) + ":" + command_line::get_arg(vm, arg_rpc_bind_port);
    }
  }

  void t_wallet_executor::init_options(
      boost::program_options::options_description & hidden_options
    , boost::program_options::options_description & normal_options
    , boost::program_options::options_description & configurable_options
    )
  {
    command_line::add_arg(configurable_options, arg_wallet_file);
    command_line::add_arg(configurable_options, arg_password);
    command_line::add_arg(configurable_options, arg_daemon_address);
    command_line::add_arg(configurable_options, arg_daemon_host);
    command_line::add_arg(configurable_options, arg_daemon_port);
    command_line::add_arg(configurable_options, arg_rpc_bind_ip);
    command_line::add_arg(configurable_options, arg_rpc_bind_port);
  }

  t_wallet_executor::t_wallet_executor(
      boost::program_options::variables_map const & vm
    )
    : m_name{daemon_name(vm)}
  {}

  std::string const & t_wallet_executor::name()
  {
    return m_name;
  }

  t_failable<t_wallet_daemon> t_wallet_executor::create_daemon(
      boost::program_options::variables_map const & vm
    )
  {
    return tools::create_daemon(vm);
  }

  int t_wallet_executor::run_interactive(
      boost::program_options::variables_map const & vm
    )
  {
    epee::log_space::log_singletone::add_logger(LOGGER_CONSOLE, nullptr, nullptr, LOG_LEVEL_2);
    auto maybe_daemon = tools::create_daemon(vm);
    if (maybe_daemon.success())
    {
      return maybe_daemon.result().run();
    }
    else
    {
      return maybe_daemon.error_code();
    }
  }
}
