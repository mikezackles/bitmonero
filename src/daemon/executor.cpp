#include "daemon/executor.h"

#include "misc_log_ex.h"

#include "common/command_line.h"
#include "cryptonote_config.h"
#include "version.h"

#include <string>

namespace daemonize
{
  std::string const t_executor::NAME = "BitMonero Daemon";

  void t_executor::init_options(
      boost::program_options::options_description & configurable_options
    )
  {
    t_daemon::init_options(configurable_options);
  }

  std::string const & t_executor::name()
  {
    return NAME;
  }

  boost::variant<t_daemon, int> t_executor::create_daemon(
      boost::program_options::variables_map const & vm
    )
  {
    LOG_PRINT_L0(CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG);
    try
    {
      return t_daemon{vm};
    }
    catch (...)
    {
      return 1;
    }
  }

  int t_executor::run_interactive(
      boost::program_options::variables_map const & vm
    )
  {
    epee::log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL);
    try
    {
      return t_daemon{vm}.run();
    }
    catch (...)
    {
      return 1;
    }
  }
}

