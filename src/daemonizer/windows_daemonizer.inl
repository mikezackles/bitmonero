#pragma once

#include "common/util.h"
#include "daemonizer/windows_service.h"
#include "daemonizer/windows_service_runner.h"

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

namespace daemonizer
{
  namespace
  {
    const command_line::arg_descriptor<bool> arg_install_service = {
      "install-service"
    , "Install Windows service"
    };
    const command_line::arg_descriptor<bool> arg_uninstall_service = {
      "uninstall-service"
    , "Uninstall Windows service"
    };
    const command_line::arg_descriptor<bool> arg_start_service = {
      "start-service"
    , "Start Windows service"
    };
    const command_line::arg_descriptor<bool> arg_stop_service = {
      "stop-service"
    , "Stop Windows service"
    };
    const command_line::arg_descriptor<bool> arg_is_service = {
      "run-as-service"
    , "Hidden -- true if running as windows service"
    };

    std::string get_argument_string(int argc, char const * argv[])
    {
      std::string result = "";
      for (int i = 1; i < argc; ++i)
      {
        result += " " + std::string{argv[i]};
      }
      return result;
    }
  }

  inline void init_options(
      boost::program_options::options_description & hidden_options
    , boost::program_options::options_description & normal_options
    )
  {
    command_line::add_arg(normal_options, arg_install_service);
    command_line::add_arg(normal_options, arg_uninstall_service);
    command_line::add_arg(normal_options, arg_start_service);
    command_line::add_arg(normal_options, arg_stop_service);
    command_line::add_arg(hidden_options, arg_is_service);
  }

  inline boost::filesystem::path get_relative_path_base(
      boost::program_options::variables_map const & vm
    )
  {
    if (command_line::arg_present(vm, arg_is_service))
    {
      if (command_line::arg_present(vm, command_line::arg_data_dir))
      {
        return command_line::get_arg(vm, command_line::arg_data_dir);
      }
      else
      {
        return tools::get_default_data_dir();
      }
    }
    else
    {
      return boost::filesystem::current_path();
    }
  }

  template <typename T_executor>
  inline int daemonize(
      int argc, char const * argv[]
    , T_executor && executor // universal ref
    , boost::program_options::variables_map const & vm
    )
  {
    std::string arguments = get_argument_string(argc, argv);

    if (command_line::arg_present(vm, arg_is_service))
    {
      //LOG_PRINT_L0(CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG);
      auto maybe_daemon = executor.create_daemon(vm);
      // TODO!! - There is not yet a way to retrieve the return code when
      // running as a service.  It should probably be set here using
      // SetServiceStatus.
      if (maybe_daemon.which() == 0)
      {
        windows::t_service_runner<T_executor::t_daemon>::run(
          executor.name()
        , boost::get<typename T_executor::t_daemon>(maybe_daemon)
        );
        return 0;
      }
      else
      {
        return boost::get<int>(maybe_daemon);
      }
    }
    else if (command_line::arg_present(vm, arg_install_service))
    {
      if (windows::ensure_admin(arguments))
      {
        arguments += " --run-as-service";
        if (windows::install_service(executor.name(), arguments))
        {
          return 0;
        }
      }
    }
    else if (command_line::arg_present(vm, arg_uninstall_service))
    {
      if (windows::ensure_admin(arguments))
      {
        if (windows::uninstall_service(executor.name()))
        {
          return 0;
        }
      }
    }
    else if (command_line::arg_present(vm, arg_start_service))
    {
      if (windows::ensure_admin(arguments))
      {
        if (windows::start_service(executor.name()))
        {
          return 0;
        }
      }
    }
    else if (command_line::arg_present(vm, arg_stop_service))
    {
      if (windows::ensure_admin(arguments))
      {
        if (windows::stop_service(executor.name()))
        {
          return 0;
        }
      }
    }
    else // interactive
    {
      //LOG_PRINT_L0(CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG);
      return executor.run_interactive(vm);
    }

    return 1;
  }
}
