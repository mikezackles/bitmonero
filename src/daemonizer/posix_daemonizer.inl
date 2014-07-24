#pragma once

#include "common/scoped_message_writer.h"
#include "daemonizer/posix_fork.h"

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

namespace daemonizer
{
  namespace
  {
    const command_line::arg_descriptor<bool> arg_detach = {
      "detach"
    , "Run as daemon"
    };
  }

  inline void init_options(
      boost::program_options::options_description & hidden_options
    , boost::program_options::options_description & normal_options
    )
  {
    command_line::add_arg(normal_options, arg_detach);
  }

  inline boost::filesystem::path get_relative_path_base(
      boost::program_options::variables_map const & vm
    )
  {
    return boost::filesystem::current_path();
  }

  template <typename T_executor>
  inline int daemonize(
      int argc, char const * argv[]
    , T_executor && executor // universal ref
    , boost::program_options::variables_map const & vm
    )
  {
    if (command_line::arg_present(vm, arg_detach))
    {
      tools::success_msg_writer() << "Forking to background...";
      posix::fork();
      auto maybe_daemon = executor.create_daemon(vm);
      if (maybe_daemon.which() == 1)
      {
        return boost::get<int>(maybe_daemon);
      }
      return boost::get<typename T_executor::t_daemon>(maybe_daemon).run();
    }
    else
    {
      //LOG_PRINT_L0(CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG);
      return executor.run_interactive(vm);
    }
  }
}
