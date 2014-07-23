#pragma once

#include "daemon/daemon.h"
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/variant/variant.hpp>
#include <string>
#include <vector>

namespace daemonize
{
  class t_executor final
  {
  public:
    typedef ::daemonize::t_daemon t_daemon;

    static std::string const NAME;

    static void init_options(
        boost::program_options::options_description & configurable_options
      );

    std::string const & name();

    boost::variant<t_daemon, int> create_daemon(
        boost::program_options::variables_map const & vm
      );

    int run_interactive(
        boost::program_options::variables_map const & vm
      );
  };
}
