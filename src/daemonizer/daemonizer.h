#pragma once

#include <boost/filesystem/path.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

namespace daemonizer
{
  void init_options(
      boost::program_options::options_description & hidden_options
    , boost::program_options::options_description & normal_options
    );

  boost::filesystem::path get_relative_path_base(
      boost::program_options::variables_map const & vm
    );

  template <typename T_executor>
  int daemonize(
      int argc, char const * argv[]
    , T_executor && executor // universal ref
    , boost::program_options::variables_map const & vm
    );
}

#ifdef WIN32
#  include "daemonizer/windows_daemonizer.inl"
#else
#  include "daemonizer/posix_daemonizer.inl"
#endif
