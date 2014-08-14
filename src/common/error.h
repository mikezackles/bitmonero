#pragma once

#include <string>

namespace tools
{

struct t_error
{
  std::string const file;
  uint32_t const line;
  std::string const * const message;

  std::string to_string()
  {
    return "[" + file + " : " + std::to_string(line) + "] " + *message;
  }
};

}
