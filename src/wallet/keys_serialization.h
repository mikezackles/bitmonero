#pragma once

#include "common/error.h"
#include "cryptonote_core/account.h"

#include <boost/optional/optional.hpp>
#include <boost/variant/variant.hpp>
#include <string>

namespace tools {

std::string const KEYS_SERIALIZE_ERROR = "failed to serialize wallet keys";
std::string const KEYS_DUMP_BINARY_ERROR = "failed to dump wallet keys to binary";
std::string const KEYS_FILE_SAVE_ERROR = "failed to write wallet keys file";
std::string const KEYS_FILE_LOAD_ERROR = "failed to load wallet keys file";
std::string const KEYS_DESERIALIZE_ERROR = "failed to deserialize wallet keys";
std::string const KEYS_INVALID_PASSWORD_ERROR = "failed to deserialize wallet keys";

boost::optional<tools::t_error> store_keys_to_file(
    std::string const & keys_file_name
  , std::string const & password
  , cryptonote::core_account_data const & core_data
  );

boost::variant<cryptonote::core_account_data, tools::t_error> load_keys_from_file(
    std::string const & keys_file_name
  , std::string const & password
  );

} // namespace keys_serialization
