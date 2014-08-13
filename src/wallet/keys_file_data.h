#pragma once

namespace tools {

struct keys_file_data
{
  crypto::chacha8_iv iv;
  std::string account_data;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(iv)
    FIELD(account_data)
  END_SERIALIZE()
};

} // namespace tools
