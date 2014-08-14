#include "wallet/keys_serialization.h"

#include "crypto/chacha8.h"
#include "serialization/binary_utils.h"
#include "file_io_utils.h"

// epee
#include "storages/portable_storage_template_helper.h"

namespace tools
{

namespace
{
  struct keys_file_data
  {
    crypto::chacha8_iv iv;
    std::string account_data;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(iv)
      FIELD(account_data)
    END_SERIALIZE()
  };

  bool verify_keys(
      crypto::secret_key const & sec
    , crypto::public_key const & expected_pub
    )
  {
    crypto::public_key pub;
    bool r = crypto::secret_key_to_public_key(sec, pub);
    return r && expected_pub == pub;
  }
}


boost::optional<tools::t_error> store_keys_to_file(
    std::string const & keys_file_name
  , std::string const & password
  , cryptonote::core_account_data const & core_data
  )
{
  std::string account_data;
  if (!epee::serialization::store_t_to_binary(core_data, account_data))
  {
    return t_error { __FILE__, __LINE__, &KEYS_SERIALIZE_ERROR };
  }

  crypto::chacha8_key key;
  crypto::generate_chacha8_key(password, key);
  std::string cipher;
  cipher.resize(account_data.size());

  keys_file_data file_data {};
  file_data.iv = crypto::rand<crypto::chacha8_iv>();
  crypto::chacha8(account_data.data(), account_data.size(), key, file_data.iv, &cipher[0]);
  file_data.account_data = cipher;

  std::string buf;
  if (!::serialization::dump_binary(file_data, buf))
  {
    return t_error { __FILE__, __LINE__, &KEYS_DUMP_BINARY_ERROR };
  }
  if (!epee::file_io_utils::save_string_to_file(keys_file_name, buf))
  {
    return t_error { __FILE__, __LINE__, &KEYS_FILE_SAVE_ERROR };
  }

  return boost::none;
}

boost::variant<cryptonote::core_account_data, tools::t_error> load_keys_from_file(
    std::string const & keys_file_name
  , std::string const & password
  )
{
  keys_file_data file_data;
  std::string buf;
  if (!epee::file_io_utils::load_file_to_string(keys_file_name, buf))
  {
    return t_error { __FILE__, __LINE__, &KEYS_FILE_LOAD_ERROR };
  }
  else if (!::serialization::parse_binary(buf, file_data))
  {
    return t_error { __FILE__, __LINE__, &KEYS_DESERIALIZE_ERROR };
  }

  crypto::chacha8_key key;
  crypto::generate_chacha8_key(password, key);
  std::string account_data;
  account_data.resize(file_data.account_data.size());
  crypto::chacha8(file_data.account_data.data(), file_data.account_data.size(), key, file_data.iv, &account_data[0]);

  cryptonote::core_account_data core_data;
  if (!epee::serialization::load_t_from_binary(core_data, account_data))
  {
    return t_error { __FILE__, __LINE__, &KEYS_DESERIALIZE_ERROR };
  }
  if (!verify_keys(core_data.m_keys.m_view_secret_key,  core_data.m_keys.m_account_address.m_view_public_key))
  {
    return t_error { __FILE__, __LINE__, &KEYS_INVALID_PASSWORD_ERROR };
  }
  if (!verify_keys(core_data.m_keys.m_spend_secret_key, core_data.m_keys.m_account_address.m_spend_public_key))
  {
    return t_error { __FILE__, __LINE__, &KEYS_INVALID_PASSWORD_ERROR };
  }

  return core_data;
}

}
