// Copyright (c) 2014, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include <boost/utility/value_init.hpp>
#include "include_base_utils.h"

#include "wallet2.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "common/boost_serialization_helper.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "crypto/electrum-words.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace cryptonote;
using namespace epee;

namespace
{

  void do_prepare_file_names(
      const std::string& file_path
    , std::string& keys_file
    , std::string& wallet_file
    )
  {
    keys_file = file_path;
    wallet_file = file_path;
    boost::system::error_code e;
    if(string_tools::get_extension(keys_file) == "keys")
    {//provided keys file name
      wallet_file = string_tools::cut_off_extension(wallet_file);
    }else
    {//provided wallet file name
      keys_file += ".keys";
    }
  }

} //namespace

namespace tools
{

// for now, limit to 30 attempts.  TODO: discuss a good number to limit to.
const size_t MAX_SPLIT_ATTEMPTS = 30;

void wallet2::init(
    const std::string& daemon_address
  , uint64_t upper_transaction_size_limit
  )
{
  m_upper_transaction_size_limit = upper_transaction_size_limit;
  m_daemon_address = daemon_address;
}

bool wallet2::get_seed(
    std::string& electrum_words
  )
{
  crypto::ElectrumWords::bytes_to_words(
      m_core_data.m_keys.m_spend_secret_key
    , electrum_words
    );

  crypto::secret_key second;
  keccak(
      (uint8_t *)&m_core_data.m_keys.m_spend_secret_key
    , sizeof(crypto::secret_key)
    , (uint8_t *)&second
    , sizeof(crypto::secret_key)
    );

  sc_reduce32((uint8_t *)&second);

  return memcmp(
      second.data
    , m_core_data.m_keys.m_view_secret_key.data
    , sizeof(crypto::secret_key)
    ) == 0;
}

void wallet2::process_new_transaction(
    const cryptonote::transaction& tx
  , uint64_t height
  )
{
  process_unconfirmed(tx);
  std::vector<size_t> outs;
  uint64_t tx_money_got_in_outs = 0;

  std::vector<tx_extra_field> tx_extra_fields;
  if(!parse_tx_extra(tx.extra, tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
    LOG_PRINT_L0("Transaction extra has unsupported format: " << get_transaction_hash(tx));
  }

  tx_extra_pub_key pub_key_field;
  if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
  {
    LOG_PRINT_L0("Public key wasn't found in the transaction extra. Skipping transaction " << get_transaction_hash(tx));
    if(0 != m_callback)
    {
      m_callback->on_skip_transaction(height, tx);
    }
    return;
  }

  crypto::public_key tx_pub_key = pub_key_field.pub_key;
  lookup_acc_outs(m_core_data.m_keys, tx, tx_pub_key, outs, tx_money_got_in_outs);

  if(!outs.empty() && tx_money_got_in_outs)
  {
    //good news - got money! take care about it
    //usually we have only one transfer for user in transaction
    cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request req = AUTO_VAL_INIT(req);
    cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response res = AUTO_VAL_INIT(res);
    req.txid = get_transaction_hash(tx);
    if (!net_utils::invoke_http_bin_remote_command2(
          m_daemon_address + "/get_o_indexes.bin"
        , req
        , res
        , m_http_client
        , WALLET_RCP_CONNECTION_TIMEOUT
        )
      )
    {
      throw error::no_connection_to_daemon { LOCATION_TAG, "get_o_indexes.bin" };
    }
    else if (res.status == CORE_RPC_STATUS_BUSY)
    {
      throw error::daemon_busy { LOCATION_TAG, "get_o_indexes.bin" };
    }
    else if (res.status != CORE_RPC_STATUS_OK)
    {
      throw error::daemon_error { LOCATION_TAG, res.status };
    }
    else if (res.o_indexes.size() != tx.vout.size())
    {
      throw error::internal_error {
          LOCATION_TAG
        , "transactions outputs size (" + std::to_string(tx.vout.size()) + ") "
        //+ "does not match COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES response size "
        //+ "(" + std::to_string(res.o_indexes.size()) + ")"
      };
    }

    BOOST_FOREACH(size_t o, outs)
    {
      if (tx.vout.size() <= o)
      {
        throw error::internal_error {
            LOCATION_TAG
          , "wrong out in transaction: internal index="
          + std::to_string(o)
          + ", total_outs=" + std::to_string(tx.vout.size())
        };
      }

      m_transfers.push_back(boost::value_initialized<transfer_details>());
      transfer_details& td = m_transfers.back();
      td.m_block_height = height;
      td.m_internal_output_index = o;
      td.m_global_output_index = res.o_indexes[o];
      td.m_tx = tx;
      td.m_spent = false;
      cryptonote::keypair in_ephemeral;
      cryptonote::generate_key_image_helper(m_core_data.m_keys, tx_pub_key, o, in_ephemeral, td.m_key_image);

      if (in_ephemeral.pub != boost::get<cryptonote::txout_to_key>(tx.vout[o].target).key)
      {
        throw error::internal_error { LOCATION_TAG, "key_image generated ephemeral public key not matched with output_key"};
      }

      m_key_images[td.m_key_image] = m_transfers.size()-1;
      LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << get_transaction_hash(tx));
      if (0 != m_callback)
        m_callback->on_money_received(height, td.m_tx, td.m_internal_output_index);
    }
  }

  uint64_t tx_money_spent_in_ins = 0;
  // check all outputs for spending (compare key images)
  BOOST_FOREACH(auto& in, tx.vin)
  {
    if(in.type() != typeid(cryptonote::txin_to_key))
      continue;
    auto it = m_key_images.find(boost::get<cryptonote::txin_to_key>(in).k_image);
    if(it != m_key_images.end())
    {
      LOG_PRINT_L0("Spent money: " << print_money(boost::get<cryptonote::txin_to_key>(in).amount) << ", with tx: " << get_transaction_hash(tx));
      tx_money_spent_in_ins += boost::get<cryptonote::txin_to_key>(in).amount;
      transfer_details& td = m_transfers[it->second];
      td.m_spent = true;
      if (0 != m_callback)
        m_callback->on_money_spent(height, td.m_tx, td.m_internal_output_index, tx);
    }
  }

  tx_extra_nonce extra_nonce;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    crypto::hash payment_id;
    if(get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
    {
      uint64_t received = (tx_money_spent_in_ins < tx_money_got_in_outs) ? tx_money_got_in_outs - tx_money_spent_in_ins : 0;
      if (0 < received && null_hash != payment_id)
      {
        payment_details payment;
        payment.m_tx_hash      = cryptonote::get_transaction_hash(tx);
        payment.m_amount       = received;
        payment.m_block_height = height;
        payment.m_unlock_time  = tx.unlock_time;
        m_payments.emplace(payment_id, payment);
        LOG_PRINT_L2("Payment found: " << payment_id << " / " << payment.m_tx_hash << " / " << payment.m_amount);
      }
    }
  }
}

void wallet2::process_unconfirmed(
    const cryptonote::transaction& tx
  )
{
  auto unconf_it = m_unconfirmed_txs.find(get_transaction_hash(tx));
  if(unconf_it != m_unconfirmed_txs.end())
    m_unconfirmed_txs.erase(unconf_it);
}

void wallet2::process_new_blockchain_entry(
    const cryptonote::block& b
  , cryptonote::block_complete_entry& bche
  , crypto::hash& bl_id
  , uint64_t height
  )
{
  //handle transactions from new block

  //optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  if(b.timestamp + 60*60*24 > m_account_creation_timestamp)
  {
    TIME_MEASURE_START(miner_tx_handle_time);
    process_new_transaction(b.miner_tx, height);
    TIME_MEASURE_FINISH(miner_tx_handle_time);

    TIME_MEASURE_START(txs_handle_time);
    BOOST_FOREACH(auto& txblob, bche.txs)
    {
      cryptonote::transaction tx;
      if (!parse_and_validate_tx_from_blob(txblob, tx))
      {
        throw error::tx_parse_error { LOCATION_TAG };
      }
      process_new_transaction(tx, height);
    }
    TIME_MEASURE_FINISH(txs_handle_time);
    LOG_PRINT_L2("Processed block: " << bl_id << ", height " << height << ", " <<  miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time <<")ms");
  }
  else
  {
    LOG_PRINT_L2( "Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account_creation_timestamp);
  }
  m_blockchain.push_back(bl_id);
  ++m_local_bc_height;

  if (0 != m_callback)
  {
    m_callback->on_new_block(height, b);
  }
}

void wallet2::get_short_chain_history(
    std::list<crypto::hash>& ids
  )
{
  size_t i = 0;
  size_t current_multiplier = 1;
  size_t sz = m_blockchain.size();
  if(!sz)
    return;
  size_t current_back_offset = 1;
  bool genesis_included = false;
  while(current_back_offset < sz)
  {
    ids.push_back(m_blockchain[sz-current_back_offset]);
    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }else
    {
      current_back_offset += current_multiplier *= 2;
    }
    ++i;
  }
  if(!genesis_included)
  {
    ids.push_back(m_blockchain[0]);
  }
}

void wallet2::pull_blocks(
    uint64_t start_height
  , size_t& blocks_added
  )
{
  blocks_added = 0;
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
  get_short_chain_history(req.block_ids);
  req.start_height = start_height;
  if (!net_utils::invoke_http_bin_remote_command2(
        m_daemon_address + "/getblocks.bin"
      , req
      , res
      , m_http_client
      , WALLET_RCP_CONNECTION_TIMEOUT
      )
    )
  {
    throw error::no_connection_to_daemon { LOCATION_TAG, "getblocks.bin" };
  }
  else if (res.status == CORE_RPC_STATUS_BUSY)
  {
    throw error::daemon_busy { LOCATION_TAG, "getblocks.bin" };
  }
  else if (res.status != CORE_RPC_STATUS_OK)
  {
    throw error::get_blocks_error { LOCATION_TAG, res.status };
  }

  size_t current_index = res.start_height;
  BOOST_FOREACH(auto& bl_entry, res.blocks)
  {
    cryptonote::block bl;
    if (!cryptonote::parse_and_validate_block_from_blob(bl_entry.block, bl))
    {
      throw error::block_parse_error { LOCATION_TAG, bl_entry.block };
    }

    crypto::hash bl_id = get_block_hash(bl);
    if(current_index >= m_blockchain.size())
    {
      process_new_blockchain_entry(bl, bl_entry, bl_id, current_index);
      ++blocks_added;
    }
    else if(bl_id != m_blockchain[current_index])
    {
      //split detected here !!!
      if (current_index == res.start_height)
      {
        throw error::internal_error {
            LOCATION_TAG
          , "wrong daemon response: split starts from the first block in response " + string_tools::pod_to_hex(bl_id)
          + " (height " + std::to_string(res.start_height) + "), local block id at this height: "
          + string_tools::pod_to_hex(m_blockchain[current_index])
        };
      }

      detach_blockchain(current_index);
      process_new_blockchain_entry(bl, bl_entry, bl_id, current_index);
    }
    else
    {
      LOG_PRINT_L2("Block is already in blockchain: " << string_tools::pod_to_hex(bl_id));
    }

    ++current_index;
  }
}

void wallet2::refresh()
{
  size_t blocks_fetched = 0;
  refresh(0, blocks_fetched);
}

void wallet2::refresh(
    uint64_t start_height
  , size_t & blocks_fetched
  )
{
  bool received_money = false;
  refresh(start_height, blocks_fetched, received_money);
}

void wallet2::refresh(
    uint64_t start_height
  , size_t & blocks_fetched
  , bool& received_money
  )
{
  received_money = false;
  blocks_fetched = 0;
  size_t added_blocks = 0;
  size_t try_count = 0;
  crypto::hash last_tx_hash_id = m_transfers.size() ? get_transaction_hash(m_transfers.back().m_tx) : null_hash;

  while(m_run.load(std::memory_order_relaxed))
  {
    try
    {
      pull_blocks(start_height, added_blocks);
      blocks_fetched += added_blocks;
      if(!added_blocks)
        break;
    }
    catch (const std::exception&)
    {
      blocks_fetched += added_blocks;
      if(try_count < 3)
      {
        LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
        ++try_count;
      }
      else
      {
        LOG_ERROR("pull_blocks failed, try_count=" << try_count);
        throw;
      }
    }
  }
  if(last_tx_hash_id != (m_transfers.size() ? get_transaction_hash(m_transfers.back().m_tx) : null_hash))
  {
    received_money = true;
  }

  LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance: " << print_money(balance()) << ", unlocked: " << print_money(unlocked_balance()));
}

bool wallet2::refresh(
    size_t & blocks_fetched
  , bool& received_money
  , bool& ok
  )
{
  try
  {
    refresh(0, blocks_fetched, received_money);
    ok = true;
  }
  catch (...)
  {
    ok = false;
  }
  return ok;
}

void wallet2::detach_blockchain(
    uint64_t height
  )
{
  LOG_PRINT_L0("Detaching blockchain on height " << height);
  size_t transfers_detached = 0;

  auto it = std::find_if(m_transfers.begin(), m_transfers.end(), [&](const transfer_details& td){return td.m_block_height >= height;});
  size_t i_start = it - m_transfers.begin();

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    auto it_ki = m_key_images.find(m_transfers[i].m_key_image);
    if (it_ki == m_key_images.end())
    {
      throw error::internal_error { LOCATION_TAG, "key image not found" };
    }
    m_key_images.erase(it_ki);
    ++transfers_detached;
  }
  m_transfers.erase(it, m_transfers.end());

  size_t blocks_detached = m_blockchain.end() - (m_blockchain.begin()+height);
  m_blockchain.erase(m_blockchain.begin()+height, m_blockchain.end());
  m_local_bc_height -= blocks_detached;

  for (auto it = m_payments.begin(); it != m_payments.end(); )
  {
    if(height <= it->second.m_block_height)
    {
      it = m_payments.erase(it);
    }
    else
    {
      ++it;
    }
  }

  LOG_PRINT_L0("Detached blockchain on height " << height << ", transfers detached " << transfers_detached << ", blocks detached " << blocks_detached);
}

bool wallet2::deinit()
{
  return true;
}

bool wallet2::clear()
{
  m_blockchain.clear();
  m_transfers.clear();
  cryptonote::block b;
  cryptonote::generate_genesis_block(b);
  m_blockchain.push_back(get_block_hash(b));
  m_local_bc_height = 1;
  return true;
}

bool wallet2::store_keys_to_file(
    const std::string& keys_file_name
  , const std::string& password
  )
{
  std::string account_data;
  bool r = epee::serialization::store_t_to_binary(m_core_data, account_data);
  CHECK_AND_ASSERT_MES(r, false, "failed to serialize wallet keys");
  wallet2::keys_file_data keys_file_data = boost::value_initialized<wallet2::keys_file_data>();

  crypto::chacha8_key key;
  crypto::generate_chacha8_key(password, key);
  std::string cipher;
  cipher.resize(account_data.size());
  keys_file_data.iv = crypto::rand<crypto::chacha8_iv>();
  crypto::chacha8(account_data.data(), account_data.size(), key, keys_file_data.iv, &cipher[0]);
  keys_file_data.account_data = cipher;

  std::string buf;
  r = ::serialization::dump_binary(keys_file_data, buf);
  r = r && epee::file_io_utils::save_string_to_file(keys_file_name, buf); //and never touch wallet_keys_file again, only read
  CHECK_AND_ASSERT_MES(r, false, "failed to generate wallet keys file " << keys_file_name);

  return true;
}

namespace
{
  bool verify_keys(
      const crypto::secret_key& sec
    , const crypto::public_key& expected_pub
    )
  {
    crypto::public_key pub;
    bool r = crypto::secret_key_to_public_key(sec, pub);
    return r && expected_pub == pub;
  }
}

void wallet2::load_keys_from_file(
    const std::string& keys_file_name
  , const std::string& password
  )
{
  wallet2::keys_file_data keys_file_data;
  std::string buf;
  if (!epee::file_io_utils::load_file_to_string(keys_file_name, buf))
  {
    throw error::file_read_error { LOCATION_TAG, keys_file_name };
  }
  else if (!::serialization::parse_binary(buf, keys_file_data))
  {
    throw error::internal_error { LOCATION_TAG, "failed to deserialize \"" + keys_file_name + '\"' };
  }

  crypto::chacha8_key key;
  crypto::generate_chacha8_key(password, key);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  bool r;
  r = epee::serialization::load_t_from_binary(m_core_data, account_data);
  r = r && verify_keys(m_core_data.m_keys.m_view_secret_key,  m_core_data.m_keys.m_account_address.m_view_public_key);
  r = r && verify_keys(m_core_data.m_keys.m_spend_secret_key, m_core_data.m_keys.m_account_address.m_spend_public_key);
  if (!r)
  {
    throw error::invalid_password { LOCATION_TAG };
  }
}

crypto::secret_key wallet2::generate(
    const std::string& wallet_
  , const std::string& password
  , const crypto::secret_key& recovery_key
  , bool recover
  , bool deterministic
  )
{
  clear();
  prepare_file_names(wallet_);

  boost::system::error_code ignored_ec;
  if (boost::filesystem::exists(m_wallet_file, ignored_ec))
  {
    throw error::file_exists_error { LOCATION_TAG, m_wallet_file };
  }
  else if (boost::filesystem::exists(m_keys_file, ignored_ec))
  {
    throw error::file_exists_error { LOCATION_TAG, m_keys_file };
  }

  crypto::secret_key new_recovery_key;
  if (recover)
  {
    m_core_data = recover_account(recovery_key);
  }
  else if (deterministic)
  {
    recoverable_account account = create_recoverable_account();
    m_core_data = account.m_core_data;
    new_recovery_key = account.m_recovery_key;
  }
  else
  {
    m_core_data = create_unrecoverable_account();
  }

  m_account_public_address = m_core_data.m_keys.m_account_address;

  bool r = store_keys_to_file(m_keys_file, password);
  if (!r)
  {
    throw error::file_save_error { LOCATION_TAG, m_keys_file };
  }

  r = file_io_utils::save_string_to_file(m_wallet_file + ".address.txt", m_core_data.m_keys.m_account_address.base58());
  if(!r) LOG_PRINT_RED_L0("String with address text not saved");

  store();
  return new_recovery_key;
}

void wallet2::wallet_exists(
    const std::string& file_path
  , bool& keys_file_exists
  , bool& wallet_file_exists
  )
{
  std::string keys_file, wallet_file;
  do_prepare_file_names(file_path, keys_file, wallet_file);

  boost::system::error_code ignore;
  keys_file_exists = boost::filesystem::exists(keys_file, ignore);
  wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
}

bool wallet2::parse_payment_id(
    const std::string& payment_id_str
  , crypto::hash& payment_id
  )
{
  cryptonote::blobdata payment_id_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data))
  {
    return false;
  }

  if(sizeof(crypto::hash) != payment_id_data.size())
  {
    return false;
  }

  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
  return true;
}

bool wallet2::prepare_file_names(
    const std::string& file_path
  )
{
  do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
  return true;
}

bool wallet2::check_connection()
{
  if(m_http_client.is_connected())
  {
    return true;
  }

  net_utils::http::url_content u;
  net_utils::parse_url(m_daemon_address, u);
  if(!u.port)
  {
    u.port = RPC_DEFAULT_PORT;
  }
  return m_http_client.connect(u.host, std::to_string(u.port), WALLET_RCP_CONNECTION_TIMEOUT);
}

void wallet2::load(
    const std::string& wallet_
  , const std::string& password
  )
{
  clear();
  prepare_file_names(wallet_);

  boost::system::error_code e;
  bool exists = boost::filesystem::exists(m_keys_file, e);
  if (e || !exists)
  {
    throw error::file_not_found_error { LOCATION_TAG, m_keys_file };
  }

  load_keys_from_file(m_keys_file, password);
  LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_core_data.m_keys.m_account_address.base58());

  //keys loaded ok!
  //try to load wallet file. but even if we failed, it is not big problem
  if(!boost::filesystem::exists(m_wallet_file, e) || e)
  {
    LOG_PRINT_L0("file not found: " << m_wallet_file << ", starting with empty blockchain");
    m_account_public_address = m_core_data.m_keys.m_account_address;
    return;
  }
  bool r = tools::unserialize_obj_from_file(*this, m_wallet_file);
  if (!r)
  {
    throw error::file_read_error { LOCATION_TAG, m_wallet_file };
  }
  else if (
      m_account_public_address.m_spend_public_key != m_core_data.m_keys.m_account_address.m_spend_public_key
   || m_account_public_address.m_view_public_key  != m_core_data.m_keys.m_account_address.m_view_public_key
   )
  {
    throw error::mismatched_files { LOCATION_TAG, m_wallet_file + ", " + m_keys_file };
  }

  if(m_blockchain.empty())
  {
    cryptonote::block b;
    cryptonote::generate_genesis_block(b);
    m_blockchain.push_back(get_block_hash(b));
  }
  m_local_bc_height = m_blockchain.size();
}

void wallet2::store()
{
  if (!tools::serialize_obj_to_file(*this, m_wallet_file))
  {
    throw error::file_save_error { LOCATION_TAG, m_wallet_file };
  }
}

uint64_t wallet2::unlocked_balance()
{
  uint64_t amount = 0;
  BOOST_FOREACH(transfer_details& td, m_transfers)
  {
    if(!td.m_spent && is_transfer_unlocked(td))
    {
      amount += td.amount();
    }
  }

  return amount;
}

uint64_t wallet2::balance()
{
  uint64_t amount = 0;
  BOOST_FOREACH(auto& td, m_transfers)
  {
    if(!td.m_spent)
    {
      amount += td.amount();
    }
  }

  BOOST_FOREACH(auto& utx, m_unconfirmed_txs)
  {
    amount+= utx.second.m_change;
  }

  return amount;
}

void wallet2::get_transfers(
    wallet2::transfer_container& incoming_transfers
  ) const
{
  incoming_transfers = m_transfers;
}

void wallet2::get_payments(
    const crypto::hash& payment_id
  , std::list<wallet2::payment_details>& payments
  , uint64_t min_height
  ) const
{
  auto range = m_payments.equal_range(payment_id);
  std::for_each(range.first, range.second, [&payments, &min_height](const payment_container::value_type& x) {
    if (min_height < x.second.m_block_height)
    {
      payments.push_back(x.second);
    }
  });
}

std::string wallet2::secret_view_key_as_hex()
{
  return string_tools::pod_to_hex(m_core_data.m_keys.m_view_secret_key);
}

std::string wallet2::get_account_address_base58()
{
  return m_core_data.m_keys.m_account_address.base58();
}

bool wallet2::is_transfer_unlocked(
    const transfer_details& td
  ) const
{
  if(!is_tx_spendtime_unlocked(td.m_tx.unlock_time))
  {
    return false;
  }

  if(td.m_block_height + DEFAULT_TX_SPENDABLE_AGE > m_blockchain.size())
  {
    return false;
  }

  return true;
}

bool wallet2::is_tx_spendtime_unlocked(
    uint64_t unlock_time
  ) const
{
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    //interpret as block index
    if(m_blockchain.size()-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  else
  {
    //interpret as time
    uint64_t current_time = static_cast<uint64_t>(time(NULL));
    if(current_time + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS >= unlock_time)
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  return false;
}

namespace
{
  template<typename T>
  T pop_random_value(
      std::vector<T>& vec
    )
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    size_t idx = crypto::rand<size_t>() % vec.size();
    T res = vec[idx];
    if (idx + 1 != vec.size())
    {
      vec[idx] = vec.back();
    }
    vec.resize(vec.size() - 1);

    return res;
  }
}

// Select random input sources for transaction.
// returns:
//    direct return: amount of money found
//    modified reference: selected_transfers, a list of iterators/indices of input sources
uint64_t wallet2::select_transfers(
    uint64_t needed_money
  , bool add_dust
  , uint64_t dust
  , std::list<transfer_container::iterator>& selected_transfers
  )
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;

  // aggregate sources available for transfers
  // if dust needed, take dust from only one source (so require source has at least dust amount)
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!td.m_spent && is_transfer_unlocked(td))
    {
      if (dust < td.amount())
      {
        unused_transfers_indices.push_back(i);
      }
      else
      {
        unused_dust_indices.push_back(i);
      }
    }
  }

  bool select_one_dust = add_dust && !unused_dust_indices.empty();
  uint64_t found_money = 0;
  while (found_money < needed_money && (!unused_transfers_indices.empty() || !unused_dust_indices.empty()))
  {
    size_t idx;
    if (select_one_dust)
    {
      idx = pop_random_value(unused_dust_indices);
      select_one_dust = false;
    }
    else
    {
      idx = !unused_transfers_indices.empty() ? pop_random_value(unused_transfers_indices) : pop_random_value(unused_dust_indices);
    }

    transfer_container::iterator it = m_transfers.begin() + idx;
    selected_transfers.push_back(it);
    found_money += it->amount();
  }

  return found_money;
}

void wallet2::add_unconfirmed_tx(
    const cryptonote::transaction& tx
  , uint64_t change_amount
  )
{
  unconfirmed_transfer_details& utd = m_unconfirmed_txs[cryptonote::get_transaction_hash(tx)];
  utd.m_change = change_amount;
  utd.m_sent_time = time(NULL);
  utd.m_tx = tx;
}

void wallet2::transfer(
    const std::vector<cryptonote::tx_destination_entry>& dsts
  , size_t fake_outputs_count
  , uint64_t unlock_time
  , uint64_t fee
  , const std::vector<uint8_t>& extra
  , transaction_splitting::strategy destination_split_strategy
  , const tx_dust_policy& dust_policy
  , cryptonote::transaction& tx
  , pending_tx &ptx
  )
{
  using namespace cryptonote;
  // throw if attempting a transaction with no destinations
  if (dsts.empty())
  {
    throw error::zero_destination { LOCATION_TAG };
  }

  uint64_t needed_money = fee;

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  BOOST_FOREACH(auto& dt, dsts)
  {
    if (0 == dt.amount)
    {
      throw error::zero_destination { LOCATION_TAG };
    }
    needed_money += dt.amount;
    if (needed_money < dt.amount)
    {
      throw error::tx_sum_overflow { LOCATION_TAG };
    }
  }

  // randomly select inputs for transaction
  // throw if requested send amount is greater than amount available to send
  std::list<transfer_container::iterator> selected_transfers;
  uint64_t found_money = select_transfers(needed_money, 0 == fake_outputs_count, dust_policy.dust_threshold, selected_transfers);
  if (found_money < needed_money)
  {
    throw error::not_enough_money { LOCATION_TAG, "found: " + std::to_string(found_money) + ", need:" + std::to_string(needed_money) };
  }

  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;
  typedef cryptonote::tx_source_entry::output_entry tx_output_entry;

  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response daemon_resp = AUTO_VAL_INIT(daemon_resp);
  if(fake_outputs_count)
  {
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request req = AUTO_VAL_INIT(req);
    req.outs_count = fake_outputs_count + 1;// add one to make possible (if need) to skip real output key
    BOOST_FOREACH(transfer_container::iterator it, selected_transfers)
    {
      if (it->m_tx.vout.size() <= it->m_internal_output_index)
      {
        throw error::internal_error {
            LOCATION_TAG
          , "m_internal_output_index = " + std::to_string(it->m_internal_output_index)
          + " is greater or equal to outputs count = " + std::to_string(it->m_tx.vout.size())
        };
      }
      req.amounts.push_back(it->amount());
    }

    bool r = epee::net_utils::invoke_http_bin_remote_command2(
        m_daemon_address + "/getrandom_outs.bin"
      , req
      , daemon_resp
      , m_http_client
      , 200000
      );

    if (!r)
    {
      throw error::no_connection_to_daemon { LOCATION_TAG, "getrandom_outs.bin" };
    }
    else if (daemon_resp.status == CORE_RPC_STATUS_BUSY)
    {
      throw error::daemon_busy { LOCATION_TAG, "getrandom_outs.bin" };
    }
    else if (daemon_resp.status != CORE_RPC_STATUS_OK)
    {
      throw error::get_random_outs_error { LOCATION_TAG, daemon_resp.status };
    }
    if (daemon_resp.outs.size() != selected_transfers.size())
    {
      throw error::internal_error {
          LOCATION_TAG
        , "daemon returned incorrect number of transactions for getrandom_outs.bin"
      };
    }

    std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount> scanty_outs;
    BOOST_FOREACH(COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& amount_outs, daemon_resp.outs)
    {
      if (amount_outs.outs.size() < fake_outputs_count)
      {
        scanty_outs.push_back(amount_outs);
      }
    }
    if (!scanty_outs.empty())
    {
      throw error::not_enough_outs_to_mix { LOCATION_TAG };
    }
  }

  //prepare inputs
  size_t i = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  BOOST_FOREACH(transfer_container::iterator it, selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& src = sources.back();
    transfer_details& td = *it;
    src.amount = td.amount();
    //paste mixin transaction
    if(daemon_resp.outs.size())
    {
      daemon_resp.outs[i].outs.sort([](const out_entry& a, const out_entry& b){return a.global_amount_index < b.global_amount_index;});
      BOOST_FOREACH(out_entry& daemon_oe, daemon_resp.outs[i].outs)
      {
        if(td.m_global_output_index == daemon_oe.global_amount_index)
          continue;
        tx_output_entry oe;
        oe.first = daemon_oe.global_amount_index;
        oe.second = daemon_oe.out_key;
        src.outputs.push_back(oe);
        if(src.outputs.size() >= fake_outputs_count)
          break;
      }
    }

    //paste real transaction to the random index
    auto it_to_insert = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
    {
      return a.first >= td.m_global_output_index;
    });
    //size_t real_index = src.outputs.size() ? (rand() % src.outputs.size() ):0;
    tx_output_entry real_oe;
    real_oe.first = td.m_global_output_index;
    real_oe.second = boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key;
    auto interted_it = src.outputs.insert(it_to_insert, real_oe);
    src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx);
    src.real_output = interted_it - src.outputs.begin();
    src.real_output_in_tx_index = td.m_internal_output_index;
    detail::print_source_entry(src);
    ++i;
  }

  cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
  if (needed_money < found_money)
  {
    change_dts.addr = m_core_data.m_keys.m_account_address;
    change_dts.amount = found_money - needed_money;
  }

  uint64_t dust = 0;
  std::vector<cryptonote::tx_destination_entry> splitted_dsts;
  destination_split_strategy(dsts, change_dts, dust_policy.dust_threshold, splitted_dsts, dust);
  if (dust_policy.dust_threshold < dust)
  {
    throw error::internal_error {
      LOCATION_TAG
    , "invalid dust value: dust = " + std::to_string(dust)
    + ", dust_threshold = " + std::to_string(dust_policy.dust_threshold)
    };
  }
  if (0 != dust && !dust_policy.add_to_fee)
  {
    splitted_dsts.push_back(cryptonote::tx_destination_entry(dust, dust_policy.addr_for_dust));
  }

  bool r = cryptonote::construct_tx(m_core_data.m_keys, sources, splitted_dsts, extra, tx, unlock_time);
  if (!r)
  {
    throw error::tx_not_constructed { LOCATION_TAG };
  }
  else if(m_upper_transaction_size_limit <= get_object_blobsize(tx))
  {
    throw error::tx_too_big { LOCATION_TAG };
  }

  std::string key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
    key_images += boost::to_string(in.k_image) + " ";
    return true;
  });
  if (!all_are_txin_to_key)
  {
    throw error::unexpected_txin_type { LOCATION_TAG };
  }

  ptx.key_images = key_images;
  ptx.fee = fee;
  ptx.dust = dust;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
}

// take a pending tx and actually send it to the daemon
void wallet2::commit_tx(
    pending_tx& ptx
  )
{
  using namespace cryptonote;
  COMMAND_RPC_SEND_RAW_TX::request req;
  req.tx_as_hex = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx));
  COMMAND_RPC_SEND_RAW_TX::response daemon_send_resp;
  bool r = epee::net_utils::invoke_http_json_remote_command2(
      m_daemon_address + "/sendrawtransaction"
    , req
    , daemon_send_resp
    , m_http_client
    , 200000
    );
  if (!r)
  {
    throw error::no_connection_to_daemon { LOCATION_TAG, "sendrawtransaction" };
  }
  else if (daemon_send_resp.status == CORE_RPC_STATUS_BUSY)
  {
    throw error::daemon_busy { LOCATION_TAG, "sendrawtransaction" };
  }
  else if (daemon_send_resp.status != CORE_RPC_STATUS_OK)
  {
    throw error::tx_rejected { LOCATION_TAG, daemon_send_resp.status };
  }

  add_unconfirmed_tx(ptx.tx, ptx.change_dts.amount);

  LOG_PRINT_L2("transaction " << get_transaction_hash(ptx.tx) << " generated ok and sent to daemon, key_images: [" << ptx.key_images << "]");

  BOOST_FOREACH(transfer_container::iterator it, ptx.selected_transfers)
  {
    it->m_spent = true;
  }

  LOG_PRINT_L0("Transaction successfully sent. <" << get_transaction_hash(ptx.tx) << ">" << ENDL
            << "Commission: " << print_money(ptx.fee+ptx.dust) << " (dust: " << print_money(ptx.dust) << ")" << ENDL
            << "Balance: " << print_money(balance()) << ENDL
            << "Unlocked: " << print_money(unlocked_balance()) << ENDL
            << "Please, wait for confirmation for your balance to be unlocked.");
}

void wallet2::commit_tx(
    std::vector<pending_tx>& ptx_vector
  )
{
  for (auto & ptx : ptx_vector)
  {
    commit_tx(ptx);
  }
}

// separated the call(s) to wallet2::transfer into their own function
//
// this function will make multiple calls to wallet2::transfer if multiple
// transactions will be required
std::vector<wallet2::pending_tx> wallet2::create_transactions(
    std::vector<cryptonote::tx_destination_entry> dsts
  , const size_t fake_outs_count
  , const uint64_t unlock_time
  , const uint64_t fee
  , const std::vector<uint8_t> extra
  )
{

  // failsafe split attempt counter
  size_t attempt_count = 0;

  for(attempt_count = 1; ;attempt_count++)
  {
    auto split_values = transaction_splitting::split_amounts(dsts, attempt_count);

    // Throw if split_amounts comes back with a vector of size different than it should
    if (split_values.size() != attempt_count)
    {
      throw std::runtime_error("Splitting transactions returned a number of potential tx not equal to what was requested");
    }

    std::vector<pending_tx> ptx_vector;
    try
    {
      // for each new destination vector (i.e. for each new tx)
      for (auto & dst_vector : split_values)
      {
        cryptonote::transaction tx;
        pending_tx ptx;
        transfer(
            dst_vector
          , fake_outs_count
          , unlock_time
          , fee
          , extra
          , &transaction_splitting::digit_split_strategy
          , tx_dust_policy(fee)
          , tx
          , ptx
          );
        ptx_vector.push_back(ptx);

        // mark transfers to be used as "spent"
        BOOST_FOREACH(transfer_container::iterator it, ptx.selected_transfers)
        {
          it->m_spent = true;
        }
      }

      // if we made it this far, we've selected our transactions.  committing them will mark them spent,
      // so this is a failsafe in case they don't go through
      // unmark pending tx transfers as spent
      for (auto & ptx : ptx_vector)
      {
        // mark transfers to be used as not spent
        BOOST_FOREACH(transfer_container::iterator it2, ptx.selected_transfers)
        {
          it2->m_spent = false;
        }
      }

      // if we made it this far, we're OK to actually send the transactions
      return ptx_vector;

    }
    // only catch this here, other exceptions need to pass through to the calling function
    catch (const tools::error::tx_too_big& e)
    {

      // unmark pending tx transfers as spent
      for (auto & ptx : ptx_vector)
      {
        // mark transfers to be used as not spent
        BOOST_FOREACH(transfer_container::iterator it2, ptx.selected_transfers)
        {
          it2->m_spent = false;
        }
      }

      if (attempt_count >= MAX_SPLIT_ATTEMPTS)
      {
        throw;
      }
    }
    catch (...)
    {
      // in case of some other exception, make sure any tx in queue are marked unspent again

      // unmark pending tx transfers as spent
      for (auto & ptx : ptx_vector)
      {
        // mark transfers to be used as not spent
        BOOST_FOREACH(transfer_container::iterator it2, ptx.selected_transfers)
        {
          it2->m_spent = false;
        }
      }

      throw;
    }
  }
}
}
