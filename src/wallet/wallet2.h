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

#pragma once

#include "wallet/i_wallet2_callback.h"
#include "wallet/transfer_container.h"
#include "wallet/transfer_details.h"
#include "wallet/tx_dust_policy.h"
#include "wallet/payment_details.h"
#include "wallet/pending_tx.h"
#include "wallet/keys_file_data.h"
#include "wallet/unconfirmed_transfer_details.h"

#include <memory>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <atomic>

#include "include_base_utils.h"
#include "cryptonote_core/account.h"
#include "cryptonote_core/account_boost_serialization.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "net/http_client.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "common/unordered_containers_boost_serialization.h"
#include "crypto/chacha8.h"
#include "crypto/hash.h"
#include "wallet/transaction_splitting.h"

#include "wallet_errors.h"

#include <iostream>

namespace tools
{

class wallet2
{
public:
  typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;
private:
  cryptonote::core_account_data m_core_data;
  uint64_t m_account_creation_timestamp; // not accurate for recovered accounts
  std::string m_daemon_address;
  std::string m_wallet_file;
  std::string m_keys_file;
  epee::net_utils::http::http_simple_client m_http_client;
  std::vector<crypto::hash> m_blockchain;
  std::unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;

  transfer_container m_transfers;
  payment_container m_payments;
  std::unordered_map<crypto::key_image, size_t> m_key_images;
  cryptonote::account_public_address m_account_public_address;
  uint64_t m_upper_transaction_size_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value

  std::atomic<bool> m_run;

  i_wallet2_callback* m_callback;

  wallet2(wallet2 const &)
    : m_run(true)
    , m_callback(0)
  {};
public:
  wallet2()
    : m_run(true)
    , m_callback(0)
  {};

  crypto::secret_key generate(
      std::string const & wallet
    , std::string const & password
    , crypto::secret_key const & recovery_param = crypto::secret_key()
    , bool recover = false
    , bool two_random = false
    );

  void load(
      std::string const & wallet
    , std::string const & password
    );

  void store();

  // upper_transaction_size_limit as defined below is set to
  // approximately 125% of the fixed minimum allowable penalty
  // free block size. TODO: fix this so that it actually takes
  // into account the current median block size rather than
  // the minimum block size.
  void init(
      std::string const & daemon_address = "http://localhost:8080"
    , uint64_t upper_transaction_size_limit = ((CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 125) / 100) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE
    );

  bool deinit();

  void stop()
  {
    m_run.store(false, std::memory_order_relaxed);
  }

  void callback(i_wallet2_callback* callback)
  {
    m_callback = callback;
  }

  bool get_seed(std::string& electrum_words);

  size_t refresh(uint64_t start_height);

  uint64_t balance();

  uint64_t unlocked_balance();

  void transfer(
      std::vector<cryptonote::tx_destination_entry> const & dsts
    , size_t fake_outputs_count
    , uint64_t unlock_time
    , uint64_t fee
    , std::vector<uint8_t> const & extra
    , transaction_splitting::strategy destination_split_strategy
    , tx_dust_policy const & dust_policy
    , cryptonote::transaction& tx
    , pending_tx& ptx
    );

  void commit_tx(pending_tx& ptx_vector);

  void commit_tx(std::vector<pending_tx>& ptx_vector);

  std::vector<pending_tx> create_transactions(
      std::vector<cryptonote::tx_destination_entry> dsts
    , size_t const fake_outs_count
    , uint64_t const unlock_time
    , uint64_t const fee
    , std::vector<uint8_t> const extra
    );

  bool check_connection();

  void get_transfers(transfer_container & incoming_transfers) const;

  void get_payments(
      crypto::hash const & payment_id
    , std::vector<payment_details> & payments
    , uint64_t min_height = 0
    ) const;

  std::string secret_view_key_as_hex();

  std::string get_account_address_base58();

  template <class T_archive>
  void serialize(
      T_archive & a
    , unsigned int const ver
    )
  {
    if(ver < 5)
    {
      return;
    }
    a & m_blockchain;
    a & m_transfers;
    a & m_account_public_address;
    a & m_key_images;
    if(ver < 6)
    {
      return;
    }
    a & m_unconfirmed_txs;
    if(ver < 7)
    {
      return;
    }
    a & m_payments;
  }

public:
  static void wallet_exists(
      std::string const & file_path
    , bool& keys_file_exists
    , bool& wallet_file_exists
    );

  static bool parse_payment_id(
      const std::string& payment_id_str
    , crypto::hash& payment_id
    );

private:

  bool store_keys_to_file(
      std::string const & keys_file_name
    , std::string const & password
    );

  void load_keys_from_file(
      std::string const & keys_file_name
    , std::string const & password
    );

  void process_new_transaction(
      cryptonote::transaction const & tx
    , uint64_t height
    );

  void process_new_blockchain_entry(
      cryptonote::block const & b
    , cryptonote::block_complete_entry& bche
    , crypto::hash& bl_id
    , uint64_t height
    );

  void detach_blockchain(uint64_t height);

  void get_short_chain_history(std::list<crypto::hash>& ids);

  bool is_tx_spendtime_unlocked(uint64_t unlock_time) const;

  bool is_transfer_unlocked(transfer_details const & td) const;

  bool clear();

  size_t pull_blocks(uint64_t start_height);

  uint64_t select_transfers(
      uint64_t needed_money
    , bool add_dust
    , uint64_t dust
    , std::vector<transfer_container::iterator>& selected_transfers
    );
};
}
BOOST_CLASS_VERSION(tools::wallet2, 7)
