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

namespace
{
  uint64_t const DEFAULT_TX_SPENDABLE_AGE = 10;
  unsigned int const WALLET_RCP_CONNECTION_TIMEOUT = 200000;
}

class i_wallet2_callback
{
public:
  virtual void on_new_block(
      uint64_t height
    , const cryptonote::block& block
    )
  {}

  virtual void on_money_received(
      uint64_t height
    , const cryptonote::transaction& tx
    , size_t out_index
    )
  {}

  virtual void on_money_spent(
      uint64_t height
    , const cryptonote::transaction& in_tx
    , size_t out_index
    , const cryptonote::transaction& spend_tx
    )
  {}

  virtual void on_skip_transaction(
      uint64_t height
    , const cryptonote::transaction& tx
    )
  {}
};

struct tx_dust_policy
{
  uint64_t dust_threshold;
  bool add_to_fee;
  cryptonote::account_public_address addr_for_dust;

  tx_dust_policy(
      uint64_t a_dust_threshold = 0
    , bool an_add_to_fee = true
    , cryptonote::account_public_address an_addr_for_dust = cryptonote::account_public_address()
    )
    : dust_threshold(a_dust_threshold)
    , add_to_fee(an_add_to_fee)
    , addr_for_dust(an_addr_for_dust)
  {}
};

class wallet2
{
public:
  struct transfer_details
  {
    uint64_t m_block_height;
    cryptonote::transaction m_tx;
    size_t m_internal_output_index;
    uint64_t m_global_output_index;
    bool m_spent;
    crypto::key_image m_key_image; //TODO: key_image stored twice :(

    uint64_t amount() const
    {
      return m_tx.vout[m_internal_output_index].amount;
    }
  };

  struct payment_details
  {
    crypto::hash m_tx_hash;
    uint64_t m_amount;
    uint64_t m_block_height;
    uint64_t m_unlock_time;
  };

  struct unconfirmed_transfer_details
  {
    cryptonote::transaction m_tx;
    uint64_t m_change;
    time_t m_sent_time;
  };

  typedef std::vector<transfer_details> transfer_container;
  typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;

  struct pending_tx
  {
    cryptonote::transaction tx;
    uint64_t dust, fee;
    cryptonote::tx_destination_entry change_dts;
    std::list<transfer_container::iterator> selected_transfers;
    std::string key_images;
  };

  struct keys_file_data
  {
    crypto::chacha8_iv iv;
    std::string account_data;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(iv)
      FIELD(account_data)
    END_SERIALIZE()
  };

private:
  cryptonote::account_base m_account;
  std::string m_daemon_address;
  std::string m_wallet_file;
  std::string m_keys_file;
  epee::net_utils::http::http_simple_client m_http_client;
  std::vector<crypto::hash> m_blockchain;
  std::atomic<uint64_t> m_local_bc_height; //temporary workaround
  std::unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;

  transfer_container m_transfers;
  payment_container m_payments;
  std::unordered_map<crypto::key_image, size_t> m_key_images;
  cryptonote::account_public_address m_account_public_address;
  uint64_t m_upper_transaction_size_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value

  std::atomic<bool> m_run;

  i_wallet2_callback* m_callback;

  wallet2(
      const wallet2&
    )
    : m_run(true)
    , m_callback(0)
  {};
public:
  wallet2()
    : m_run(true)
    , m_callback(0)
  {};

  crypto::secret_key generate(
      const std::string& wallet
    , const std::string& password
    , const crypto::secret_key& recovery_param = crypto::secret_key()
    , bool recover = false
    , bool two_random = false
    );

  void load(
      const std::string& wallet
    , const std::string& password
    );

  void store();

  cryptonote::account_base& get_account()
  {
    return m_account;
  }

  // upper_transaction_size_limit as defined below is set to
  // approximately 125% of the fixed minimum allowable penalty
  // free block size. TODO: fix this so that it actually takes
  // into account the current median block size rather than
  // the minimum block size.
  void init(
      const std::string& daemon_address = "http://localhost:8080"
    , uint64_t upper_transaction_size_limit = ((CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 125) / 100) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE
    );

  bool deinit();

  void stop()
  {
    m_run.store(false, std::memory_order_relaxed);
  }

  i_wallet2_callback* callback() const
  {
    return m_callback;
  }

  void callback(
      i_wallet2_callback* callback
    )
  {
    m_callback = callback;
  }

  bool get_seed(
      std::string& electrum_words
    );

  void refresh();

  void refresh(
      uint64_t start_height
    , size_t & blocks_fetched
    );

  void refresh(
      uint64_t start_height
    , size_t & blocks_fetched
    , bool& received_money
    );

  bool refresh(
      size_t & blocks_fetched
    , bool& received_money
    , bool& ok
    );

  uint64_t balance();

  uint64_t unlocked_balance();

  void transfer(
      const std::vector<cryptonote::tx_destination_entry>& dsts
    , size_t fake_outputs_count
    , uint64_t unlock_time
    , uint64_t fee
    , const std::vector<uint8_t>& extra
    , transaction_splitting::strategy destination_split_strategy
    , const tx_dust_policy& dust_policy
    , cryptonote::transaction& tx
    , pending_tx& ptx
    );

  void commit_tx(
      pending_tx& ptx_vector
    );

  void commit_tx(
      std::vector<pending_tx>& ptx_vector
    );

  std::vector<pending_tx> create_transactions(
      std::vector<cryptonote::tx_destination_entry> dsts
    , const size_t fake_outs_count
    , const uint64_t unlock_time
    , const uint64_t fee
    , const std::vector<uint8_t> extra
    );

  bool check_connection();

  void get_transfers(
      wallet2::transfer_container& incoming_transfers
    ) const;

  void get_payments(
      const crypto::hash& payment_id
    , std::list<wallet2::payment_details>& payments
    , uint64_t min_height = 0
    ) const;

  uint64_t get_blockchain_current_height() const
  {
    return m_local_bc_height;
  }

  template <class t_archive>
  inline void serialize(
      t_archive &a
    , const unsigned int ver
    )
  {
    if(ver < 5)
      return;
    a & m_blockchain;
    a & m_transfers;
    a & m_account_public_address;
    a & m_key_images;
    if(ver < 6)
      return;
    a & m_unconfirmed_txs;
    if(ver < 7)
      return;
    a & m_payments;
  }

  static void wallet_exists(
      const std::string& file_path
    , bool& keys_file_exists
    , bool& wallet_file_exists
    );

  static bool parse_payment_id(
      const std::string& payment_id_str
    , crypto::hash& payment_id
    );

private:

  bool store_keys_to_file(
      const std::string& keys_file_name
    , const std::string& password
    );

  void load_keys_from_file(
      const std::string& keys_file_name
    , const std::string& password
    );

  void process_new_transaction(
      const cryptonote::transaction& tx
    , uint64_t height
    );

  void process_new_blockchain_entry(
      const cryptonote::block& b
    , cryptonote::block_complete_entry& bche
    , crypto::hash& bl_id
    , uint64_t height
    );

  void detach_blockchain(
      uint64_t height
    );

  void get_short_chain_history(
      std::list<crypto::hash>& ids
    );

  bool is_tx_spendtime_unlocked(
      uint64_t unlock_time
    ) const;

  bool is_transfer_unlocked(
      const transfer_details& td
    ) const;

  bool clear();

  void pull_blocks(
      uint64_t start_height
    , size_t& blocks_added
    );

  uint64_t select_transfers(
      uint64_t needed_money
    , bool add_dust
    , uint64_t dust
    , std::list<transfer_container::iterator>& selected_transfers
    );

  bool prepare_file_names(
      const std::string& file_path
    );

  void process_unconfirmed(
      const cryptonote::transaction& tx
    );

  void add_unconfirmed_tx(
      const cryptonote::transaction& tx
    , uint64_t change_amount
    );
};
}
BOOST_CLASS_VERSION(tools::wallet2, 7)

namespace boost
{
namespace serialization
{
  template <class Archive>
  inline void serialize(
      Archive &a
    , tools::wallet2::transfer_details &x
    , const boost::serialization::version_type ver
    )
  {
    a & x.m_block_height;
    a & x.m_global_output_index;
    a & x.m_internal_output_index;
    a & x.m_tx;
    a & x.m_spent;
    a & x.m_key_image;
  }

  template <class Archive>
  inline void serialize(
      Archive &a
    , tools::wallet2::unconfirmed_transfer_details &x
    , const boost::serialization::version_type ver
    )
  {
    a & x.m_change;
    a & x.m_sent_time;
    a & x.m_tx;
  }

  template <class Archive>
  inline void serialize(
      Archive& a
    , tools::wallet2::payment_details& x
    , const boost::serialization::version_type ver
    )
  {
    a & x.m_tx_hash;
    a & x.m_amount;
    a & x.m_block_height;
    a & x.m_unlock_time;
  }
}
}

namespace tools
{

namespace detail
{
  inline void print_source_entry(
      const cryptonote::tx_source_entry& src
    )
  {
    std::string indexes;
    std::for_each(
        src.outputs.begin()
      , src.outputs.end()
      , [&](const cryptonote::tx_source_entry::output_entry& s_e)
        {
          indexes += boost::to_string(s_e.first) + " ";
        }
      );
    LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
  }
}

}
