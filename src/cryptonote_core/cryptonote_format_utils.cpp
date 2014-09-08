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

#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_format_utils.h"
#include <boost/foreach.hpp>
#include "cryptonote_config.h"
#include "miner.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

namespace cryptonote
{
  //---------------------------------------------------------------
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h)
  {
    std::ostringstream s;
    binary_archive<true> a(s);
    ::serialization::serialize(a, const_cast<transaction_prefix&>(tx));
    crypto::cn_fast_hash(s.str().data(), s.str().size(), h);
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx)
  {
    crypto::hash h = null_hash;
    get_transaction_prefix_hash(tx, h);
    return h;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata& tx_blob, transaction& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse transaction from blob");
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata& tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse transaction from blob");
    //TODO: validate tx

    crypto::cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);
    get_transaction_prefix_hash(tx, tx_prefix_hash);
    return true;
  }
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_size, uint64_t already_generated_coins, size_t current_block_size, uint64_t fee, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce, size_t max_outs) {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    keypair txkey = keypair::generate();
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if(!extra_nonce.empty())
      if(!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        return false;

    txin_gen in;
    in.height = height;

    uint64_t block_reward;
    if(!get_block_reward(median_size, current_block_size, already_generated_coins, block_reward))
    {
      LOG_PRINT_L0("Block is too big");
      return false;
    }
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    LOG_PRINT_L1("Creating block template: reward " << block_reward <<
      ", fee " << fee)
#endif
    block_reward += fee;

    std::vector<uint64_t> out_amounts;
    decompose_amount_into_digits(
        block_reward
      , config::DEFAULT_DUST_THRESHOLD
      , [&out_amounts](uint64_t a_chunk) { out_amounts.push_back(a_chunk); }
      , [&out_amounts](uint64_t a_dust) { out_amounts.push_back(a_dust); }
      );

    CHECK_AND_ASSERT_MES(1 <= max_outs, false, "max_out must be non-zero");
    while (max_outs < out_amounts.size())
    {
      out_amounts[out_amounts.size() - 2] += out_amounts.back();
      out_amounts.resize(out_amounts.size() - 1);
    }

    uint64_t summary_amounts = 0;
    for (size_t no = 0; no < out_amounts.size(); no++)
    {
      crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);;
      crypto::public_key out_eph_public_key = AUTO_VAL_INIT(out_eph_public_key);
      bool r = crypto::generate_key_derivation(miner_address.m_view_public_key, txkey.sec, derivation);
      CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to generate_key_derivation(" << miner_address.m_view_public_key << ", " << txkey.sec << ")");

      r = crypto::derive_public_key(derivation, no, miner_address.m_spend_public_key, out_eph_public_key);
      CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", " << no << ", "<< miner_address.m_spend_public_key << ")");

      txout_to_key tk;
      tk.key = out_eph_public_key;

      tx_out out;
      summary_amounts += out.amount = out_amounts[no];
      out.target = tk;
      tx.vout.push_back(out);
    }

    CHECK_AND_ASSERT_MES(summary_amounts == block_reward, false, "Failed to construct miner tx, summary_amounts = " << summary_amounts << " not equal block_reward = " << block_reward);

    tx.version = CURRENT_TRANSACTION_VERSION;
    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);
    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return true;
  }
  //---------------------------------------------------------------
  bool generate_key_image_helper(
      const account_keys& ack
    , const crypto::public_key & tx_public_key
    , size_t real_output_index
    , keypair & in_ephemeral
    , crypto::key_image & ki
    )
  {
    crypto::key_derivation recv_derivation {};
    bool r = crypto::generate_key_derivation(
        tx_public_key
      , ack.m_view_secret_key
      , recv_derivation
      );
    CHECK_AND_ASSERT_MES(r, false
      , "key image helper: failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")"
      );

    r = crypto::derive_public_key(
        recv_derivation
      , real_output_index
      , ack.m_account_address.m_spend_public_key
      , in_ephemeral.pub
      );
    CHECK_AND_ASSERT_MES(r, false
      , "key image helper: failed to derive_public_key("
        << recv_derivation << ", " << real_output_index << ", " << ack.m_account_address.m_spend_public_key << ")"
      );

    crypto::derive_secret_key(
        recv_derivation
      , real_output_index
      , ack.m_spend_secret_key
      , in_ephemeral.sec
      );

    crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, ki);
    return true;
  }
  //---------------------------------------------------------------
  uint64_t power_integral(uint64_t a, uint64_t b)
  {
    if(b == 0)
      return 1;
    uint64_t total = a;
    for(uint64_t i = 1; i != b; i++)
      total *= a;
    return total;
  }
  //---------------------------------------------------------------
  bool parse_amount(uint64_t& amount, const std::string& str_amount_)
  {
    std::string str_amount = str_amount_;
    boost::algorithm::trim(str_amount);

    size_t point_index = str_amount.find_first_of('.');
    size_t fraction_size;
    if (std::string::npos != point_index)
    {
      fraction_size = str_amount.size() - point_index - 1;
      while (CRYPTONOTE_DISPLAY_DECIMAL_POINT < fraction_size && '0' == str_amount.back())
      {
        str_amount.erase(str_amount.size() - 1, 1);
        --fraction_size;
      }
      if (CRYPTONOTE_DISPLAY_DECIMAL_POINT < fraction_size)
        return false;
      str_amount.erase(point_index, 1);
    }
    else
    {
      fraction_size = 0;
    }

    if (str_amount.empty())
      return false;

    if (fraction_size < CRYPTONOTE_DISPLAY_DECIMAL_POINT)
    {
      str_amount.append(CRYPTONOTE_DISPLAY_DECIMAL_POINT - fraction_size, '0');
    }

    return string_tools::get_xtype_from_string(amount, str_amount);
  }
  //---------------------------------------------------------------
  bool get_tx_fee(const transaction& tx, uint64_t & fee)
  {
    uint64_t amount_in = 0;
    uint64_t amount_out = 0;
    BOOST_FOREACH(auto& in, tx.vin)
    {
      CHECK_AND_ASSERT_MES(in.type() == typeid(txin_to_key), 0, "unexpected type id in transaction");
      amount_in += boost::get<txin_to_key>(in).amount;
    }
    BOOST_FOREACH(auto& o, tx.vout)
      amount_out += o.amount;

    CHECK_AND_ASSERT_MES(amount_in >= amount_out, false, "transaction spend (" <<amount_in << ") more than it has (" << amount_out << ")");
    fee = amount_in - amount_out;
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_tx_fee(const transaction& tx)
  {
    uint64_t r = 0;
    if(!get_tx_fee(tx, r))
      return 0;
    return r;
  }
  //---------------------------------------------------------------
  bool parse_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<tx_extra_field>& tx_extra_fields)
  {
    tx_extra_fields.clear();

    if(tx_extra.empty())
      return true;

    std::string extra_str(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size());
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      CHECK_AND_NO_ASSERT_MES(r, false, "failed to deserialize extra field. extra = " << string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size())));
      tx_extra_fields.push_back(field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    CHECK_AND_NO_ASSERT_MES(::serialization::check_stream_state(ar), false, "failed to deserialize extra field. extra = " << string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size())));

    return true;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
      return null_pkey;

    return pub_key_field.pub_key;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const transaction& tx)
  {
    return get_tx_pub_key_from_extra(tx.extra);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(transaction& tx, const crypto::public_key& tx_pub_key)
  {
    tx.extra.resize(tx.extra.size() + 1 + sizeof(crypto::public_key));
    tx.extra[tx.extra.size() - 1 - sizeof(crypto::public_key)] = TX_EXTRA_TAG_PUBKEY;
    *reinterpret_cast<crypto::public_key*>(&tx.extra[tx.extra.size() - sizeof(crypto::public_key)]) = tx_pub_key;
    return true;
  }
  //---------------------------------------------------------------
  bool add_extra_nonce_to_tx_extra(std::vector<uint8_t>& tx_extra, const blobdata& extra_nonce)
  {
    CHECK_AND_ASSERT_MES(extra_nonce.size() <= TX_EXTRA_NONCE_MAX_COUNT, false, "extra nonce could be 255 bytes max");
    size_t start_pos = tx_extra.size();
    tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
    //write tag
    tx_extra[start_pos] = TX_EXTRA_NONCE;
    //write len
    ++start_pos;
    tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
    //write data
    ++start_pos;
    memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
    return true;
  }
  //---------------------------------------------------------------
  void set_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash& payment_id)
  {
    extra_nonce.clear();
    extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
    const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
    std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
  }
  //---------------------------------------------------------------
  bool get_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash& payment_id)
  {
    if(sizeof(crypto::hash) + 1 != extra_nonce.size())
      return false;
    if(TX_EXTRA_NONCE_PAYMENT_ID != extra_nonce[0])
      return false;
    payment_id = *reinterpret_cast<const crypto::hash*>(extra_nonce.data() + 1);
    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx(
      const account_keys & sender_account_keys
    , const std::vector<tx_source_entry> & input_transfers
    , std::vector<tx_destination_entry> output_transfers
    , std::vector<uint8_t> extra
    , transaction & tx
    , uint64_t unlock_time
    )
  {
    tx.vin.clear();
    tx.vout.clear();
    tx.signatures.clear();

    tx.version = CURRENT_TRANSACTION_VERSION;
    tx.unlock_time = unlock_time;

    // Add a random public key to identify this transaction
    tx.extra = std::move(extra);
    keypair txkey = keypair::generate();
    add_tx_pub_key_to_extra(tx, txkey.pub);

    std::vector<keypair> one_time_key_pairs;

    // Create and add the txin_to_key inputs to the transaction.
    uint64_t total_money_from_inputs = 0;
    for (const tx_source_entry & input_transfer : input_transfers)
    {
      // The input transfer contains a field denoting which of its outputs is
      // the real one.  (The real one should correspond with this account.)
      // Check that it points to a valid output.
      if (input_transfer.real_output >= input_transfer.outputs.size())
      {
        LOG_ERROR("real_output index (" << input_transfer.real_output
          << ")bigger than output_keys.size()=" << input_transfer.outputs.size());
        return false;
      }

      total_money_from_inputs += input_transfer.amount;

      // Generate the key image and derive the one-time key
      one_time_key_pairs.push_back(keypair {});
      keypair & one_time_key = one_time_key_pairs.back();
      crypto::key_image img;
      if (!generate_key_image_helper(
          sender_account_keys
        , input_transfer.real_out_tx_key
        , input_transfer.real_output_in_tx_index
        , one_time_key
        , img
        ))
      {
        return false;
      }

      // Check that the one-time key we've derived has the same public key as
      // the real output of the input transfer (the one corresponding with this
      // account)
      if( !(one_time_key.pub == input_transfer.outputs[input_transfer.real_output].second) )
      {
        LOG_ERROR("derived public key missmatch with output public key! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(one_time_key.pub) << ENDL << "real output_public_key:"
          << string_tools::pod_to_hex(input_transfer.outputs[input_transfer.real_output].second) );
        return false;
      }

      // Construct the transaction input
      txin_to_key transaction_input;
      transaction_input.amount = input_transfer.amount;
      transaction_input.k_image = img;

      // Store the global index of each output
      for (auto const & out_entry : input_transfer.outputs)
      {
        transaction_input.key_offsets.push_back(out_entry.first);
      }

      // Convert the global indices to relative indices
      transaction_input.key_offsets = absolute_output_offsets_to_relative(transaction_input.key_offsets);

      // Add the input to the transaction
      tx.vin.push_back(transaction_input);
    }

    // Sort the output transfers by amount
    std::sort(
        output_transfers.begin()
      , output_transfers.end()
      , [](const tx_destination_entry & de1, const tx_destination_entry & de2)
        {
          return de1.amount < de2.amount;
        }
      );

    // Create and add the tx_out outputs to the transaction.
    uint64_t total_money_from_outputs = 0;
    size_t output_index = 0;
    for (const tx_destination_entry & output_transfer : output_transfers)
    {
      if (output_transfer.amount <= 0)
      {
        LOG_ERROR("Destination with wrong amount: " << output_transfer.amount);
        return false;
      }

      // Generate the one-time public key for this output
      crypto::public_key one_time_public_key;
      {
        crypto::key_derivation derivation;
        if (!crypto::generate_key_derivation(
            output_transfer.addr.m_view_public_key
          , txkey.sec
          , derivation
          ))
        {
          LOG_ERROR(
            "at creation outs: failed to generate_key_derivation("
            << output_transfer.addr.m_view_public_key << ", " << txkey.sec << ")"
          );
          return false;
        }

        if (!crypto::derive_public_key(
            derivation
          , output_index
          , output_transfer.addr.m_spend_public_key
          , one_time_public_key
          ))
        {
          LOG_ERROR(
            "at creation outs: failed to derive_public_key(" << derivation << ", "
            << output_index << ", "<< output_transfer.addr.m_spend_public_key << ")"
          );
          return false;
        }
      }

      // Construct the tx_out output and add it to the transaction
      tx_out out;
      {
        out.amount = output_transfer.amount;
        txout_to_key tk;
        tk.key = one_time_public_key;
        out.target = tk;
      }
      tx.vout.push_back(out);

      output_index++;

      total_money_from_outputs += output_transfer.amount;
    }

    // Make sure the output amounts don't sum to more than the input amounts.
    // (Otherwise the transaction would be creating money.)
    if (total_money_from_outputs > total_money_from_inputs)
    {
      LOG_ERROR("Transaction inputs money ("<< total_money_from_inputs
        << ") less than outputs money (" << total_money_from_outputs << ")");
      return false;
    }

    // Create a hash of the internal structure of the transaction.  (This is
    // everything but the signatures.)
    crypto::hash transaction_hash;
    get_transaction_prefix_hash(tx, transaction_hash);

    // Append a ring signature to the transaction for each input transfer
    std::stringstream ring_signatures_log;
    size_t i = 0;
    for (const tx_source_entry & input_transfer : input_transfers)
    {
      ring_signatures_log << "public keys:" << ENDL;

      // Create a view containing the public keys in this input transfer
      std::vector<const crypto::public_key *> public_keys;
      for (const tx_source_entry::output_entry & o : input_transfer.outputs)
      {
        public_keys.push_back(&o.second);
        ring_signatures_log << o.second << ENDL;
      }

      // Add an empty ring signature to the transaction suffix whose size is
      // equal to the number of outputs for this input transfer
      tx.signatures.push_back(std::vector<crypto::signature> {});
      std::vector<crypto::signature> & ring_signature = tx.signatures.back();
      ring_signature.resize(input_transfer.outputs.size());

      // Populate the ring signature
      crypto::generate_ring_signature(
          transaction_hash
        , boost::get<txin_to_key>(tx.vin[i]).k_image
        , public_keys
        , one_time_key_pairs[i].sec
        , input_transfer.real_output
        , ring_signature.data()
        );

      ring_signatures_log << "signatures:" << ENDL;

      // Log the ring signature
      std::for_each(
          ring_signature.begin()
        , ring_signature.end()
        , [&](const crypto::signature & s) {ring_signatures_log << s << ENDL;}
        );

      // Log the other pertinent details
      ring_signatures_log
        << "transaction hash:" << transaction_hash << ENDL
        << "one-time key: " << one_time_key_pairs[i].sec << ENDL
        << "real output index: " << input_transfer.real_output;

      i++;
    }

    LOG_PRINT2(
        "construct_tx.log"
      , "transaction created: " << get_transaction_hash(tx) << ENDL
        << obj_to_json_str(tx) << ENDL
        << ring_signatures_log.str()
      , LOG_LEVEL_3
      );

    return true;
  }
  //---------------------------------------------------------------
  bool get_inputs_money_amount(const transaction& tx, uint64_t& money)
  {
    money = 0;
    BOOST_FOREACH(const auto& in, tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      money += tokey_in.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_block_height(const block& b)
  {
    CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, 0, "wrong miner tx in block: " << get_block_hash(b) << ", b.miner_tx.vin.size() != 1");
    CHECKED_GET_SPECIFIC_VARIANT(b.miner_tx.vin[0], const txin_gen, coinbase_in, 0);
    return coinbase_in.height;
  }
  //---------------------------------------------------------------
  bool check_inputs_types_supported(const transaction& tx)
  {
    BOOST_FOREACH(const auto& in, tx.vin)
    {
      CHECK_AND_ASSERT_MES(in.type() == typeid(txin_to_key), false, "wrong variant type: "
        << in.type().name() << ", expected " << typeid(txin_to_key).name()
        << ", in transaction id=" << get_transaction_hash(tx));

    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_outs_valid(const transaction& tx)
  {
    BOOST_FOREACH(const tx_out& out, tx.vout)
    {
      CHECK_AND_ASSERT_MES(out.target.type() == typeid(txout_to_key), false, "wrong variant type: "
        << out.target.type().name() << ", expected " << typeid(txout_to_key).name()
        << ", in transaction id=" << get_transaction_hash(tx));

      CHECK_AND_NO_ASSERT_MES(0 < out.amount, false, "zero amount ouput in transaction id=" << get_transaction_hash(tx));

      if(!check_key(boost::get<txout_to_key>(out.target).key))
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_money_overflow(const transaction& tx)
  {
    return check_inputs_overflow(tx) && check_outs_overflow(tx);
  }
  //---------------------------------------------------------------
  bool check_inputs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    BOOST_FOREACH(const auto& in, tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if(money > tokey_in.amount + money)
        return false;
      money += tokey_in.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  bool check_outs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    BOOST_FOREACH(const auto& o, tx.vout)
    {
      if(money > o.amount + money)
        return false;
      money += o.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_outs_money_amount(const transaction& tx)
  {
    uint64_t outputs_amount = 0;
    BOOST_FOREACH(const auto& o, tx.vout)
      outputs_amount += o.amount;
    return outputs_amount;
  }
  //---------------------------------------------------------------
  std::string short_hash_str(const crypto::hash& h)
  {
    std::string res = string_tools::pod_to_hex(h);
    CHECK_AND_ASSERT_MES(res.size() == 64, res, "wrong hash256 with string_tools::pod_to_hex conversion");
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
    return res;
  }
  //---------------------------------------------------------------
  bool is_out_to_acc(const account_keys& acc, const txout_to_key& out_key, const crypto::public_key& tx_pub_key, size_t output_index)
  {
    crypto::key_derivation derivation;
    generate_key_derivation(tx_pub_key, acc.m_view_secret_key, derivation);
    crypto::public_key pk;
    derive_public_key(derivation, output_index, acc.m_account_address.m_spend_public_key, pk);
    return pk == out_key.key;
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    if(null_pkey == tx_pub_key)
      return false;
    return lookup_acc_outs(acc, tx, tx_pub_key, outs, money_transfered);
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    money_transfered = 0;
    size_t i = 0;
    BOOST_FOREACH(const tx_out& o,  tx.vout)
    {
      CHECK_AND_ASSERT_MES(o.target.type() ==  typeid(txout_to_key), false, "wrong type id in transaction out" );
      if(is_out_to_acc(acc, boost::get<txout_to_key>(o.target), tx_pub_key, i))
      {
        outs.push_back(i);
        money_transfered += o.amount;
      }
      i++;
    }
    return true;
  }
  //---------------------------------------------------------------
  void get_blob_hash(const blobdata& blob, crypto::hash& res)
  {
    cn_fast_hash(blob.data(), blob.size(), res);
  }
  //---------------------------------------------------------------
  std::string print_money(uint64_t amount)
  {
    std::string s = std::to_string(amount);
    if(s.size() < CRYPTONOTE_DISPLAY_DECIMAL_POINT+1)
    {
      s.insert(0, CRYPTONOTE_DISPLAY_DECIMAL_POINT+1 - s.size(), '0');
    }
    s.insert(s.size() - CRYPTONOTE_DISPLAY_DECIMAL_POINT, ".");
    return s;
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata& blob)
  {
    crypto::hash h = null_hash;
    get_blob_hash(blob, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_hash(const transaction& t)
  {
    crypto::hash h = null_hash;
    size_t blob_size = 0;
    get_object_hash(t, h, blob_size);
    return h;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res)
  {
    size_t blob_size = 0;
    return get_object_hash(t, res, blob_size);
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t& blob_size)
  {
    return get_object_hash(t, res, blob_size);
  }
  //---------------------------------------------------------------
  blobdata get_block_hashing_blob(const block& b)
  {
    blobdata blob = t_serializable_object_to_blob(static_cast<block_header>(b));
    crypto::hash tree_root_hash = get_tx_tree_hash(b);
    blob.append(reinterpret_cast<const char*>(&tree_root_hash), sizeof(tree_root_hash));
    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));
    return blob;
  }
  //---------------------------------------------------------------
  bool get_block_hash(const block& b, crypto::hash& res)
  {
    return get_object_hash(get_block_hashing_blob(b), res);
  }
  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    crypto::hash p = null_hash;
    get_block_hash(b, p);
    return p;
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(
      block& bl
    , std::string const & genesis_tx
    , uint32_t nonce
    )
  {
    //genesis block
    bl = boost::value_initialized<block>();


    account_public_address ac = boost::value_initialized<account_public_address>();
    std::vector<size_t> sz;
    construct_miner_tx(0, 0, 0, 0, 0, ac, bl.miner_tx); // zero fee in genesis
    blobdata txb = tx_to_blob(bl.miner_tx);
    std::string hex_tx_represent = string_tools::buff_to_hex_nodelimer(txb);

    std::string genesis_coinbase_tx_hex = config::GENESIS_TX;

    blobdata tx_bl;
    string_tools::parse_hexstr_to_binbuff(genesis_coinbase_tx_hex, tx_bl);
    bool r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = nonce;
    miner::find_nonce_for_given_block(bl, 1, 0);
    return true;
  }
  //---------------------------------------------------------------
  bool get_block_longhash(const block& b, crypto::hash& res, uint64_t height)
  {
    block b_local = b; //workaround to avoid const errors with do_serialize
    blobdata bd = get_block_hashing_blob(b);
    crypto::cn_slow_hash(bd.data(), bd.size(), res);
    return true;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    for(size_t i = 1; i < res.size(); i++)
      res[i] += res[i-1];
    return res;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    if(!off.size())
      return res;
    std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
    for(size_t i = res.size()-1; i != 0; i--)
      res[i] -= res[i-1];

    return res;
  }
  //---------------------------------------------------------------
  crypto::hash get_block_longhash(const block& b, uint64_t height)
  {
    crypto::hash p = null_hash;
    get_block_longhash(b, p, height);
    return p;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata& b_blob, block& b)
  {
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, b);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse block from blob");
    return true;
  }
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  bool block_to_blob(const block& b, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(b, b_blob);
  }
  //---------------------------------------------------------------
  blobdata tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool tx_to_blob(const transaction& tx, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(tx, b_blob);
  }
  //---------------------------------------------------------------
  void get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes, crypto::hash& h)
  {
    tree_hash(tx_hashes.data(), tx_hashes.size(), h);
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes)
  {
    crypto::hash h = null_hash;
    get_tx_tree_hash(tx_hashes, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    std::vector<crypto::hash> txs_ids;
    crypto::hash h = null_hash;
    size_t bl_sz = 0;
    get_transaction_hash(b.miner_tx, h, bl_sz);
    txs_ids.push_back(h);
    BOOST_FOREACH(auto& th, b.tx_hashes)
      txs_ids.push_back(th);
    return get_tx_tree_hash(txs_ids);
  }
  //---------------------------------------------------------------
}
