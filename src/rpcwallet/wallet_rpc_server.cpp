// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "include_base_utils.h"
#include "wallet_rpc_server.h"
#include "wallet/wallet_errors.h"
#include "common/command_line.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_core/account.h"
#include "wallet_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "string_tools.h"
#include "crypto/hash.h"
#include "common/util.h"
#include "version.h"
#include <ctime>
#include <chrono>
#include <iostream>
#include <thread>

namespace tools
{
  //------------------------------------------------------------------------------------------------------------------------------
  wallet_rpc_server::wallet_rpc_server(
      std::string const & wallet_file
    , std::string const & wallet_password
    , std::string const & daemon_address
    , std::string bind_ip
    , std::string port
    )
    : m_wallet()
    , m_bind_ip(std::move(bind_ip))
    , m_port(std::move(port))
    , m_last_refresh(0)
  {
    LOG_PRINT_L0("Loading wallet...");
    m_wallet.load(wallet_file, wallet_password);
    m_wallet.init(daemon_address);
    LOG_PRINT_GREEN("Loaded ok", LOG_LEVEL_0);
    try
    {
      m_wallet.refresh();
    }
    catch(...)
    {
      LOG_PRINT_L0("Error refreshing wallet, possible lost connection to daemon.");
      throw;
    }
    m_net_server.set_threads_prefix("RPC");
    epee::http_server_impl_base<wallet_rpc_server, connection_context>::init(m_port, m_bind_ip);
  }
  //-------------------------------------------------------------------------------------------------------------------------------
  wallet_rpc_server::~wallet_rpc_server()
  {
    LOG_PRINT_L0("Stopped wallet rpc server");
    try
    {
      LOG_PRINT_L0("Storing wallet...");
      m_wallet.store();
      LOG_PRINT_GREEN("Stored ok", LOG_LEVEL_0);
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("Failed to store wallet: " << e.what());
    }
    catch (...)
    {
      LOG_ERROR("Failed to store wallet");
    }
  }
  //-------------------------------------------------------------------------------------------------------------------------------

  // check if the time since the last refresh is too long
  bool wallet_rpc_server::check_time(epee::json_rpc::error& er)
  {
    if (difftime(time(NULL), m_last_refresh) > STALE_WALLET_TIME)
    {
      // try to refresh just in case a daemon has been started in between auto-refresh
      try
      {
        m_wallet.refresh();
        m_last_refresh = time(NULL);
      }
      catch(...)
      {
        er.code = WALLET_RPC_ERROR_CODE_STALE_WALLET;
        er.message = "Too much time has passed since the last successful refresh.  The wallet may not be able to connect to a running daemon.";
        return false;
      }
    }
    return true;
  }

  bool wallet_rpc_server::run()
  {
    LOG_PRINT_L0("Starting wallet rpc server");
    m_net_server.add_idle_handler([this](){
      try
      {
        m_wallet.refresh();
        m_last_refresh = time(NULL); // if refresh successful, update last refresh time
      }
      catch(...)
      {
        LOG_PRINT_L0("Error refreshing wallet balance, possible lost connection to daemon.");
      }
      return true;
    }, 20000);

    //DO NOT START THIS SERVER IN MORE THEN 1 THREADS WITHOUT REFACTORING
    return epee::http_server_impl_base<wallet_rpc_server, connection_context>::run(1, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::stop()
  {
    m_wallet.store();
    wallet_rpc_server::send_stop_signal();
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getbalance(const wallet_rpc::COMMAND_RPC_GET_BALANCE::request& req, wallet_rpc::COMMAND_RPC_GET_BALANCE::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    try
    {
      res.balance = m_wallet.balance();
      res.unlocked_balance = m_wallet.unlocked_balance();
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getaddress(const wallet_rpc::COMMAND_RPC_GET_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_GET_ADDRESS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    try
    {
      res.address = m_wallet.get_account().get_public_address_str();
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::validate_transfer(const std::list<wallet_rpc::transfer_destination> destinations, const std::string payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, epee::json_rpc::error& er)
  {
    for (auto it = destinations.begin(); it != destinations.end(); it++)
    {
      cryptonote::tx_destination_entry de;
      if(!get_account_address_from_str(de.addr, it->address))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
        er.message = std::string("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: ") + it->address;
        return false;
      }
      de.amount = it->amount;
      dsts.push_back(de);
    }

    if (!payment_id.empty())
    {

      /* Just to clarify */
      const std::string& payment_id_str = payment_id;

      crypto::hash payment_id;
      /* Parse payment ID */
      if (!wallet2::parse_payment_id(payment_id_str, payment_id)) {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment id has invalid format: \"" + payment_id_str + "\", expected 64-character string";
        return false;
      }

      std::string extra_nonce;
      cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
      
      /* Append Payment ID data into extra */
      if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Something went wront with payment_id. Please check its format: \"" + payment_id_str + "\", expected 64-character string";
        return false;
      }

    }
    return true;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_transfer(const wallet_rpc::COMMAND_RPC_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_TRANSFER::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    // validate the transfer requested and populate dsts & extra
    if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, er))
    {
      return false;
    }

    try
    {
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet.create_transactions(dsts, req.mixin, req.unlock_time, req.fee, extra);

      // reject proposed transactions if there are more than one.  see on_transfer_split below.
      if (ptx_vector.size() != 1)
      {
        er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
        er.message = "Transaction would be too large.  try /transfer_split.";
        return false;
      }

      m_wallet.commit_tx(ptx_vector);

      // populate response with tx hash
      res.tx_hash = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(ptx_vector.back().tx));
      return true;
    }
    catch (const tools::error::daemon_busy& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
      er.message = e.what();
      return false;
    }
    catch (const std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = e.what();
      return false;
    }
    catch (...)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_transfer_split(const wallet_rpc::COMMAND_RPC_TRANSFER_SPLIT::request& req, wallet_rpc::COMMAND_RPC_TRANSFER_SPLIT::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    // validate the transfer requested and populate dsts & extra; RPC_TRANSFER::request and RPC_TRANSFER_SPLIT::request are identical types.
    if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, er))
    {
      return false;
    }

    try
    {
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet.create_transactions(dsts, req.mixin, req.unlock_time, req.fee, extra);

      m_wallet.commit_tx(ptx_vector);

      // populate response with tx hashes
      for (auto & ptx : ptx_vector)
      {
        res.tx_hash_list.push_back(boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(ptx.tx)));
      }

      return true;
    }
    catch (const tools::error::daemon_busy& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
      er.message = e.what();
      return false;
    }
    catch (const std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = e.what();
      return false;
    }
    catch (...)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_store(const wallet_rpc::COMMAND_RPC_STORE::request& req, wallet_rpc::COMMAND_RPC_STORE::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    try
    {
      m_wallet.store();
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_stop(const wallet_rpc::COMMAND_RPC_STOP::request& req, wallet_rpc::COMMAND_RPC_STOP::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // TODO - This avoids stopping the server before sending a response.  Note
    // that this is an ugly, ugly, no-good hack, and we should come up with
    // something better.
    m_wallet.store();
    std::thread thread{[this]() {
      std::chrono::milliseconds dur{200};
      std::this_thread::sleep_for(dur);
      wallet_rpc_server::send_stop_signal();
    }};
    thread.detach();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_payments(const wallet_rpc::COMMAND_RPC_GET_PAYMENTS::request& req, wallet_rpc::COMMAND_RPC_GET_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    crypto::hash payment_id;
    cryptonote::blobdata payment_id_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.payment_id, payment_id_blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
      er.message = "Payment ID has invald format";
      return false;
    }

    if(sizeof(payment_id) != payment_id_blob.size())
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
      er.message = "Payment ID has invalid size";
      return false;
    }

    payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());

    res.payments.clear();
    std::list<wallet2::payment_details> payment_list;
    m_wallet.get_payments(payment_id, payment_list);
    for (auto & payment : payment_list)
    {
      wallet_rpc::payment_details rpc_payment;
      rpc_payment.payment_id   = req.payment_id;
      rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
      rpc_payment.amount       = payment.m_amount;
      rpc_payment.block_height = payment.m_block_height;
      rpc_payment.unlock_time  = payment.m_unlock_time;
      res.payments.push_back(std::move(rpc_payment));
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_bulk_payments(const wallet_rpc::COMMAND_RPC_GET_BULK_PAYMENTS::request& req, wallet_rpc::COMMAND_RPC_GET_BULK_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    res.payments.clear();

    for (auto & payment_id_str : req.payment_ids)
    {
      crypto::hash payment_id;
      cryptonote::blobdata payment_id_blob;

      // TODO - should the whole thing fail because of one bad id?

      if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_blob))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment ID has invalid format: " + payment_id_str;
        return false;
      }

      if(sizeof(payment_id) != payment_id_blob.size())
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment ID has invalid size: " + payment_id_str;
        return false;
      }

      payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());

      std::list<wallet2::payment_details> payment_list;
      m_wallet.get_payments(payment_id, payment_list, req.min_block_height);

      for (auto & payment : payment_list)
      {
        wallet_rpc::payment_details rpc_payment;
        rpc_payment.payment_id   = payment_id_str;
        rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
        rpc_payment.amount       = payment.m_amount;
        rpc_payment.block_height = payment.m_block_height;
        rpc_payment.unlock_time  = payment.m_unlock_time;
        res.payments.push_back(std::move(rpc_payment));
      }
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_incoming_transfers(const wallet_rpc::COMMAND_RPC_INCOMING_TRANSFERS::request& req, wallet_rpc::COMMAND_RPC_INCOMING_TRANSFERS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    if(req.transfer_type.compare("all") != 0 && req.transfer_type.compare("available") != 0 && req.transfer_type.compare("unavailable") != 0)
    {
      er.code = WALLET_RPC_ERROR_CODE_TRANSFER_TYPE;
      er.message = "Transfer type must be one of: all, available, or unavailable";
      return false;
    }

    bool filter = false;
    bool available = false;
    if (req.transfer_type.compare("available") == 0)
    {
      filter = true;
      available = true;
    }
    else if (req.transfer_type.compare("unavailable") == 0)
    {
      filter = true;
      available = false;
    }

    wallet2::transfer_container transfers;
    m_wallet.get_transfers(transfers);

    bool transfers_found = false;
    for (const auto& td : transfers)
    {
      if (!filter || available != td.m_spent)
      {
        if (!transfers_found)
        {
          transfers_found = true;
        }
        wallet_rpc::transfer_details rpc_transfers;
        rpc_transfers.amount       = td.amount();
        rpc_transfers.spent        = td.m_spent;
        rpc_transfers.global_index = td.m_global_output_index;
        rpc_transfers.tx_hash      = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(td.m_tx));
        res.transfers.push_back(rpc_transfers);
      }
    }

    if (!transfers_found)
    {
      return false;
    }
  
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
}  // namespace tools
