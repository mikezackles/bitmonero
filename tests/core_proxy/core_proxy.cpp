// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// node.cpp : Defines the entry point for the console application.
//


#include "include_base_utils.h"
#include "version.h"

using namespace epee;

#include <iostream>
#include <sstream>
using namespace std;

#include <boost/program_options.hpp>

#include "common/command_line.h"
#include "console_handler.h"
#include "p2p/net_node.h"
//#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "core_proxy.h"
#include "version.h"

#if defined(WIN32)
#include <crtdbg.h>
#endif

namespace po = boost::program_options;
using namespace cryptonote;
using namespace crypto;


BOOST_CLASS_VERSION(nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<tests::proxy_core> >, 1);

int main(int argc, char* argv[])
{

#ifdef WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

  TRY_ENTRY();


  string_tools::set_module_name_and_folder(argv[0]);

  //set up logging options
  log_space::get_set_log_detalisation_level(true, LOG_LEVEL_2);
  //log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL);
  log_space::log_singletone::add_logger(LOGGER_FILE,
    log_space::log_singletone::get_default_log_file().c_str(),
    log_space::log_singletone::get_default_log_folder().c_str());


  po::options_description desc("Allowed options");
  // tools::get_default_data_dir() can't be called during static initialization
  command_line::add_arg(desc, command_line::arg_data_dir, tools::get_default_data_dir());
  nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<tests::proxy_core> >::init_options(desc);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  LOG_PRINT("Module folder: " << argv[0], LOG_LEVEL_0);
  LOG_PRINT("Node starting ...", LOG_LEVEL_0);


  //create objects and link them
  tests::proxy_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<tests::proxy_core> cprotocol(pr_core, NULL);
  nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<tests::proxy_core> > p2psrv(cprotocol);
  cprotocol.set_p2p_endpoint(&p2psrv);
  //pr_core.set_cryptonote_protocol(&cprotocol);
  //daemon_cmmands_handler dch(p2psrv);

  //initialize objects

  LOG_PRINT_L0("Initializing p2p server...");
  bool res = p2psrv.init(vm);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize p2p server.");
  LOG_PRINT_L0("P2p server initialized OK");

  LOG_PRINT_L0("Initializing cryptonote protocol...");
  res = cprotocol.init(vm);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize cryptonote protocol.");
  LOG_PRINT_L0("Cryptonote protocol initialized OK");

  //initialize core here
  LOG_PRINT_L0("Initializing proxy core...");
  res = pr_core.init(vm);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize core");
  LOG_PRINT_L0("Core initialized OK");

  LOG_PRINT_L0("Starting p2p net loop...");
  p2psrv.run();
  LOG_PRINT_L0("p2p net loop stopped");

  //deinitialize components
  LOG_PRINT_L0("Deinitializing core...");
  pr_core.deinit();
  LOG_PRINT_L0("Deinitializing cryptonote_protocol...");
  cprotocol.deinit();
  LOG_PRINT_L0("Deinitializing p2p...");
  p2psrv.deinit();


  //pr_core.set_cryptonote_protocol(NULL);
  cprotocol.set_p2p_endpoint(NULL);


  LOG_PRINT("Node stopped.", LOG_LEVEL_0);
  return 0;

  CATCH_ENTRY_L0("main", 1);
}

/*
string tx2str(const cryptonote::transaction& tx, const cryptonote::hash256& tx_hash, const cryptonote::hash256& tx_prefix_hash, const cryptonote::blobdata& blob) {
    stringstream ss;

    ss << "{" << endl;
    ss << "\tversion:" << tx.version << endl;
    ss << "\tunlock_time:" << tx.unlock_time << endl;
    ss << "\t"

    return ss.str();
}*/

bool tests::proxy_core::handle_incoming_tx(const cryptonote::blobdata& tx_blob, cryptonote::tx_verification_context& tvc, bool keeped_by_block) {
    if (!keeped_by_block)
        return true;

    crypto::hash tx_hash = null_hash;
    crypto::hash tx_prefix_hash = null_hash;
    transaction tx;

    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash, tx_prefix_hash)) {
        cerr << "WRONG TRANSACTION BLOB, Failed to parse, rejected" << endl;
        return false;
    }

    cout << "TX " << endl << endl;
    cout << tx_hash << endl;
    cout << tx_prefix_hash << endl;
    cout << tx_blob.size() << endl;
    //cout << string_tools::buff_to_hex_nodelimer(tx_blob) << endl << endl;
    cout << obj_to_json_str(tx) << endl;
    cout << endl << "ENDTX" << endl;

    return true;
}

bool tests::proxy_core::handle_incoming_block(const cryptonote::blobdata& block_blob, cryptonote::block_verification_context& bvc, bool update_miner_blocktemplate) {
    block b = AUTO_VAL_INIT(b);

    if(!parse_and_validate_block_from_blob(block_blob, b)) {
        cerr << "Failed to parse and validate new block" << endl;
        return false;
    }

    crypto::hash h;
    crypto::hash lh;
    cout << "BLOCK" << endl << endl;
    cout << (h = get_block_hash(b)) << endl;
    cout << (lh = get_block_longhash(m_cn_context, b, 0)) << endl;
    cout << get_transaction_hash(b.miner_tx) << endl;
    cout << ::get_object_blobsize(b.miner_tx) << endl;
    //cout << string_tools::buff_to_hex_nodelimer(block_blob) << endl;
    cout << obj_to_json_str(b) << endl;

    cout << endl << "ENDBLOCK" << endl << endl;

    if (!add_block(h, lh, b, block_blob))
        return false;

    return true;
}

bool tests::proxy_core::get_short_chain_history(std::list<crypto::hash>& ids) {
    build_short_history(ids, m_lastblk);
    return true;
}

bool tests::proxy_core::get_blockchain_top(uint64_t& height, crypto::hash& top_id) {
    height = 0;
    top_id = get_block_hash(m_genesis);
    return true;
}

bool tests::proxy_core::init(const boost::program_options::variables_map& /*vm*/) {
    generate_genesis_block(m_genesis);
    crypto::hash h = get_block_hash(m_genesis);
    add_block(h, get_block_longhash(m_cn_context, m_genesis, 0), m_genesis, block_to_blob(m_genesis));
    return true;
}

bool tests::proxy_core::have_block(const crypto::hash& id) {
    if (m_hash2blkidx.end() == m_hash2blkidx.find(id))
        return false;
    return true;
}

void tests::proxy_core::build_short_history(std::list<crypto::hash> &m_history, const crypto::hash &m_start) {
    m_history.push_front(get_block_hash(m_genesis));
    /*std::unordered_map<crypto::hash, tests::block_index>::const_iterator cit = m_hash2blkidx.find(m_lastblk);

    do {
        m_history.push_front(cit->first);

        size_t n = 1 << m_history.size();
        while (m_hash2blkidx.end() != cit && cryptonote::null_hash != cit->second.blk.prev_id && n > 0) {
            n--;
            cit = m_hash2blkidx.find(cit->second.blk.prev_id);
        }
    } while (m_hash2blkidx.end() != cit && get_block_hash(cit->second.blk) != cit->first);*/
}

bool tests::proxy_core::add_block(const crypto::hash &_id, const crypto::hash &_longhash, const cryptonote::block &_blk, const cryptonote::blobdata &_blob) {
    size_t height = 0;

    if (cryptonote::null_hash != _blk.prev_id) {
        std::unordered_map<crypto::hash, tests::block_index>::const_iterator cit = m_hash2blkidx.find(_blk.prev_id);
        if (m_hash2blkidx.end() == cit) {
            cerr << "ERROR: can't find previous block with id \"" << _blk.prev_id << "\"" << endl;
            return false;
        }

        height = cit->second.height + 1;
    }

    m_known_block_list.push_back(_id);

    block_index bi(height, _id, _longhash, _blk, _blob, txes);
    m_hash2blkidx.insert(std::make_pair(_id, bi));
    txes.clear();
    m_lastblk = _id;

    return true;
}
