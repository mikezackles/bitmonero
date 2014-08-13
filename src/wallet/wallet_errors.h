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

#include <stdexcept>
#include <string>

#define CUSTOM_ERROR(classname, error_message) \
  struct classname : public std::runtime_error \
  { \
    explicit classname( \
        std::string const & tag \
      , std::string const & extra_detail \
      ) \
      : std::runtime_error( \
            "[" + tag + "] " + error_message + " - " + extra_detail \
          ) \
    {} \
    \
    explicit classname( \
        std::string const & tag \
      ) \
      : std::runtime_error( \
            "[" + tag + "] " + error_message \
          ) \
    {} \
  };

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION_TAG __FILE__ " : " STRINGIZE(__LINE__)

namespace tools {
namespace error
{

CUSTOM_ERROR(unexpected_txin_type, "unexpected transaction type")
CUSTOM_ERROR(file_exists_error, "file already exists")
CUSTOM_ERROR(file_not_found_error, "file not found")
CUSTOM_ERROR(file_read_error, "couldn't read file")
CUSTOM_ERROR(file_save_error, "couldn't save file")
CUSTOM_ERROR(invalid_password, "invalid password")
CUSTOM_ERROR(block_parse_error, "couldn't parse block")
CUSTOM_ERROR(get_blocks_error, "daemon error fetching blocks")
CUSTOM_ERROR(daemon_error, "daemon error")
CUSTOM_ERROR(tx_parse_error, "couldn't parse transaction")
CUSTOM_ERROR(get_random_outs_error, "failed to get random outputs to mix")
CUSTOM_ERROR(not_enough_money, "not enough money")
CUSTOM_ERROR(not_enough_outs_to_mix, "not enough outputs for specified mixin count")
CUSTOM_ERROR(tx_not_constructed, "transaction not constructed")
CUSTOM_ERROR(tx_rejected, "transaction rejected")
CUSTOM_ERROR(tx_sum_overflow, "transaction sum overflow")
CUSTOM_ERROR(tx_too_big, "transaction too big")
CUSTOM_ERROR(zero_destination, "one of the destinations is zero")
CUSTOM_ERROR(daemon_busy, "daemon is busy")
CUSTOM_ERROR(no_connection_to_daemon, "couldn't connect to daemon")
CUSTOM_ERROR(mismatched_files, "wallet file doesn't match keys file")
CUSTOM_ERROR(internal_error, "internal wallet error")

} // namespace error
} // namespace tools
