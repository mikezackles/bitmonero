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

#include "cryptonote_core/account.h"
extern "C"
{
#include "crypto/keccak.h"
}
#include <ctime>

namespace cryptonote
{

recoverable_account create_recoverable_account()
{
  account_keys keys {};
  crypto::secret_key recovery_key {};

  recovery_key = generate_keys(
      keys.m_account_address.m_spend_public_key
    , keys.m_spend_secret_key
    );

  // rng for generating second set of keys is hash of first rng.  means only
  // one set of electrum-style words needed for recovery
  crypto::secret_key view_seed;
  keccak(
      (uint8_t *)&recovery_key, sizeof(crypto::secret_key)
    , (uint8_t *)&view_seed, sizeof(crypto::secret_key)
    );

  generate_keys_from_seed(
      keys.m_account_address.m_view_public_key
    , keys.m_view_secret_key
    , view_seed
    );

  return recoverable_account {
      core_account_data { std::move(keys), static_cast<uint64_t>(time(nullptr)) }
    , std::move(recovery_key)
  };
}

core_account_data create_unrecoverable_account()
{
  account_keys keys {};

  generate_keys(
      keys.m_account_address.m_spend_public_key
    , keys.m_spend_secret_key
    );

  generate_keys(
      keys.m_account_address.m_view_public_key
    , keys.m_view_secret_key
    );

  return core_account_data {
      std::move(keys)
    , static_cast<uint64_t>(time(nullptr))
  };
}

core_account_data recover_account(
    crypto::secret_key const & recovery_key
  )
{
  account_keys keys {};

  generate_keys_from_seed(
      keys.m_account_address.m_spend_public_key
    , keys.m_spend_secret_key
    , recovery_key
    );

  // rng for generating second set of keys is hash of first rng.  means only
  // one set of electrum-style words needed for recovery
  crypto::secret_key view_seed;
  keccak(
      (uint8_t *)&recovery_key, sizeof(crypto::secret_key)
    , (uint8_t *)&view_seed, sizeof(crypto::secret_key)
    );

  generate_keys_from_seed(
      keys.m_account_address.m_view_public_key
    , keys.m_view_secret_key
    , view_seed
    );

  // This allows the whole blockchain to be scanned for relevant transactions.
  struct tm timestamp;
  timestamp.tm_year = 2014 - 1900;  // year 2014
  timestamp.tm_mon = 6 - 1;  // month june
  timestamp.tm_mday = 8;  // 8th of june
  timestamp.tm_hour = 0;
  timestamp.tm_min = 0;
  timestamp.tm_sec = 0;

  return core_account_data {
      std::move(keys)
    , static_cast<uint64_t>(mktime(&timestamp))
  };
}

}
