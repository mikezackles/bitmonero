#pragma once

namespace tools
{

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

}
