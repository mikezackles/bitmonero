#pragma once

#include "cryptonote_core/cryptonote_basic.h"

namespace tools
{

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

} // namespace tools
