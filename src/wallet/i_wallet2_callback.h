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
    ) = 0;

  virtual void on_money_received(
      uint64_t height
    , const cryptonote::transaction& tx
    , size_t out_index
    ) = 0;

  virtual void on_money_spent(
      uint64_t height
    , const cryptonote::transaction& in_tx
    , size_t out_index
    , const cryptonote::transaction& spend_tx
    ) = 0;

  virtual void on_skip_transaction(
      uint64_t height
    , const cryptonote::transaction& tx
    ) = 0;

protected:
  ~i_wallet2_callback() {}
};

} // namespace tools
