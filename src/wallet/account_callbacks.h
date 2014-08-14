#pragma once

#include "cryptonote_core/cryptonote_basic.h"
#include <functional>

namespace tools
{

struct t_account_callbacks
{
  typedef std::function<void(
      uint64_t height
    , cryptonote::block const & block
    )> t_on_new_block_callback;

  typedef std::function<void(
      uint64_t height
    , cryptonote::transaction const & tx
    , size_t out_index
    )> t_on_money_received_callback;

  typedef std::function<void(
      uint64_t height
    , cryptonote::transaction const & in_tx
    , size_t out_index
    , cryptonote::transaction const & spend_tx
    )> t_on_money_spent_callback;

  typedef std::function<void(
      uint64_t height
    , cryptonote::transaction const & tx
    )> t_on_skip_transaction_callback;

  t_on_new_block_callback const on_new_block;
  t_on_money_received_callback const on_money_received;
  t_on_money_spent_callback const on_money_spent;
  t_on_skip_transaction_callback const on_skip_transaction;

  t_account_callbacks(
      t_on_new_block_callback on_new_block_callback = [](uint64_t, cryptonote::block const &) {}
    , t_on_money_received_callback on_money_received_callback = [](uint64_t, cryptonote::transaction const &, size_t) {}
    , t_on_money_spent_callback on_money_spent_callback = [](uint64_t, cryptonote::transaction const &, size_t, cryptonote::transaction const &) {}
    , t_on_skip_transaction_callback on_skip_transaction_callback = [](uint64_t, cryptonote::transaction const &) {}
    )
    : on_new_block {on_new_block_callback}
    , on_money_received {on_money_received_callback}
    , on_money_spent {on_money_spent_callback}
    , on_skip_transaction {on_skip_transaction_callback}
  {}
};

} // namespace tools
