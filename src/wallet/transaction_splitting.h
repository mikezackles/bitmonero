#pragma once

#include "cryptonote_core/cryptonote_format_utils.h"

#include <vector>

namespace transaction_splitting
{

typedef void (*strategy)(
    const std::vector<cryptonote::tx_destination_entry>& dsts
  , const cryptonote::tx_destination_entry& change_dst
  , uint64_t dust_threshold
  , std::vector<cryptonote::tx_destination_entry>& splitted_dsts
  , uint64_t& dust
  );

void digit_split_strategy(
    const std::vector<cryptonote::tx_destination_entry>& dsts
  , const cryptonote::tx_destination_entry& change_dst
  , uint64_t dust_threshold
  , std::vector<cryptonote::tx_destination_entry>& splitted_dsts
  , uint64_t& dust
  );

void null_split_strategy(
    const std::vector<cryptonote::tx_destination_entry>& dsts
  , const cryptonote::tx_destination_entry& change_dst
  , uint64_t dust_threshold
  , std::vector<cryptonote::tx_destination_entry>& splitted_dsts
  , uint64_t& dust
  );

// split_amounts(vector<cryptonote::tx_destination_entry> dsts, size_t num_splits)
//
// split amount for each dst in dsts into num_splits parts
// and make num_splits new vector<crypt...> instances to hold these new amounts
std::vector<std::vector<cryptonote::tx_destination_entry>> split_amounts(
    std::vector<cryptonote::tx_destination_entry> dsts
  , size_t num_splits
  );

} // namespace transaction_splitting
