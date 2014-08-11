#pragma once

namespace transaction_splitting
{
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
} // namespace transaction_splitting
