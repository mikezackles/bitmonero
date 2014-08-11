#include "wallet/transaction_splitting.h"

namespace transaction_splitting
{

void digit_split_strategy(
    const std::vector<cryptonote::tx_destination_entry>& dsts
  , const cryptonote::tx_destination_entry& change_dst
  , uint64_t dust_threshold
  , std::vector<cryptonote::tx_destination_entry>& splitted_dsts
  , uint64_t& dust
  )
{
  splitted_dsts.clear();
  dust = 0;

  BOOST_FOREACH(auto& de, dsts)
  {
    cryptonote::decompose_amount_into_digits(
        de.amount
      , dust_threshold
      , [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr)); }
      , [&](uint64_t a_dust) { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr)); }
      );
  }

  cryptonote::decompose_amount_into_digits(
      change_dst.amount
    , dust_threshold
    , [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr)); }
    , [&](uint64_t a_dust) { dust = a_dust; }
    );
}

void null_split_strategy(
    const std::vector<cryptonote::tx_destination_entry>& dsts
  , const cryptonote::tx_destination_entry& change_dst
  , uint64_t dust_threshold
  , std::vector<cryptonote::tx_destination_entry>& splitted_dsts
  , uint64_t& dust
  )
{
  splitted_dsts = dsts;

  dust = 0;
  //uint64_t change = change_dst.amount;
  if (0 < dust_threshold)
  {
    for (uint64_t order = 10; order <= 10 * dust_threshold; order *= 10)
    {
      uint64_t dust_candidate = change_dst.amount % order;
      uint64_t change_candidate = (change_dst.amount / order) * order;
      if (dust_candidate <= dust_threshold)
      {
        dust = dust_candidate;
        //change = change_candidate;
      }
      else
      {
        break;
      }
    }
  }
}

// split_amounts(vector<cryptonote::tx_destination_entry> dsts, size_t num_splits)
//
// split amount for each dst in dsts into num_splits parts
// and make num_splits new vector<crypt...> instances to hold these new amounts
std::vector<std::vector<cryptonote::tx_destination_entry>> split_amounts(
    std::vector<cryptonote::tx_destination_entry> dsts
  , size_t num_splits
  )
{
  std::vector<std::vector<cryptonote::tx_destination_entry>> retVal;

  if (num_splits <= 1)
  {
    retVal.push_back(dsts);
    return retVal;
  }

  // for each split required
  for (size_t i=0; i < num_splits; i++)
  {
    std::vector<cryptonote::tx_destination_entry> new_dsts;

    // for each destination
    for (size_t j=0; j < dsts.size(); j++)
    {
      cryptonote::tx_destination_entry de;
      uint64_t amount;

      amount = dsts[j].amount;
      amount = amount / num_splits;

      // if last split, add remainder
      if (i + 1 == num_splits)
      {
        amount += dsts[j].amount % num_splits;
      }

      de.addr = dsts[j].addr;
      de.amount = amount;

      new_dsts.push_back(de);
    }

    retVal.push_back(new_dsts);
  }

  return retVal;
}

}
