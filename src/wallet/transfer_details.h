#pragma once

#include "cryptonote_core/cryptonote_basic.h"

namespace tools
{

struct transfer_details
{
  uint64_t m_block_height;
  cryptonote::transaction m_tx;
  size_t m_internal_output_index;
  uint64_t m_global_output_index;
  bool m_spent;
  crypto::key_image m_key_image; //TODO: key_image stored twice :(

  uint64_t amount() const
  {
    return m_tx.vout[m_internal_output_index].amount;
  }
};

}
