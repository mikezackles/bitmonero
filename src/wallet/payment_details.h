#pragma once

namespace tools
{

struct payment_details
{
  crypto::hash m_tx_hash;
  uint64_t m_amount;
  uint64_t m_block_height;
  uint64_t m_unlock_time;
};

}
