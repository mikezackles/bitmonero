#pragma once

namespace tools {

struct unconfirmed_transfer_details
{
  cryptonote::transaction m_tx;
  uint64_t m_change;
  time_t m_sent_time;
};

} // namespace tools
