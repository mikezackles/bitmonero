#pragma once

namespace tools {

struct unconfirmed_transfer_details
{
  cryptonote::transaction m_tx;
  uint64_t m_change;
  time_t m_sent_time;

  template <class Archive>
  inline void serialize(
      Archive & a
    , unsigned int const ver
    )
  {
    a & m_change;
    a & m_sent_time;
    a & m_tx;
  }
};

} // namespace tools
