#pragma once

#include "cryptonote_core/cryptonote_format_utils.h"
#include "wallet/transfer_container.h"

namespace tools {

struct pending_tx
{
  cryptonote::transaction tx;
  uint64_t dust, fee;
  cryptonote::tx_destination_entry change_dts;
  std::list<transfer_container::iterator> selected_transfers;
  std::string key_images;
};

} // namespace tools
