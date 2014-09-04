#pragma once

#include "crypto/hash.h"
#include "string_tools.h"
#include <vector>

namespace cryptonote
{
  inline void fix_historical_anomalies(
      uint64_t height
    , std::vector<crypto::hash> & tx_hashes
    )
  {
    switch (height)
    {
    case 202612:
      // These transactions may have the wrong hash because of a historical bug
      // in tree_hash.  Here we explicitly use the correct hash.

      if (tx_hashes.size() != 515)
      {
        LOG_ERROR("Expected block at height 202612 to contain 515 tx hashes");
        return;
      }

      epee::string_tools::hex_to_pod(
          "d2d714c86291781bb86df24404754df7d9811025f659c34d3c67af3634b79da6"
        , tx_hashes[513]
        );
      epee::string_tools::hex_to_pod(
          "d59297784bfea414885d710918c1b91bce0568550cd1538311dd3f2c71edf570"
        , tx_hashes[514]
        );

      break;
    }
  }
}
