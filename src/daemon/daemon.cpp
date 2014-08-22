// Copyright (c) 2014, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "daemon/daemon.h"

#include "common/util.h"
#include "daemon/core.h"
#include "daemon/p2p.h"
#include "daemon/protocol.h"
#include "daemon/rpc.h"
#include "misc_log_ex.h"
#include "version.h"
#include <boost/program_options.hpp>
#include <functional>

namespace daemonize {

class t_internals {
private:
  t_protocol m_protocol;
  t_core m_core;
  t_p2p m_p2p;
  t_rpc m_rpc;

public:
  t_internals(
      boost::program_options::variables_map const & vm
    )
    : m_core{vm}
    , m_protocol{vm, m_core}
    , m_p2p{vm, m_protocol}
    , m_rpc{vm, m_core, m_p2p}
  {
    // Handle circular dependencies
    m_protocol.set_p2p_endpoint(m_p2p.get());
    m_core.set_protocol(m_protocol.get());
  }

  void run()
  {
    m_core.run();
    m_rpc.run();
    m_p2p.run();
  }

  void stop()
  {
    m_p2p.stop();
  }
};

void t_daemon::init_options(boost::program_options::options_description & option_spec)
{
  t_core::init_options(option_spec);
  t_p2p::init_options(option_spec);
  t_rpc::init_options(option_spec);
}

t_daemon::t_daemon(
    boost::program_options::variables_map const & vm
  )
  : mp_internals{new t_internals{vm}}
  , m_is_running{false}
{}

t_daemon::~t_daemon() = default;

// MSVC is brain-dead and can't default this...
t_daemon::t_daemon(t_daemon && other)
{
  if (this != &other)
  {
    mp_internals = std::move(other.mp_internals);
    other.mp_internals.reset(nullptr);
  }
}

// or this
t_daemon & t_daemon::operator=(t_daemon && other)
{
  if (this != &other)
  {
    mp_internals = std::move(other.mp_internals);
    other.mp_internals.reset(nullptr);
  }
  return *this;
}

bool t_daemon::run()
{
  // Install signal handler.  We don't want interrupts to block
  tools::signal_handler::install(std::bind(&daemonize::t_daemon::nonblocking_stop, this));

  {
    std::lock_guard<std::mutex> lock {m_mutex};
    if (nullptr == mp_internals)
    {
      // The contents of mp_internals have already been destructed, so we're
      // done!
      return false;
    }

    // Signal that the daemon is now running
    m_is_running = true;
  }

  try
  {
    mp_internals->run();
    LOG_PRINT("Node stopped.", LOG_LEVEL_0);
    return true;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Uncaught exception! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Uncaught exception!");
  }

  // Signal that the daemon has stopped
  {
    std::lock_guard<std::mutex> lock {m_mutex};
    m_is_running = false;

    // Ensure resources are cleaned up before we return.  We do this while
    // holding the lock in an attempt to reliably inform t_daemon::run that the
    // contents of mp_internals have been destructed in the case that
    // t_daemon::run somehow gets called again.
    mp_internals.reset(nullptr);
  }

  return false;
}

void t_daemon::nonblocking_stop()
{
  mp_internals->stop();
}

void t_daemon::blocking_stop()
{
  // Don't do anything if the daemon isn't running
  {
    std::lock_guard<std::mutex> lock {m_mutex};
    if (!m_is_running)
    {
      return;
    }
  }

  mp_internals->stop();

  // Wait for mp_internals to finish running and then destruct its contents.
  {
    std::unique_lock<std::mutex> lock {m_mutex};
    LOG_PRINT_L0("START");
    m_condition_variable.wait(lock, [this] { return !m_is_running; });
    LOG_PRINT_L0("FINISH");
  }
}

} // namespace daemonize
