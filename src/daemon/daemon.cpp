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

#include "daemon/core.h"
#include "daemon/p2p.h"
#include "daemon/protocol.h"
#include "daemon/rpc.h"
#include "misc_log_ex.h"
#include "version.h"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>
#include <functional>
#include <thread>

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

  static void init_options(
      boost::program_options::options_description & option_spec
    )
  {
    t_core::init_options(option_spec);
    t_p2p::init_options(option_spec);
    t_rpc::init_options(option_spec);
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

void t_daemon::init_options(
    boost::program_options::options_description & option_spec
  )
{
  t_internals::init_options(option_spec);
}

t_daemon::t_daemon(
    boost::program_options::variables_map parsed_command_line
  )
  : mp_internals{nullptr}
  , m_parsed_command_line{std::move(parsed_command_line)}
  , m_is_running{false}
  , m_stop_has_been_called{false}
{}

t_daemon::~t_daemon() = default;

t_daemon::t_daemon(t_daemon && other)
{
  if (this != &other)
  {
    mp_internals = std::move(other.mp_internals);
    m_parsed_command_line = std::move(other.m_parsed_command_line);
    other.mp_internals.reset(nullptr);
  }
}

t_daemon & t_daemon::operator=(t_daemon && other)
{
  if (this != &other)
  {
    mp_internals = std::move(other.mp_internals);
    m_parsed_command_line = std::move(other.m_parsed_command_line);
    other.mp_internals.reset(nullptr);
  }
  return *this;
}

bool t_daemon::run()
{
  // Install signal handler.  This is unregistered after use, so a second
  // interrupt should terminate the process without waiting.
  std::thread {
    [this] {
      boost::asio::io_service io_service;
      boost::asio::signal_set signals {io_service, SIGINT, SIGTERM};
      signals.async_wait(std::bind(&t_daemon::nonblocking_stop, this));
      io_service.run();
    }
  }.detach();

  // Run the daemonized code
  bool success;
  try
  {
    // Initialize internals
    mp_internals.reset(new t_internals {m_parsed_command_line});

    // Signal that the daemon is now running
    {
      std::lock_guard<std::mutex> lock {m_mutex};
      m_is_running = true;
    }
    m_condition_variable.notify_one();

    mp_internals->run();
    LOG_PRINT("Node stopped.", LOG_LEVEL_0);
    success = true;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Uncaught exception! " << ex.what());
    success = false;
  }
  catch (...)
  {
    LOG_ERROR("Uncaught exception!");
    success = false;
  }

  // Ensure that the daemon is marked as running.  If there are stop methods
  // waiting for the daemon, this will prevent them from hanging.
  if (!success)
  {
    {
      std::lock_guard<std::mutex> lock {m_mutex};
      m_is_running = true;
    }
    m_condition_variable.notify_one();
  }

  // Ensure resources are cleaned up here.
  mp_internals.reset(nullptr);

  // Signal that the daemon has stopped
  {
    std::lock_guard<std::mutex> lock {m_mutex};
    m_is_running = false;
  }
  m_condition_variable.notify_one();

  return success;
}

bool t_daemon::nonblocking_stop()
{
  // Wait for the daemon to finish init, or abort if stop has already been
  // called
  {
    std::unique_lock<std::mutex> lock {m_mutex};
    if (m_stop_has_been_called)
    {
      return false;;
    }
    m_stop_has_been_called = true;
    m_condition_variable.wait(lock, [this] { return m_is_running; });
  }

  mp_internals->stop();

  return true;
}

bool t_daemon::blocking_stop()
{
  // Wait for daemon to stop if a stop method has not already been called
  if (nonblocking_stop())
  {
    std::unique_lock<std::mutex> lock {m_mutex};
    m_condition_variable.wait(lock, [this] { return !m_is_running; });
    return true;
  }
  else
  {
    return false;
  }
}

} // namespace daemonize
