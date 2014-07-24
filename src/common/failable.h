#pragma once

#include <stdexcept>
#include <typeinfo>
#include <type_traits>

namespace tools
{
  // TODO - support for more descriptive errors
  template <typename T>
  class t_failable
  {
  private:
    static const size_t t_data_size = sizeof(T) > sizeof(int) ? sizeof(T) : sizeof(int);
    static const size_t t_data_align = alignof(T) > alignof(int) ? alignof(T) : alignof(int);

    using t_data = typename std::aligned_storage<t_data_size, t_data_align>::type;

    bool m_success;
    t_data m_data;

  public:
    t_failable(T && result)
      : m_success{true}
    {
      new (&m_data) T{std::move(result)};
    }

    t_failable(int error_code)
      : m_success{false}
    {
      new (&m_data) int{error_code};
    }

    t_failable(t_failable && other)
      : m_success{other.m_success}
    {
      if (other.m_success)
      {
        new (&m_data) T{std::move(*reinterpret_cast<T*>(&other.m_data))};
      }
      else
      {
        new (&m_data) int{std::move(*reinterpret_cast<int*>(&other.m_data))};
      }
    }

    t_failable(t_failable const &) = delete;
    t_failable & operator=(t_failable const &) = delete;
    t_failable & operator=(t_failable &&) = delete;

    bool success()
    {
      return m_success;
    }

    int error_code()
    {
      if (!m_success)
      {
        return *reinterpret_cast<int*>(&m_data);
      }
      else
      {
        throw std::bad_cast{};
      }
    }

    T & result()
    {
      if (m_success)
      {
        return *reinterpret_cast<T*>(&m_data);
      }
      else
      {
        throw std::bad_cast{};
      }
    }
  };
}
