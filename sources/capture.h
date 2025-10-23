#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "thirdparty/windivert/windivert.h"
#include <thread>
#include <mutex>
#include "tools.h"
#include <format>
#include <algorithm>
#include <ranges>
#include <set>
#include <atomic>

#define NTOHS(x) WinDivertHelperNtohs(x) 
#define NTOHL(x) WinDivertHelperNtohl(x) 
#define HTONS(x) WinDivertHelperHtons(x) 
#define HTONL(x) WinDivertHelperHtonl(x)
#define MAXBUFF  WINDIVERT_MTU_MAX
#define IPV6_LEN 45

namespace Capture
{
	inline std::string toStr(const UINT32* address, bool isIpv6)
	{
		std::string src_str;
		src_str.resize(IPV6_LEN + 1);

		if (isIpv6)
			WinDivertHelperFormatIPv6Address(address, src_str.data(), src_str.size());
		else
			WinDivertHelperFormatIPv4Address(*address, src_str.data(), src_str.size());

		src_str = std::string(src_str.c_str());
		return src_str;
	}
	inline BOOL toAddr(const std::string& address_str, UINT32* address, bool isIpv6)
	{
		if (isIpv6)
			return WinDivertHelperParseIPv6Address(address_str.data(), address);
		else
			return WinDivertHelperParseIPv4Address(address_str.data(), address);
	}

	class RedirectInfo
	{
	public:
		explicit RedirectInfo(
			const std::string& from_address,
			UINT16 from_port,
			const std::string& to_address,
			UINT16 to_port
		)
		{
			this->m_isIpv6 = from_address.find('.') == std::string::npos;
			toAddr(from_address, this->m_from_address.data(), m_isIpv6);
			toAddr(to_address, this->m_to_address.data(), m_isIpv6);
			m_send_port_map[HTONS(from_port)].push_back(HTONS(to_port));
			flush_recv_port();
		}

		explicit RedirectInfo(
			const std::vector<UINT32>& from_address,
			UINT16 from_port,
			const std::vector<UINT32>& to_address,
			UINT16 to_port
		)
		{
			this->m_from_address = from_address;
			this->m_to_address = to_address;
			this->m_isIpv6 = from_address.size() > 1;
			m_send_port_map[HTONS(from_port)].push_back(HTONS(to_port));
			flush_recv_port();
		}

		explicit RedirectInfo(
			const std::string& from_address,
			const std::string& to_address,
			const std::map<UINT16, std::vector<UINT16>>& map
		)
		{
			this->m_isIpv6 = from_address.find('.') == std::string::npos;
			toAddr(from_address, this->m_from_address.data(), m_isIpv6);
			toAddr(to_address, this->m_to_address.data(), m_isIpv6);
			for (auto& pair : map)
			{
				auto from_port = pair.first;
				for (auto to_port : pair.second)
				{
					m_send_port_map[HTONS(from_port)].push_back(HTONS(to_port));
				}
			}
			flush_recv_port();
		}

		~RedirectInfo() = default;

		RedirectInfo(const RedirectInfo& info)
		{
			m_from_address = std::vector(info.m_from_address);
			m_to_address = std::vector(info.m_to_address);
			m_send_port_map = std::map(info.m_send_port_map);
			m_recv_port_map = std::map(info.m_recv_port_map);
			m_isIpv6 = info.m_isIpv6;
		}
		RedirectInfo& operator = (const RedirectInfo& info)
		{
			m_from_address = std::vector<UINT32>(info.m_from_address);
			m_to_address = std::vector<UINT32>(info.m_to_address);
			m_send_port_map = std::map(info.m_send_port_map);
			m_recv_port_map = std::map(info.m_recv_port_map);
			m_isIpv6 = info.m_isIpv6;
			return *this;
		}
		RedirectInfo(RedirectInfo&& info) noexcept
		{
			m_from_address = info.from_address();
			m_to_address = info.to_address();
			m_send_port_map = std::map(info.m_send_port_map);
			m_recv_port_map = std::map(info.m_recv_port_map);
			m_isIpv6 = info.isIpv6();
		}
		RedirectInfo& operator = (RedirectInfo&& info) noexcept
		{
			m_from_address = info.from_address();
			m_to_address = info.to_address();
			m_send_port_map = std::map(info.m_send_port_map);
			m_recv_port_map = std::map(info.m_recv_port_map);
			m_isIpv6 = info.isIpv6();
			return *this;
		}

		bool operator==(const RedirectInfo& info) const
		{
			return m_to_address == info.m_to_address &&
				m_isIpv6 == info.m_isIpv6;
		}

		std::vector<UINT16> all_from_port() const
		{
			std::vector<UINT16> list;
			for (const auto& key : m_send_port_map | std::views::keys)
			{
				list.push_back(key);
			}
			return list;
		}
		std::optional<std::vector<UINT16>> from_port_list(UINT16 port) const
		{
			if (m_send_port_map.contains(port))
				return m_send_port_map.at(port);
			return std::nullopt;
		}
		std::vector<UINT32> from_address() const
		{
			return this->m_from_address;
		}
		std::string from_address_str() const
		{
			return toStr(this->m_from_address.data(), m_isIpv6);
		}

		std::vector<UINT16> all_to_port() const
		{
			std::vector<UINT16> list;
			for (const auto& key : m_recv_port_map | std::views::keys)
			{
				list.push_back(key);
			}
			return list;
		}
		std::optional<std::vector<UINT16>> to_port_list(UINT16 port) const
		{
			if (m_recv_port_map.contains(port))
				return m_recv_port_map.at(port);
			return std::nullopt;
		}
		std::vector<UINT32> to_address() const
		{
			return m_to_address;
		}
		std::string to_address_str() const
		{
			return toStr(m_to_address.data(), m_isIpv6);
		}

		bool isValid() const
		{
			return true;
		}

		bool isIpv6() const
		{
			return m_isIpv6;
		}
	private:

		void flush_recv_port()
		{
			std::set<UINT16> key_port;
			for (auto& pair : m_send_port_map)
			{
				auto from_port = pair.first;
				for (auto to_port : pair.second)
				{
					m_recv_port_map[to_port].push_back(from_port);
				}
			}
		}

		std::vector<UINT32> m_from_address = std::vector<UINT32>(4, 0);
		std::vector<UINT32> m_to_address = std::vector<UINT32>(4, 0);
		std::map<UINT16, std::vector<UINT16>> m_send_port_map;
		std::map<UINT16, std::vector<UINT16>> m_recv_port_map;
		bool m_isIpv6;
	};

	class Capture
	{
	public:
		enum class State :uint8_t
		{
			BlockAll,
			AllowAll,
			Redirector
		};
		Capture() = default;
		~Capture()
		{
			if (m_thread.joinable())
				m_thread.join();
			if (handle != INVALID_HANDLE_VALUE) {
				WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
				WinDivertClose(handle);
			}
		}

		State state() const
		{
			return m_state;
		}

		void setState(State state)
		{
			SPDLOG_INFO("[change state]@> [{}]->[{}]", static_cast<uint8_t>(m_state), static_cast<uint8_t>(state));
			m_state = state;
		}

		bool in(const std::string& addr, UINT16 port, bool is_from_port)
		{
			std::lock_guard lock(mtx);
			bool flag = std::ranges::any_of(list, [&](auto const& info)
				{
					if (is_from_port && info.from_address_str() != addr) return false;
					if (!is_from_port && info.to_address_str() != addr) return false;
					if (is_from_port && info.from_port_list(port) != std::nullopt) return true;
					if (!is_from_port && info.to_port_list(port) != std::nullopt) return true;
				});
			return flag;
		}

		std::optional<std::reference_wrapper<RedirectInfo>> find(const std::string& addr, UINT16 port, bool is_from_port)
		{
			for (auto& info : list)
			{
				if (is_from_port && info.from_address_str() != addr) continue;
				if (!is_from_port && info.to_address_str() != addr) continue;
				if (is_from_port && info.from_port_list(port) != std::nullopt) return info;
				if (!is_from_port && info.to_port_list(port) != std::nullopt) return info;
			}
			return std::nullopt;
		}

		void add(const RedirectInfo& info)
		{
			std::lock_guard lock(mtx);
			list.push_back(info);
		}
		void clear()
		{
			list.clear();
		}
		void remove(const RedirectInfo& info)
		{
			/*	std::lock_guard lock(mtx);
				std::ranges::find_first_of(list, [&](const RedirectInfo& item)
					{
						return info == item;
					});*/
		}
		std::string filter() const
		{
			std::string str = "tcp and (";
			bool f0 = false;
			for (const auto& info : list)
			{
				if (f0)
					str += " or ";
				str += std::format("(remoteAddr = {} and (", info.from_address_str());
				bool f1 = false;
				for (auto port : info.all_from_port())
				{
					if (f1)
						str += " or ";
					str += std::format("tcp.DstPort == {}", HTONS(port));
					f1 = true;
				}
				str += std::format(")) or (remoteAddr = {} and (", info.to_address_str());
				f1 = false;
				for (auto port : info.all_to_port())
				{
					if (f1)
						str += " or ";
					str += std::format("tcp.SrcPort == {}", HTONS(port));
					f1 = true;
				}
				str += "))";
				f0 = true;
			}
			str += ")";
			SPDLOG_INFO("filter str:{}", str);
			return str;
		}

		void start()
		{
			if (run_flag || list.empty()) return;
			run_flag = true;
			handle = WinDivertOpen(filter().c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
			if (handle == INVALID_HANDLE_VALUE)
			{
				if (GetLastError() == ERROR_INVALID_PARAMETER && !WinDivertHelperCompileFilter("true", WINDIVERT_LAYER_NETWORK, nullptr, 0, &err_str, nullptr))
				{
					SPDLOG_ERROR("error: invalid filter \"{}\"", err_str);
				}
				SPDLOG_ERROR("error: failed to open the WinDivert device ({})", GetLastError());
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
				exit(-1);
			}
			m_thread = std::thread(&Capture::loop, this);
			SPDLOG_INFO("start redirector");
		}
		void stop()
		{
			if (!run_flag) return;
			run_flag = false;
			if (handle != INVALID_HANDLE_VALUE)
			{
				WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
				WinDivertClose(handle);
			}
			if (m_thread.joinable())
			{
				m_thread.join();
			}
			SPDLOG_INFO("stop redirector");
		}
		std::atomic<bool>& isRunning()
		{
			return run_flag;
		}
	private:
		void loop()
		{
			while (run_flag)
			{
				if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len,
					&recv_addr))
				{
					SPDLOG_WARN("warning: failed to read packet");
					continue;
				}

				if (m_state == State::AllowAll)
				{
					WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
					continue;
				}
				if (m_state == State::BlockAll)
				{
					continue;
				}

				WinDivertHelperParsePacket(
					packet,
					packet_len,
					&ip_header,
					&ipv6_header,
					nullptr,
					nullptr,
					nullptr,
					&tcp_header,
					&udp_header,
					nullptr,
					nullptr,
					nullptr,
					nullptr
				);

				if ((ip_header == nullptr && ipv6_header == nullptr) || tcp_header == nullptr)
				{
					WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
					continue;
				}

				// Dump packet info: 
				if (ip_header != nullptr)
				{
					WinDivertHelperFormatIPv4Address(NTOHL(ip_header->SrcAddr),
						src_str, sizeof(src_str));
					WinDivertHelperFormatIPv4Address(NTOHL(ip_header->DstAddr),
						dst_str, sizeof(dst_str));
				}
				if (ipv6_header != nullptr)
				{
					WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, src_addr);
					WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dst_addr);
					WinDivertHelperFormatIPv6Address(src_addr, src_str,
						sizeof(src_str));
					WinDivertHelperFormatIPv6Address(dst_addr, dst_str,
						sizeof(dst_str));
				}


				bool is_dst = in(dst_str, tcp_header->DstPort, true);
				bool is_src = in(src_str, tcp_header->SrcPort, false);
				if (!is_dst && !is_src)
				{
					SPDLOG_INFO("DIRECTOR> {}->{}", src_str, dst_str);
					WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
					continue;
				}

				if (ip_header != nullptr)
				{
					if (is_dst)
					{
						auto item = find(dst_str, tcp_header->DstPort, true)->get();
						ip_header->DstAddr = HTONL(item.to_address()[0]);
						auto ports = *item.from_port_list(tcp_header->DstPort);
						for (auto& port : ports)
						{
							tcp_header->DstPort = port;
							WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
							WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
						}
						continue;
					}
					if (is_src)
					{
						auto item = find(src_str, tcp_header->SrcPort, false)->get();
						ip_header->SrcAddr = HTONL(item.from_address()[0]);
						auto ports = *item.to_port_list(tcp_header->SrcPort);
						for (auto& port : ports)
						{
							tcp_header->SrcPort = port;
							WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
							WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
						}
						continue;
					}
				}
				if (ipv6_header != nullptr)
				{
					UINT32 new_addr[4];
					if (is_dst)
					{
						auto item = find(dst_str, tcp_header->DstPort, true)->get();
						WinDivertHelperHtonIPv6Address(item.to_address().data(), new_addr);
						memcpy(ipv6_header->DstAddr, new_addr, sizeof(new_addr));
						auto ports = *item.from_port_list(tcp_header->DstPort);
						for (auto port : ports) {
							tcp_header->DstPort = port;
							WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
							WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
						}
						continue;
					}
					if (is_src)
					{
						auto item = find(src_str, tcp_header->SrcPort, false)->get();
						WinDivertHelperHtonIPv6Address(item.from_address().data(), new_addr);
						memcpy(ipv6_header->SrcAddr, new_addr, sizeof(new_addr));
						auto ports = *item.to_port_list(tcp_header->SrcPort);
						for (auto port : ports) {
							tcp_header->SrcPort = port;
							WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
							WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
						}
						continue;
					}
				}

				SPDLOG_WARN("something wrong");
				WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
			}
		}

		std::atomic<bool> run_flag{ false };
		const char* err_str;
		HANDLE handle = INVALID_HANDLE_VALUE;
		unsigned char packet[MAXBUFF];
		UINT packet_len;
		WINDIVERT_ADDRESS recv_addr;
		PWINDIVERT_IPHDR ip_header;
		PWINDIVERT_IPV6HDR ipv6_header;
		PWINDIVERT_TCPHDR tcp_header;
		PWINDIVERT_UDPHDR udp_header;
		UINT32 src_addr[4], dst_addr[4];
		char src_str[IPV6_LEN + 1], dst_str[IPV6_LEN + 1];
		std::vector<RedirectInfo> list;
		State m_state{ State::AllowAll };
		std::thread m_thread;
		std::mutex mtx;
	};
}