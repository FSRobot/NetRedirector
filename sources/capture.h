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

#define NTOHS(x) WinDivertHelperNtohs(x) // 端口
#define NTOHL(x) WinDivertHelperNtohl(x) // ip address
#define HTONS(x) WinDivertHelperHtons(x) // 端口
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
			this->m_from_port = HTONS(from_port);
			toAddr(to_address, this->m_to_address.data(), m_isIpv6);
			this->m_to_port = HTONS(to_port);
		}

		explicit RedirectInfo(
			const std::vector<UINT32>& from_address,
			UINT16 from_port,
			const std::vector<UINT32>& to_address,
			UINT16 to_port
		)
		{
			this->m_from_address = from_address;
			this->m_from_port = HTONS(from_port);
			this->m_to_address = to_address;
			this->m_to_port = HTONS(to_port);
			this->m_isIpv6 = from_address.size() > 1;
		}

		~RedirectInfo() = default;

		RedirectInfo(const RedirectInfo& info)
		{
			m_from_address = std::vector<UINT32>(info.m_from_address);
			m_from_port = info.m_from_port;
			m_to_address = std::vector<UINT32>(info.m_to_address);
			m_to_port = info.m_to_port;
			m_isIpv6 = info.m_isIpv6;
		}
		RedirectInfo& operator = (const RedirectInfo& info)
		{
			m_from_address = std::vector<UINT32>(info.m_from_address);
			m_from_port = info.m_from_port;
			m_to_address = std::vector<UINT32>(info.m_to_address);
			m_to_port = info.m_to_port;
			m_isIpv6 = info.m_isIpv6;
			return *this;
		}
		RedirectInfo(RedirectInfo&& info) noexcept
		{
			m_from_address = info.from_address();
			m_from_port = info.from_port();
			m_to_address = info.to_address();
			m_to_port = info.to_port();
			m_isIpv6 = info.isIpv6();
		}
		RedirectInfo& operator = (RedirectInfo&& info) noexcept
		{
			m_from_address = info.from_address();
			m_from_port = info.from_port();
			m_to_address = info.to_address();
			m_to_port = info.to_port();
			m_isIpv6 = info.isIpv6();
			return *this;
		}

		bool operator==(const RedirectInfo& info) const
		{
			return m_from_port == info.m_from_port &&
				m_from_port == info.m_from_port &&
				m_to_address == info.m_to_address &&
				m_to_port == info.m_to_port &&
				m_isIpv6 == info.m_isIpv6;
		}

		UINT16 from_port() const
		{
			return m_from_port;
		}
		std::vector<UINT32> from_address() const
		{
			return this->m_from_address;
		}
		std::string from_address_str() const
		{
			return toStr(this->m_from_address.data(), m_isIpv6);
		}

		UINT16 to_port() const
		{
			return m_to_port;
		}
		std::vector<UINT32> to_address() const
		{
			return m_to_address;
		}
		std::string to_address_str() const
		{
			return toStr(m_to_address.data(), m_isIpv6);
		}

		std::string get_from_str() const
		{
			auto ip_str = toStr(m_from_address.data(), m_isIpv6);
			return std::format("{}:{}", ip_str, HTONS(m_from_port));
		}
		std::string get_to_str() const
		{
			auto ip_str = toStr(m_to_address.data(), m_isIpv6);
			return std::format("{}:{}", ip_str, HTONS(m_to_port));
		}

		bool isValid() const
		{
			return m_from_port != m_to_port && m_from_address != m_to_address;
		}

		bool isIpv6() const
		{
			return m_isIpv6;
		}
	private:
		std::vector<UINT32> m_from_address = std::vector<UINT32>(4, 0);
		UINT16 m_from_port;
		std::vector<UINT32> m_to_address = std::vector<UINT32>(4, 0);
		UINT16 m_to_port;
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
		Capture()
		{
			std::lock_guard lock(mtx);
			handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
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
			m_thread = std::thread(&Capture::run, this);
			SPDLOG_INFO("start running...");
		}
		~Capture()
		{
			if (m_thread.joinable())
				m_thread.join();
			if (handle != INVALID_HANDLE_VALUE)
				WinDivertClose(handle);
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

		bool in(const std::string& addr, UINT16 port)
		{
			std::lock_guard lock(mtx);
			bool flag = std::ranges::any_of(list, [&](auto const& info)
				{
					return (info.from_address_str() == addr && port == info.from_port()) || (info.to_address_str() == addr && port == info.to_port());
				});
			return flag;
		}

		std::optional<std::reference_wrapper<RedirectInfo>> find(const std::string& addr, UINT16 port)
		{
			for (auto& i : list)
			{
				auto& info = i;
				if (info.from_address_str() == addr && port == info.from_port() || info.to_address_str() == addr && port == info.to_port())
				{
					return i;
				}
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
	private:
		void run()
		{
			SPDLOG_INFO("listening...");
			while (true)
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

				// 如果不是目标地址或重定向地址，原样转发
				bool is_dst = in(dst_str, tcp_header->DstPort);
				bool is_src = in(src_str, tcp_header->SrcPort);
				if (!is_dst && !is_src)
				{
					WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
					continue;
				}

				if (ip_header != nullptr)
				{
					// 如果是发往目标地址的请求，修改为重定向地址
					if (is_dst)
					{
						auto item = find(dst_str, tcp_header->DstPort);
						if (item->get().isValid()) {
							SPDLOG_INFO("@ dst>{}->{}", item->get().get_from_str(), item->get().get_to_str());
							ip_header->DstAddr = HTONL(item->get().to_address()[0]);
							tcp_header->DstPort = item->get().to_port();
							WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
							WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
							continue;
						}
					}
					if (is_src)
					{
						auto item = find(src_str, tcp_header->SrcPort);
						if (item->get().isValid()) {
							SPDLOG_INFO("@ src>{}->{}", item->get().get_to_str(), item->get().get_from_str());
							ip_header->SrcAddr = HTONL(item->get().from_address()[0]);
							tcp_header->SrcPort = item->get().from_port();
							WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
							WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
							continue;
						}
					}
				}
				if (ipv6_header != nullptr)
				{
					UINT32 new_addr[4];
					// 如果是发往目标地址的请求，修改为重定向地址
					if (is_dst)
					{
						auto item = find(dst_str, tcp_header->DstPort);
						SPDLOG_INFO("@ dst>{}->{}", item->get().get_from_str(), item->get().get_to_str());
						WinDivertHelperHtonIPv6Address(item->get().to_address().data(), new_addr);
						memcpy(ipv6_header->DstAddr, new_addr, sizeof(new_addr));
						tcp_header->DstPort = item->get().to_port();
						WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
						WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
						continue;
					}
					if (is_src)
					{
						auto item = find(src_str, tcp_header->SrcPort);
						SPDLOG_INFO("@ src>{}->{}", item->get().get_to_str(), item->get().get_from_str());
						WinDivertHelperHtonIPv6Address(item->get().from_address().data(), new_addr);
						memcpy(ipv6_header->SrcAddr, new_addr, sizeof(new_addr));
						tcp_header->SrcPort = item->get().from_port();
						WinDivertHelperCalcChecksums(packet, packet_len, &recv_addr, 0);
						WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
						continue;
					}
				}

				WinDivertSend(handle, packet, packet_len, nullptr, &recv_addr);
			}
			SPDLOG_INFO("quit listening...");
		}

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