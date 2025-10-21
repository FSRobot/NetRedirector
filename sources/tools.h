#pragma once
#ifdef CXX_DEBUG
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#else
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
#endif

#include "spdlog/spdlog.h"
#include "spdlog/async.h"
#include "spdlog/sinks/daily_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/callback_sink.h"

namespace Tools
{
	static void init_log()
	{
		spdlog::init_thread_pool(8192, 1);
		auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
		stdout_sink->set_level(static_cast<spdlog::level::level_enum>(SPDLOG_ACTIVE_LEVEL));
		auto file_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>("logs/log.txt", 0, 0);
		file_sink->set_level(static_cast<spdlog::level::level_enum>(SPDLOG_ACTIVE_LEVEL));
		auto callback_sink = std::make_shared<spdlog::sinks::callback_sink_mt>([](const spdlog::details::log_msg& msg)
			{
				std::string name(msg.logger_name.data(), 0, msg.logger_name.size());
				std::string str(msg.payload.data(), 0, msg.payload.size());
				std::time_t now_c = std::chrono::system_clock::to_time_t(msg.time);
				// TODO message callback
			});
		callback_sink->set_level(static_cast<spdlog::level::level_enum>(SPDLOG_ACTIVE_LEVEL));
		std::vector<spdlog::sink_ptr> sinks{ stdout_sink,file_sink,callback_sink };
		auto log = std::make_shared<spdlog::async_logger>
			("logger", sinks.begin(), sinks.end(), spdlog::thread_pool(), spdlog::async_overflow_policy::block);
		log->set_level(static_cast<spdlog::level::level_enum>(SPDLOG_ACTIVE_LEVEL));
		log->set_pattern("[%Y-%m-%d %H:%M:%S.%e] %^[%l]%$ [%t] [%s:%#] %v");
		log->flush_on(static_cast<spdlog::level::level_enum>(SPDLOG_ACTIVE_LEVEL));
		spdlog::flush_every(std::chrono::seconds(30));
		spdlog::set_default_logger(log);
	};
};