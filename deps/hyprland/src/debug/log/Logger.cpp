#include "Logger.hpp"
#include "RollingLogFollow.hpp"
#include <cstdlib>

#include "../../event/EventBus.hpp"

#include "../../config/ConfigValue.hpp"

using namespace Log;

CLogger::CLogger() {
    const auto IS_TRACE = Env::isTrace();
    m_logger.setLogLevel(IS_TRACE ? Hyprutils::CLI::LOG_TRACE : Hyprutils::CLI::LOG_DEBUG);
}

void CLogger::log(Hyprutils::CLI::eLogLevel level, const std::string_view& str) {

    static bool TRACE = Env::isTrace();

    if (!m_logsEnabled)
        return;

    // EpinAnonymOS: stdout logging is routed to the emulated serial UART, where
    // every line is a slow VM-exit to QEMU. Aquamarine emits per-frame TRACE/DEBUG
    // (scheduleFrame, G8 present, …) — thousands of lines/sec — which under KVM
    // made the compositor I/O-bound on serial writes and froze the whole desktop.
    // Past bring-up, drop TRACE and DEBUG and keep WARN and above (real problems
    // still surface; HOS_VERBOSE_LOG=1 restores everything for debugging).
    static const bool VERBOSE = TRACE || std::getenv("HOS_VERBOSE_LOG") != nullptr;
    if (!VERBOSE && (level == Hyprutils::CLI::LOG_TRACE || level == Hyprutils::CLI::LOG_DEBUG))
        return;

    if (SRollingLogFollow::get().isRunning())
        SRollingLogFollow::get().addLog(str);

    m_logger.log(level, str);
}

void CLogger::initIS(const std::string_view& IS) {
    // NOLINTNEXTLINE
    m_logger.setOutputFile(std::string{IS} + (ISDEBUG ? "/hyprlandd.log" : "/hyprland.log"));
    m_logger.setEnableRolling(true);
    m_logger.setEnableColor(false);
    m_logger.setEnableStdout(true);
    m_logger.setTime(false);
}

void CLogger::initCallbacks() {
    static auto P = Event::bus()->m_events.config.reloaded.listen([this]() { recheckCfg(); });
    recheckCfg();
}

void CLogger::recheckCfg() {
    static auto PDISABLELOGS  = CConfigValue<Config::INTEGER>("debug:disable_logs");
    static auto PDISABLETIME  = CConfigValue<Config::INTEGER>("debug:disable_time");
    static auto PENABLESTDOUT = CConfigValue<Config::INTEGER>("debug:enable_stdout_logs");
    static auto PENABLECOLOR  = CConfigValue<Config::INTEGER>("debug:colored_stdout_logs");

    // EpinAnonymOS: force stdout logging on for bring-up so renderer/EGL/dmabuf
    // messages reach the serial console (the lua debug.enable_stdout_logs config
    // isn't registering, and hyprland.log is buffered/invisible).
    m_logger.setEnableStdout(true);
    // EpinAnonymOS: also force m_logsEnabled on. CLogger::log() early-returns when
    // !m_logsEnabled (line ~19), which the config's debug:disable_logs flips false —
    // that suppressed ALL Hyprland-core logs after config load (renderer/EGL/assert
    // messages went only to the guest hyprland.log file, invisible on serial).
    m_logsEnabled = true; // was: !*PDISABLELOGS
    m_logger.setTime(!*PDISABLETIME);
    m_logger.setEnableColor(*PENABLECOLOR);
}

const std::string& CLogger::rolling() {
    return m_logger.rollingLog();
}

Hyprutils::CLI::CLogger& CLogger::hu() {
    return m_logger;
}
