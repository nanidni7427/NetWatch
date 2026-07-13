#pragma once
#include "Packet.h"
#include "TrafficAnalyzer.h"
#include <string>
#include <fstream>

// -----------------------------------------------------------------------
//  Logger  –  writes packets and alerts to logs/traffic_log.txt
// -----------------------------------------------------------------------
class Logger {
public:
    explicit Logger(const std::string& logPath);
    ~Logger();

    void logPacket(const Packet& p);
    void logAlert(const Alert& a);
    void logInfo(const std::string& msg);

private:
    std::ofstream file_;
    std::string   path_;

    std::string timestamp() const;
};

// -----------------------------------------------------------------------
//  Misc helpers
// -----------------------------------------------------------------------
namespace utils {
    // Ensure a directory exists (simple mkdir)
    void ensureDir(const std::string& path);

    // Create default suspicious_ips.txt if missing
    void createDefaultSuspiciousIPs(const std::string& path);
}
