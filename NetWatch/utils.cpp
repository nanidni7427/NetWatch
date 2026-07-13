#include "utils.h"
#include <ctime>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <fstream>
#include <iostream>

// -----------------------------------------------------------------------
//  Logger
// -----------------------------------------------------------------------
Logger::Logger(const std::string& logPath) : path_(logPath) {
    file_.open(logPath, std::ios::app);
    if (!file_.is_open())
        std::cerr << "[WARN] Could not open log file: " << logPath << "\n";
    else
        logInfo("===== NetWatch Session Started =====");
}

Logger::~Logger() {
    if (file_.is_open()) {
        logInfo("===== NetWatch Session Ended =====");
        file_.close();
    }
}

std::string Logger::timestamp() const {
    time_t t = std::time(nullptr);
    struct tm* tm_info = localtime(&t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

void Logger::logPacket(const Packet& p) {
    if (!file_.is_open()) return;
    file_ << "[PKT] " << p.toString() << "\n";
    file_.flush();
}

void Logger::logAlert(const Alert& a) {
    if (!file_.is_open()) return;
    std::string level;
    switch (a.level) {
        case AlertLevel::INFO:     level = "INFO";     break;
        case AlertLevel::WARNING:  level = "WARNING";  break;
        case AlertLevel::CRITICAL: level = "CRITICAL"; break;
    }
    file_ << "[" << level << "] " << timestamp() << " " << a.message << "\n";
    file_.flush();
}

void Logger::logInfo(const std::string& msg) {
    if (!file_.is_open()) return;
    file_ << "[INFO] " << timestamp() << " " << msg << "\n";
    file_.flush();
}

// -----------------------------------------------------------------------
//  utils::ensureDir
// -----------------------------------------------------------------------
void utils::ensureDir(const std::string& path) {
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0755);
#endif
}

void utils::createDefaultSuspiciousIPs(const std::string& path) {
    // Only create if file doesn't already exist
    std::ifstream check(path);
    if (check.good()) return;
    check.close();

    std::ofstream f(path);
    if (!f.is_open()) return;
    f << "# NetWatch Suspicious IP Blacklist\n";
    f << "# One IP per line  (lines starting with # are comments)\n";
    f << "185.220.101.45\n";   // known Tor exit node range
    f << "45.142.212.100\n";   // known scanner
    f << "192.168.1.99\n";     // internal rogue device (demo)
    f << "10.0.0.254\n";       // internal rogue device (demo)
    f << "198.51.100.1\n";     // RFC-5737 test address (demo trigger)\n";
    f.close();
}
