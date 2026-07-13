#include "Dashboard.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <algorithm>

// -----------------------------------------------------------------------
//  ANSI colour helpers
// -----------------------------------------------------------------------
namespace Color {
    const char* RESET   = "\033[0m";
    const char* BOLD    = "\033[1m";
    const char* DIM     = "\033[2m";

    // Foreground
    const char* BLACK   = "\033[30m";
    const char* RED     = "\033[31m";
    const char* GREEN   = "\033[32m";
    const char* YELLOW  = "\033[33m";
    const char* BLUE    = "\033[34m";
    const char* MAGENTA = "\033[35m";
    const char* CYAN    = "\033[36m";
    const char* WHITE   = "\033[37m";

    // Bright
    const char* BRED    = "\033[91m";
    const char* BGREEN  = "\033[92m";
    const char* BYELLOW = "\033[93m";
    const char* BBLUE   = "\033[94m";
    const char* BCYAN   = "\033[96m";
    const char* BWHITE  = "\033[97m";

    // Background
    const char* BG_BLACK  = "\033[40m";
    const char* BG_RED    = "\033[41m";
    const char* BG_GREEN  = "\033[42m";
    const char* BG_BLUE   = "\033[44m";
    const char* BG_CYAN   = "\033[46m";
}

// Cursor: move to top-left
static void clearScreen() {
    std::cout << "\033[H\033[2J";
}

static std::string now_str() {
    time_t t = std::time(nullptr);
    struct tm* tm_info = localtime(&t);
    char buf[16];
    strftime(buf, sizeof(buf), "%H:%M:%S", tm_info);
    return buf;
}

// -----------------------------------------------------------------------
Dashboard::Dashboard(TrafficAnalyzer& analyzer)
    : analyzer_(analyzer), tickCount_(0)
{}

void Dashboard::addToFeed(const Packet& p) {
    liveFeed_.push_back(p);
    if (liveFeed_.size() > 8)
        liveFeed_.pop_front();
}

// -----------------------------------------------------------------------
void Dashboard::render(const Packet& lastPacket) {
    clearScreen();
    printHeader();
    printStats();
    printTopTalkers();
    printProtoDist();
    printLiveFeed();
    printAlerts();
    printFooter();
    std::cout << std::flush;
}

// -----------------------------------------------------------------------
void Dashboard::printHeader() const {
    std::cout << Color::BCYAN << Color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║          ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗  ║\n";
    std::cout << "║          ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝  ║\n";
    std::cout << "║          ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║        ║\n";
    std::cout << "║          ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║        ║\n";
    std::cout << "║          ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗   ║\n";
    std::cout << "║          ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝   ║\n";
    std::cout << "║" << Color::BYELLOW << "              Network Packet Monitoring Simulator  v1.0              " << Color::BCYAN << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << Color::RESET;

    // Time bar
    std::cout << Color::DIM << "  ⏰  " << Color::RESET
              << Color::BWHITE << now_str() << Color::RESET
              << Color::DIM << "   Tick #" << tickCount_
              << "   Press Ctrl+C to exit" << Color::RESET << "\n\n";
}

// -----------------------------------------------------------------------
void Dashboard::printStats() const {
    std::cout << Color::BOLD << Color::BBLUE
              << "┌─────────────────────── LIVE STATISTICS ───────────────────────────────┐\n"
              << Color::RESET;

    auto fmt = [](long long n) -> std::string {
        std::ostringstream oss;
        oss << std::setw(8) << n;
        return oss.str();
    };

    int pps = analyzer_.packetsLastSec();

    std::cout << "│  "
              << Color::BGREEN << "📦 Total Packets : " << Color::BWHITE << fmt(analyzer_.totalPackets()) << Color::RESET
              << "    "
              << Color::BCYAN  << "🖥  Active IPs    : " << Color::BWHITE << fmt(analyzer_.activeIPCount()) << Color::RESET
              << "  │\n";

    std::cout << "│  "
              << Color::BYELLOW << "⚡ Pkts / sec    : " << Color::BWHITE << fmt(pps)  << Color::RESET
              << "    "
              << Color::MAGENTA << "📊 Avg Pkt Size  : " << Color::BWHITE
              << std::fixed << std::setprecision(0) << std::setw(5) << analyzer_.avgPacketSize() << " B  " << Color::RESET
              << "  │\n";

    // Simple ASCII traffic bar
    std::cout << "│  " << Color::CYAN << "Traffic Level : [";
    int bar = std::min(pps / 2, 40);
    for (int i = 0; i < 40; ++i) {
        if (i < bar) std::cout << (i < 20 ? Color::BGREEN : (i < 30 ? Color::BYELLOW : Color::BRED)) << "█";
        else         std::cout << Color::DIM << "░";
    }
    std::cout << Color::CYAN << "]  " << Color::BWHITE << pps << " p/s" << Color::RESET << "   │\n";

    std::cout << Color::BBLUE
              << "└───────────────────────────────────────────────────────────────────────┘\n"
              << Color::RESET;
}

// -----------------------------------------------------------------------
void Dashboard::printTopTalkers() const {
    std::cout << "\n" << Color::BOLD << Color::BYELLOW
              << "  🔥 TOP TALKERS\n" << Color::RESET;

    auto talkers = analyzer_.topTalkers(5);
    if (talkers.empty()) {
        std::cout << "     " << Color::DIM << "(no data yet)\n" << Color::RESET;
        return;
    }
    int maxVal = talkers[0].second;
    int rank = 1;
    for (auto& [ip, cnt] : talkers) {
        std::string bar = barChart(cnt, maxVal, 22);
        std::cout << "  " << Color::BYELLOW << rank++ << ". "
                  << Color::BWHITE << std::setw(17) << std::left << ip
                  << Color::RESET << " " << bar
                  << Color::BCYAN << " " << std::setw(6) << cnt << " pkts\n" << Color::RESET;
    }
}

// -----------------------------------------------------------------------
void Dashboard::printProtoDist() const {
    std::cout << "\n" << Color::BOLD << Color::BCYAN
              << "  📡 PROTOCOL DISTRIBUTION\n" << Color::RESET;

    auto dist = analyzer_.protocolDistribution();
    if (dist.empty()) {
        std::cout << "     " << Color::DIM << "(no data yet)\n" << Color::RESET;
        return;
    }
    int total = 0;
    for (auto& [p, c] : dist) total += c;
    for (auto& [proto, cnt] : dist) {
        int pct = total ? (cnt * 100 / total) : 0;
        std::string bar = barChart(cnt, total, 18);
        std::cout << "  " << Color::BCYAN << std::setw(7) << std::left << proto
                  << Color::RESET << " " << bar
                  << Color::DIM << " " << std::setw(4) << cnt << " pkts  ("
                  << std::setw(3) << pct << "%)\n" << Color::RESET;
    }
}

// -----------------------------------------------------------------------
void Dashboard::printLiveFeed() const {
    std::cout << "\n" << Color::BOLD << Color::BGREEN
              << "  📥 LIVE PACKET FEED  (last 8 packets)\n" << Color::RESET;

    if (liveFeed_.empty()) {
        std::cout << "     " << Color::DIM << "(waiting for packets...)\n" << Color::RESET;
        return;
    }

    // Print newest first
    for (auto it = liveFeed_.rbegin(); it != liveFeed_.rend(); ++it) {
        const Packet& p = *it;

        // Color by protocol
        const char* protoColor = Color::BWHITE;
        switch (p.protocol) {
            case Protocol::TCP:   protoColor = Color::BGREEN;   break;
            case Protocol::UDP:   protoColor = Color::BYELLOW;  break;
            case Protocol::HTTP:  protoColor = Color::BCYAN;    break;
            case Protocol::HTTPS: protoColor = Color::BBLUE;    break;
            case Protocol::ICMP:  protoColor = Color::MAGENTA;  break;
        }

        struct tm* t = localtime(&p.timestamp);
        char timeBuf[10];
        strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", t);

        std::cout << "  "
                  << Color::DIM << "[" << timeBuf << "] " << Color::RESET
                  << Color::BWHITE << std::setw(15) << std::left << p.srcIP << Color::RESET
                  << Color::DIM << " → " << Color::RESET
                  << Color::BWHITE << std::setw(15) << std::left << p.destIP << Color::RESET
                  << Color::DIM << " :" << std::setw(6) << p.port << Color::RESET
                  << protoColor << std::setw(6) << protocolToString(p.protocol) << Color::RESET
                  << Color::DIM << std::setw(6) << p.size << "B\n" << Color::RESET;
    }
}

// -----------------------------------------------------------------------
void Dashboard::printAlerts() const {
    auto alerts = analyzer_.recentAlerts();
    if (alerts.empty()) return;

    std::cout << "\n" << Color::BOLD << Color::BRED
              << "  🚨 ALERTS  (most recent first)\n" << Color::RESET;

    // Show last 6
    int start = std::max(0, (int)alerts.size() - 6);
    for (int i = (int)alerts.size() - 1; i >= start; --i) {
        const Alert& a = alerts[i];
        struct tm* t = localtime(&a.timestamp);
        char timeBuf[10];
        strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", t);

        std::cout << "  " << Color::DIM << "[" << timeBuf << "] " << Color::RESET
                  << alertColor(a.level) << Color::BOLD << alertLevelStr(a.level) << Color::RESET
                  << "  " << a.message << "\n";
    }
}

// -----------------------------------------------------------------------
void Dashboard::printFooter() const {
    std::cout << "\n" << Color::DIM
              << "  ─────────────────────────────────────────────────────────────────────\n"
              << "  NetWatch v1.0  |  DSA: Sliding Window · Queue · HashMap · HashSet · Sort\n"
              << "  GitHub: github.com/yourusername/netwatch\n"
              << Color::RESET;
}

// -----------------------------------------------------------------------
std::string Dashboard::alertLevelStr(AlertLevel l) const {
    switch (l) {
        case AlertLevel::INFO:     return "[INFO]    ";
        case AlertLevel::WARNING:  return "[WARNING] ";
        case AlertLevel::CRITICAL: return "[CRITICAL]";
    }
    return "";
}

std::string Dashboard::alertColor(AlertLevel l) const {
    switch (l) {
        case AlertLevel::INFO:     return Color::BCYAN;
        case AlertLevel::WARNING:  return Color::BYELLOW;
        case AlertLevel::CRITICAL: return Color::BRED;
    }
    return Color::BWHITE;
}

std::string Dashboard::barChart(int value, int max, int width) const {
    if (max == 0) max = 1;
    int filled = (value * width) / max;
    std::string bar;
    bar += Color::BGREEN;
    for (int i = 0; i < width; ++i) {
        if (i < filled) bar += "█";
        else            bar += Color::DIM + std::string("░");
    }
    bar += Color::RESET;
    return bar;
}
