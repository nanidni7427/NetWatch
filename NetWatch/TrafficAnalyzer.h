#pragma once
#include "Packet.h"
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <functional>

// -----------------------------------------------------------------------
//  Alert severity levels
// -----------------------------------------------------------------------
enum class AlertLevel { INFO, WARNING, CRITICAL };

struct Alert {
    AlertLevel  level;
    std::string message;
    time_t      timestamp;
};

// -----------------------------------------------------------------------
//  TrafficAnalyzer  – the heart of NetWatch
//
//  DSA concepts used:
//    • Queue           – packet buffer (FIFO processing)
//    • Sliding Window  – last-N-seconds packet counting per IP
//    • unordered_map   – IP → count, protocol → count
//    • unordered_set   – duplicate packet signature detection
//    • Sorting         – top-talker ranking
// -----------------------------------------------------------------------
class TrafficAnalyzer {
public:
    // windowSeconds : sliding-window size
    // spikeThreshold: packets/window to trigger spike alert
    // floodThreshold: packets/5s from one IP to trigger flood alert
    explicit TrafficAnalyzer(int windowSeconds  = 10,
                             int spikeThreshold = 50,
                             int floodThreshold = 30);

    // Feed one packet into the analyzer
    void ingest(const Packet& p);

    // Feed a burst of packets
    void ingestBurst(const std::vector<Packet>& packets);

    // Load blacklisted IPs from file
    void loadBlacklist(const std::string& filepath);

    // ---------- Stats accessors ----------
    long long totalPackets()   const { return totalPackets_; }
    int       activeIPCount()  const { return (int)ipPacketCount_.size(); }
    double    avgPacketSize()  const;
    int       packetsLastSec() const;

    // Returns copy of recent alerts (last 20)
    std::vector<Alert> recentAlerts() const;

    // Top N talkers: { ip, count }
    std::vector<std::pair<std::string,int>> topTalkers(int n = 5) const;

    // Protocol distribution: { proto_string, count }
    std::vector<std::pair<std::string,int>> protocolDistribution() const;

    // Drain the alert callback queue (used by Dashboard)
    void setAlertCallback(std::function<void(const Alert&)> cb) { alertCB_ = cb; }

private:
    // ----- configuration -----
    int windowSeconds_;
    int spikeThreshold_;
    int floodThreshold_;

    // ----- state -----
    long long totalPackets_;
    long long totalBytes_;

    // Sliding window: queue of (timestamp, srcIP)
    std::queue<std::pair<time_t, std::string>> windowQueue_;

    // IP packet counts inside current window
    std::unordered_map<std::string, int> windowIPCount_;

    // All-time IP packet count
    std::unordered_map<std::string, int> ipPacketCount_;

    // Protocol counts
    std::unordered_map<std::string, int> protoCount_;

    // Duplicate detection: set of signatures seen in last window
    std::unordered_set<std::string> seenSignatures_;

    // Blacklisted IPs
    std::unordered_set<std::string> blacklist_;

    // Short-window flood detection (5-second queue)
    std::queue<std::pair<time_t, std::string>> floodQueue_;
    std::unordered_map<std::string, int>       floodIPCount_;

    // Packets-per-second tracking
    std::queue<time_t> ppsQueue_;   // one entry per packet, last 2s

    // Recent alerts (circular buffer of 20)
    std::vector<Alert> alertBuffer_;

    std::function<void(const Alert&)> alertCB_;

    // ----- helpers -----
    void purgeOldEntries(time_t now);
    void raiseAlert(AlertLevel level, const std::string& msg);
};
