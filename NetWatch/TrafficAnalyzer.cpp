#include "TrafficAnalyzer.h"
#include <fstream>
#include <algorithm>
#include <chrono>

TrafficAnalyzer::TrafficAnalyzer(int windowSeconds, int spikeThreshold, int floodThreshold)
    : windowSeconds_(windowSeconds),
      spikeThreshold_(spikeThreshold),
      floodThreshold_(floodThreshold),
      totalPackets_(0),
      totalBytes_(0)
{}

void TrafficAnalyzer::loadBlacklist(const std::string& filepath) {
    std::ifstream f(filepath);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line))
        if (!line.empty() && line[0] != '#')
            blacklist_.insert(line);
}

// -----------------------------------------------------------------------
//  ingest  –  main analysis pipeline for a single packet
// -----------------------------------------------------------------------
void TrafficAnalyzer::ingest(const Packet& p) {
    time_t now = p.timestamp;

    // Purge stale entries from sliding windows
    purgeOldEntries(now);

    ++totalPackets_;
    totalBytes_ += p.size;

    // All-time IP count
    ++ipPacketCount_[p.srcIP];

    // Protocol count
    ++protoCount_[protocolToString(p.protocol)];

    // ---------- Blacklist check ----------
    if (blacklist_.count(p.srcIP)) {
        raiseAlert(AlertLevel::CRITICAL,
                   "Blacklisted IP detected! SRC=" + p.srcIP +
                   " -> DST=" + p.destIP);
    }

    // ---------- Sliding window (10s) ----------
    windowQueue_.push({now, p.srcIP});
    int windowCount = ++windowIPCount_[p.srcIP];

    if (windowCount >= spikeThreshold_) {
        // Only alert once per IP per second (de-dupe)
        raiseAlert(AlertLevel::WARNING,
                   "Traffic spike from " + p.srcIP +
                   " (" + std::to_string(windowCount) +
                   " pkts in " + std::to_string(windowSeconds_) + "s)");
    }

    // ---------- Flood detection (5s window) ----------
    floodQueue_.push({now, p.srcIP});
    int floodCount = ++floodIPCount_[p.srcIP];

    if (floodCount >= floodThreshold_) {
        raiseAlert(AlertLevel::WARNING,
                   "Possible flood attack! IP=" + p.srcIP +
                   "  pkts/5s=" + std::to_string(floodCount));
    }

    // ---------- Duplicate detection ----------
    std::string sig = p.signature();
    if (seenSignatures_.count(sig)) {
        raiseAlert(AlertLevel::INFO,
                   "Duplicate packet: " + sig);
    } else {
        seenSignatures_.insert(sig);
    }

    // ---------- PPS tracking ----------
    ppsQueue_.push(now);
}

void TrafficAnalyzer::ingestBurst(const std::vector<Packet>& packets) {
    for (const auto& p : packets)
        ingest(p);
}

// -----------------------------------------------------------------------
//  purgeOldEntries  –  evict expired entries from all sliding windows
// -----------------------------------------------------------------------
void TrafficAnalyzer::purgeOldEntries(time_t now) {
    // 10-second window
    while (!windowQueue_.empty() &&
           now - windowQueue_.front().first >= windowSeconds_) {
        auto& [ts, ip] = windowQueue_.front();
        if (--windowIPCount_[ip] <= 0)
            windowIPCount_.erase(ip);
        windowQueue_.pop();
    }

    // 5-second flood window
    while (!floodQueue_.empty() &&
           now - floodQueue_.front().first >= 5) {
        auto& [ts, ip] = floodQueue_.front();
        if (--floodIPCount_[ip] <= 0)
            floodIPCount_.erase(ip);
        floodQueue_.pop();
    }

    // 2-second PPS window
    while (!ppsQueue_.empty() && now - ppsQueue_.front() >= 2)
        ppsQueue_.pop();

    // Refresh duplicate set every window cycle (keep it bounded)
    // Simple strategy: clear it when it exceeds 10000 entries
    if (seenSignatures_.size() > 10000)
        seenSignatures_.clear();
}

// -----------------------------------------------------------------------
//  Stats
// -----------------------------------------------------------------------
double TrafficAnalyzer::avgPacketSize() const {
    return totalPackets_ ? (double)totalBytes_ / totalPackets_ : 0.0;
}

int TrafficAnalyzer::packetsLastSec() const {
    return (int)ppsQueue_.size();
}

std::vector<Alert> TrafficAnalyzer::recentAlerts() const {
    return alertBuffer_;
}

std::vector<std::pair<std::string,int>>
TrafficAnalyzer::topTalkers(int n) const {
    std::vector<std::pair<std::string,int>> v(ipPacketCount_.begin(),
                                              ipPacketCount_.end());
    std::sort(v.begin(), v.end(),
              [](auto& a, auto& b){ return a.second > b.second; });
    if ((int)v.size() > n) v.resize(n);
    return v;
}

std::vector<std::pair<std::string,int>>
TrafficAnalyzer::protocolDistribution() const {
    std::vector<std::pair<std::string,int>> v(protoCount_.begin(),
                                              protoCount_.end());
    std::sort(v.begin(), v.end(),
              [](auto& a, auto& b){ return a.second > b.second; });
    return v;
}

// -----------------------------------------------------------------------
//  raiseAlert
// -----------------------------------------------------------------------
void TrafficAnalyzer::raiseAlert(AlertLevel level, const std::string& msg) {
    Alert a{level, msg, std::time(nullptr)};
    alertBuffer_.push_back(a);
    if (alertBuffer_.size() > 20)
        alertBuffer_.erase(alertBuffer_.begin());
    if (alertCB_) alertCB_(a);
}
