#pragma once
#include "TrafficAnalyzer.h"
#include "Packet.h"
#include <deque>
#include <string>

// -----------------------------------------------------------------------
//  Dashboard  – renders the terminal UI
//
//  Uses ANSI escape codes for colors and cursor control.
//  No external dependencies needed.
// -----------------------------------------------------------------------
class Dashboard {
public:
    explicit Dashboard(TrafficAnalyzer& analyzer);

    // Call every tick to render the full dashboard
    void render(const Packet& lastPacket);

    // Add a packet to the live feed (keeps last N)
    void addToFeed(const Packet& p);

    // Increment tick counter (used for uptime display)
    void tick() { ++tickCount_; }

private:
    TrafficAnalyzer& analyzer_;
    std::deque<Packet> liveFeed_;   // last 8 packets shown in feed
    long long tickCount_;

    // ---------- rendering helpers ----------
    void printHeader()        const;
    void printStats()         const;
    void printTopTalkers()    const;
    void printProtoDist()     const;
    void printLiveFeed()      const;
    void printAlerts()        const;
    void printFooter()        const;

    std::string alertLevelStr(AlertLevel l) const;
    std::string alertColor(AlertLevel l)    const;
    std::string barChart(int value, int max, int width = 20) const;
};
