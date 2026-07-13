// ============================================================
//  NetWatch – Network Packet Monitoring Simulator
//  main.cpp  –  Simulation loop and orchestration
//
//  DSA Concepts:
//    Queue          → PacketGenerator buffer + sliding windows
//    Sliding Window → TrafficAnalyzer (10s & 5s windows)
//    Hash Map       → IP frequency counts, protocol distribution
//    Hash Set       → Duplicate packet detection
//    Sorting        → Top-talker ranking
// ============================================================

#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <random>

#include "Packet.h"
#include "PacketGenerator.h"
#include "TrafficAnalyzer.h"
#include "Dashboard.h"
#include "utils.h"

// -----------------------------------------------------------------------
//  Global flag for clean shutdown on Ctrl+C
// -----------------------------------------------------------------------
std::atomic<bool> running(true);

void signalHandler(int) {
    running = false;
}

// -----------------------------------------------------------------------
//  main
// -----------------------------------------------------------------------
int main() {
    // Register Ctrl+C handler
    std::signal(SIGINT, signalHandler);

    // Ensure directories exist
    utils::ensureDir("logs");
    utils::ensureDir("data");
    utils::createDefaultSuspiciousIPs("data/suspicious_ips.txt");

    // --- Components ---
    PacketGenerator generator;
    generator.loadSuspiciousIPs("data/suspicious_ips.txt");

    TrafficAnalyzer analyzer(/*window=*/10, /*spike=*/15, /*flood=*/12);
    analyzer.loadBlacklist("data/suspicious_ips.txt");

    Dashboard dashboard(analyzer);

    Logger logger("logs/traffic_log.txt");

    // Wire up alert callback → logger
    analyzer.setAlertCallback([&](const Alert& a) {
        logger.logAlert(a);
    });

    // ----------------------------------------------------------------
    //  Random helpers for simulation variety
    // ----------------------------------------------------------------
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> pktCountDist(3, 8);   // normal: 3-8 pkts/tick
    std::uniform_int_distribution<int> burstChance(1, 20);   // 1-in-20 chance of burst
    std::uniform_int_distribution<int> burstSize(15, 25);    // burst size

    // IP pool for flood demo
    const std::vector<std::string> floodCandidates = {
        "192.168.1.4", "10.0.0.7", "172.16.0.3"
    };
    std::uniform_int_distribution<int> floodIP(0, (int)floodCandidates.size() - 1);

    int tickCount = 0;

    // ----------------------------------------------------------------
    //  Main simulation loop  (1 tick ≈ 500 ms)
    // ----------------------------------------------------------------
    while (running) {
        ++tickCount;

        // Normal traffic batch
        int normalCount = pktCountDist(rng);
        auto normalBatch = generator.generateBurst(normalCount);

        for (auto& p : normalBatch) {
            analyzer.ingest(p);
            dashboard.addToFeed(p);
            logger.logPacket(p);
        }

        // Occasionally simulate a flood burst from one IP
        if (burstChance(rng) == 1) {
            std::string attacker = floodCandidates[floodIP(rng)];
            auto burst = generator.generateBurst(burstSize(rng), attacker);
            for (auto& p : burst) {
                analyzer.ingest(p);
                dashboard.addToFeed(p);
                logger.logPacket(p);
            }
        }

        // Tick dashboard + render
        dashboard.tick();
        if (!normalBatch.empty())
            dashboard.render(normalBatch.back());

        // Sleep ~500ms between ticks
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // ----------------------------------------------------------------
    //  Shutdown
    // ----------------------------------------------------------------
    std::cout << "\n\033[0m\033[96m[NetWatch] Shutting down. Logs saved to logs/traffic_log.txt\033[0m\n";
    return 0;
}
