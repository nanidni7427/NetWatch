#pragma once
#include "Packet.h"
#include <vector>
#include <string>
#include <random>

class PacketGenerator {
public:
    PacketGenerator();

    // Generate a single random packet
    Packet generate();

    // Generate a burst of packets (for flood simulation)
    std::vector<Packet> generateBurst(int count, const std::string& forcedSrcIP = "");

    // Load suspicious IPs so generator can occasionally inject them
    void loadSuspiciousIPs(const std::string& filepath);

private:
    int nextID_;
    std::mt19937 rng_;

    std::vector<std::string> ipPool_;
    std::vector<std::string> suspiciousIPs_;
    std::vector<int>         commonPorts_;
    std::vector<Protocol>    protocols_;

    std::string randomIP();
    std::string randomSuspiciousIP();
    int         randomPort();
    Protocol    randomProtocol();
    int         randomSize();
};
