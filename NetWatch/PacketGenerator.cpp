#include "PacketGenerator.h"
#include <fstream>
#include <chrono>
#include <algorithm>

PacketGenerator::PacketGenerator()
    : nextID_(1),
      rng_(std::random_device{}())
{
    // Simulated internal IP pool
    ipPool_ = {
        "192.168.1.2",  "192.168.1.4",  "192.168.1.10",
        "192.168.1.20", "192.168.1.33", "10.0.0.5",
        "10.0.0.7",     "10.0.0.15",    "10.0.0.22",
        "172.16.0.3",   "172.16.0.9",   "172.16.0.17",
        "203.0.113.5",  "198.51.100.1", "198.51.100.42"
    };

    commonPorts_ = { 80, 443, 22, 21, 8080, 3306, 5432, 53, 25, 110, 143, 3389 };
    protocols_   = { Protocol::TCP, Protocol::UDP, Protocol::HTTP,
                     Protocol::HTTPS, Protocol::ICMP };
}

void PacketGenerator::loadSuspiciousIPs(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#')
            suspiciousIPs_.push_back(line);
    }
}

std::string PacketGenerator::randomIP() {
    std::uniform_int_distribution<int> dist(0, (int)ipPool_.size() - 1);
    return ipPool_[dist(rng_)];
}

std::string PacketGenerator::randomSuspiciousIP() {
    if (suspiciousIPs_.empty()) return randomIP();
    std::uniform_int_distribution<int> dist(0, (int)suspiciousIPs_.size() - 1);
    return suspiciousIPs_[dist(rng_)];
}

int PacketGenerator::randomPort() {
    std::uniform_int_distribution<int> dist(0, (int)commonPorts_.size() - 1);
    return commonPorts_[dist(rng_)];
}

Protocol PacketGenerator::randomProtocol() {
    std::uniform_int_distribution<int> dist(0, (int)protocols_.size() - 1);
    return protocols_[dist(rng_)];
}

int PacketGenerator::randomSize() {
    // Most packets 64–1500 bytes, occasionally jumbo
    std::uniform_int_distribution<int> dist(64, 1500);
    return dist(rng_);
}

Packet PacketGenerator::generate() {
    Packet p;
    p.id        = nextID_++;
    p.timestamp = std::time(nullptr);
    p.port      = randomPort();
    p.protocol  = randomProtocol();
    p.size      = randomSize();

    // 10% chance to inject a suspicious IP as source
    std::uniform_int_distribution<int> chance(1, 10);
    if (!suspiciousIPs_.empty() && chance(rng_) == 1)
        p.srcIP = randomSuspiciousIP();
    else
        p.srcIP = randomIP();

    p.destIP = randomIP();
    // Ensure src != dest
    while (p.destIP == p.srcIP)
        p.destIP = randomIP();

    return p;
}

std::vector<Packet> PacketGenerator::generateBurst(int count, const std::string& forcedSrcIP) {
    std::vector<Packet> burst;
    burst.reserve(count);
    for (int i = 0; i < count; ++i) {
        Packet p = generate();
        if (!forcedSrcIP.empty())
            p.srcIP = forcedSrcIP;
        burst.push_back(p);
    }
    return burst;
}
