#pragma once
#include <string>
#include <ctime>

enum class Protocol { TCP, UDP, HTTP, HTTPS, ICMP };

std::string protocolToString(Protocol p);
Protocol stringToProtocol(const std::string& s);

struct Packet {
    int         id;
    std::string srcIP;
    std::string destIP;
    int         port;
    Protocol    protocol;
    int         size;       // bytes
    time_t      timestamp;

    // Returns a unique signature for duplicate detection
    std::string signature() const;

    // Pretty-print one packet
    std::string toString() const;
};
