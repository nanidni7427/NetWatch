#include "Packet.h"
#include <sstream>
#include <iomanip>
#include <ctime>

std::string protocolToString(Protocol p) {
    switch (p) {
        case Protocol::TCP:   return "TCP";
        case Protocol::UDP:   return "UDP";
        case Protocol::HTTP:  return "HTTP";
        case Protocol::HTTPS: return "HTTPS";
        case Protocol::ICMP:  return "ICMP";
        default:              return "UNKNOWN";
    }
}

Protocol stringToProtocol(const std::string& s) {
    if (s == "TCP")   return Protocol::TCP;
    if (s == "UDP")   return Protocol::UDP;
    if (s == "HTTP")  return Protocol::HTTP;
    if (s == "HTTPS") return Protocol::HTTPS;
    return Protocol::ICMP;
}

std::string Packet::signature() const {
    return srcIP + "->" + destIP + ":" + std::to_string(port) + ":" + std::to_string(size);
}

std::string Packet::toString() const {
    std::ostringstream oss;
    // Format timestamp as HH:MM:SS
    struct tm* t = localtime(&timestamp);
    char timeBuf[16];
    strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", t);

    oss << "[" << timeBuf << "] "
        << "ID:" << std::setw(5) << id << "  "
        << "SRC:" << std::setw(15) << std::left << srcIP << "  "
        << "DST:" << std::setw(15) << std::left << destIP << "  "
        << "PORT:" << std::setw(6) << port
        << "PROTO:" << std::setw(6) << protocolToString(protocol)
        << "SIZE:" << size << "B";
    return oss.str();
}
