> A real-time, terminal-based network traffic simulator and cybersecurity monitor written in modern C++17.  
> Built to showcase core **Data Structures & Algorithms** concepts in a practical, visually impressive project.

---


```
╔══════════════════════════════════════════════════════════════════════════╗
║          ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗  ║
║          ...         N  E  T  W  A  T  C  H                              ║
║              Network Packet Monitoring Simulator  v1.0              ║
╚══════════════════════════════════════════════════════════════════════════╝

  ⏰  14:23:05   Tick #42   Press Ctrl+C to exit

┌─────────────────────── LIVE STATISTICS ───────────────────────────────┐
│  📦 Total Packets :     1520    🖥  Active IPs    :       34          │
│  ⚡ Pkts / sec    :      210    📊 Avg Pkt Size  :  762 B             │
│  Traffic Level : [████████████████████░░░░░░░░░░░░░░░░░]  210 p/s   │
└───────────────────────────────────────────────────────────────────────┘

  🔥 TOP TALKERS
  1. 192.168.1.4      ██████████████████████  220 pkts
  2. 10.0.0.7         ████████████████░░░░░░  180 pkts

  🚨 ALERTS (most recent first)
  [14:23:04] [CRITICAL]  Blacklisted IP detected! SRC=185.220.101.45 -> DST=10.0.0.5
  [14:23:03] [WARNING]   Possible flood attack! IP=192.168.1.4  pkts/5s=14
  [14:23:02] [INFO]      Duplicate packet: 192.168.1.4->10.0.0.5:443:512
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 📦 Packet Simulation | Randomly generates TCP/UDP/HTTP/HTTPS/ICMP packets every tick |
| 📊 Live Dashboard | Real-time terminal UI with ANSI colors, bars, and stats |
| 🌊 Sliding Window | Monitors traffic per IP over configurable time windows |
| 🚨 Spike Detection | Alerts when any IP exceeds packet rate threshold |
| 💥 Flood Detection | DDoS-style attack detection using a 5-second window |
| 🔁 Duplicate Detection | Identifies replayed/duplicated packets via signature hashing |
| 🔴 Blacklist Checking | Flags packets from known-bad IPs instantly |
| 📝 Logging | Writes all packets, alerts, and events to `logs/traffic_log.txt` |
| 📡 Protocol Stats | Tracks TCP/UDP/HTTP/HTTPS/ICMP distribution in real time |
| 🏆 Top Talkers | Ranks most active source IPs with ASCII bar charts |

---

## 🧠 DSA Concepts Used

This project is intentionally designed to demonstrate core CS fundamentals:

| DSA Concept | Where Used | File |
|---|---|---|
| **Queue (FIFO)** | Packet processing buffer; sliding window queues | `TrafficAnalyzer.cpp` |
| **Sliding Window** | 10-second traffic monitoring + 5-second flood window | `TrafficAnalyzer.cpp` |
| **Hash Map** (`unordered_map`) | IP packet count, protocol frequency, window IP tracking | `TrafficAnalyzer.cpp` |
| **Hash Set** (`unordered_set`) | Duplicate packet detection; blacklist lookups | `TrafficAnalyzer.cpp` |
| **Sorting** | Top-talker ranking by packet count | `TrafficAnalyzer.cpp` |
| **String Hashing** | Packet signature generation for deduplication | `Packet.cpp` |
| **OOP / Modular Design** | Clean separation into Packet, Generator, Analyzer, Dashboard | All files |

### Sliding Window Detail

```
Time:    0  1  2  3  4  5  6  7  8  9  10  11
Packets: p  p  p  p  p  p  p  p  p  p   p   p
         └─────────── 10s window ──────────┘
                                         ↑ oldest entry evicted here
```

Each tick, entries older than the window are purged from the queue and their IP counts decremented — O(1) amortized per packet.

---

## 📁 Project Structure

```
NetWatch/
│
├── main.cpp              ← Entry point; simulation loop
├── Packet.h / .cpp       ← Packet struct, protocol enum, toString()
├── PacketGenerator.h/.cpp← Random packet factory; burst generation
├── TrafficAnalyzer.h/.cpp← DSA core: sliding windows, maps, sets, sorting
├── Dashboard.h / .cpp    ← ANSI terminal UI renderer
├── utils.h / .cpp        ← Logger class; filesystem helpers
├── Makefile              ← Build system
│
├── logs/
│   └── traffic_log.txt   ← Auto-generated session log
│
└── data/
    └── suspicious_ips.txt ← Blacklisted IP addresses
```

---

## ⚙️ Installation & Build

### Prerequisites

- A C++17-compatible compiler:
  - **Linux/macOS**: `g++` (GCC 7+) or `clang++`
  - **Windows**: MinGW-w64, MSYS2, or WSL

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/netwatch.git
cd netwatch

# Build with make
make

# Or compile manually
g++ -std=c++17 -O2 -o netwatch \
    main.cpp Packet.cpp PacketGenerator.cpp \
    TrafficAnalyzer.cpp Dashboard.cpp utils.cpp
```

### Run

```bash
./netwatch
```

Press `Ctrl+C` to stop. Logs are saved automatically to `logs/traffic_log.txt`.

---

## 🔧 Configuration

Edit thresholds directly in `main.cpp`:

```cpp
TrafficAnalyzer analyzer(
    /* windowSeconds  */ 10,   // sliding window size
    /* spikeThreshold */ 15,   // packets/window to trigger spike alert
    /* floodThreshold */ 12    // packets/5s from one IP to trigger flood alert
);
```

Add your own suspicious IPs to `data/suspicious_ips.txt`:

```
# Lines starting with # are comments
185.220.101.45
10.0.0.99
```

---

## 🗂️ Log Format

```
[INFO]  2025-01-15 14:23:00 ===== NetWatch Session Started =====
[PKT]   [14:23:01] ID:    1  SRC:192.168.1.4    DST:10.0.0.5    PORT:443  PROTO:TCP   SIZE:512B
[WARNING] 2025-01-15 14:23:03 Possible flood attack! IP=192.168.1.4  pkts/5s=14
[CRITICAL] 2025-01-15 14:23:04 Blacklisted IP detected! SRC=185.220.101.45 -> DST=10.0.0.5
[INFO]  2025-01-15 14:23:05 Duplicate packet: 192.168.1.4->10.0.0.5:443:512
```

---

## 🚀 Future Improvements

- [ ] **ncurses UI** — proper terminal window management with resizing
- [ ] **Multi-threading** — separate producer/consumer threads for packet generation
- [ ] **CSV export** — export analytics reports for spreadsheet analysis
- [ ] **Packet filtering** — filter live feed by IP, port, or protocol
- [ ] **Simulated firewall** — auto-block IPs that exceed flood threshold
- [ ] **Real-time ASCII graph** — rolling sparkline of packets/sec over time
- [ ] **Geo-IP lookup** — map IPs to country codes
- [ ] **PCAP replay** — load real `.pcap` files and analyze them

---

## 📄 Resume Description

> **NetWatch — Network Packet Monitoring Simulator** | C++17  
> Built a real-time terminal-based network monitoring tool simulating TCP/UDP/ICMP packet traffic.  
> Applied **sliding window**, **queue**, **hash map**, and **hash set** data structures to detect traffic spikes, packet floods, duplicate packets, and blacklisted IPs. Designed with modular OOP architecture (6 classes, 12 files) and a live ANSI dashboard refreshing at 2 Hz. Features include protocol distribution analytics, top-talker ranking via sorting, and persistent session logging.

---

## 🤝 Contributing

Pull requests welcome! Please open an issue first to discuss what you'd like to change.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

buidling along with learning c++ and DSA 
