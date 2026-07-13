CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

SRCS = main.cpp Packet.cpp PacketGenerator.cpp TrafficAnalyzer.cpp Dashboard.cpp utils.cpp
TARGET = netwatch

all: dirs $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

dirs:
	@mkdir -p logs data

clean:
	rm -f $(TARGET)

.PHONY: all clean dirs
