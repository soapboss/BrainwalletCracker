CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O3 -pthread
LDFLAGS = -lcrypto -lssl -lscrypt -lyaml-cpp

TARGET = brainflayer_brainwalletio

.PHONY: all clean

all: $(TARGET)

$(TARGET): brainflayer_brainwalletio.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) 