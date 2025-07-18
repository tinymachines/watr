# Makefile for WATR protocol test programs
# Complete version with all necessary flags

CC = gcc
CXX = g++
CFLAGS = -Wall -O2 -std=c11 -g
CXXFLAGS = -Wall -O2 -std=c++11 -g
LDFLAGS = -lpthread

# Add debugging symbols
DEBUG ?= 1
ifeq ($(DEBUG),1)
    CFLAGS += -DDEBUG -g3
    CXXFLAGS += -DDEBUG -g3
endif

# For OpenWRT cross-compilation
ifdef CROSS_COMPILE
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
endif

# Target platform optimizations
ifdef TARGET_ARCH
CFLAGS += -march=$(TARGET_ARCH)
CXXFLAGS += -march=$(TARGET_ARCH)
endif

# Programs
PROGRAMS = send-test receive-test wifi-monitor-check wifi-monitor-setup

# Source files
SEND_SRC = send-test.cpp
RECEIVE_SRC = receive-test.cpp
COMMON_SRC = watr_protocol.cpp
MONITOR_CHECK_SRC = wifi-monitor-check.c
MONITOR_SETUP_SRC = wifi-monitor-setup.c

# Object files
SEND_OBJ = $(SEND_SRC:.cpp=.o)
RECEIVE_OBJ = $(RECEIVE_SRC:.cpp=.o)
COMMON_OBJ = $(COMMON_SRC:.cpp=.o)
MONITOR_CHECK_OBJ = $(MONITOR_CHECK_SRC:.c=.o)
MONITOR_SETUP_OBJ = $(MONITOR_SETUP_SRC:.c=.o)

# Default target
all: $(PROGRAMS)

# Build rules
send-test: $(SEND_OBJ) $(COMMON_OBJ)
	$(CCX) $(CXXFLAGS) -o $@ $^ -I/usr/include/libnl3 $(pkg-config --libs libnl-3.0 libnl-genl-3.0)
	#$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

receive-test: $(RECEIVE_OBJ) $(COMMON_OBJ)
	$(CCX) $(CXXFLAGS) -o $@ $^ -I/usr/include/libnl3 $(pkg-config --libs libnl-3.0 libnl-genl-3.0)
	#$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

#wifi-monitor-check: $(MONITOR_CHECK_OBJ)
#	$(CC) $(CFLAGS) -o $@ $^ -I/usr/include/libnl3 $(pkg-config --libs libnl-3.0 libnl-genl-3.0)

#wifi-monitor-setup: $(MONITOR_SETUP_OBJ)
#	$(CC) $(CFLAGS) -o $@ $^ $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0)

# Generic rules
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Dependencies
$(SEND_OBJ) $(RECEIVE_OBJ) $(COMMON_OBJ): watr_protocol.h

# Test target
test: all
	@echo "Run these tests as root:"
	@echo "  sudo ./wifi-monitor-check"
	@echo "  sudo ./send-test mon0"
	@echo "  sudo ./receive-test mon0"

# Debug target
debug: CFLAGS += -DDEBUG -g3 -O0
debug: CXXFLAGS += -DDEBUG -g3 -O0
debug: clean all

# Clean
clean:
	rm -f $(PROGRAMS) *.o core *.pcap

# Install (for OpenWRT ipkg)
install:
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(PROGRAMS) $(DESTDIR)/usr/bin/

# Create debug script
create-debug-script:
	cp watr-debug.sh watr-debug.sh.bak 2>/dev/null || true
	chmod +x watr-debug.sh

# Full test sequence
full-test: all create-debug-script
	@echo "Full test sequence - run as root:"
	@echo "1. Check monitor capability: sudo ./wifi-monitor-check"
	@echo "2. Set up monitor mode: sudo ./wifi-monitor-setup phy0"
	@echo "3. Run debug script: sudo ./watr-debug.sh mon0"

# OpenWRT package info
openwrt-package:
	@echo "Package: watr-protocol"
	@echo "Version: 1.0"
	@echo "Architecture: all"
	@echo "Depends: libnl"
	@echo "Description: WATR protocol implementation"

.PHONY: all clean install test debug create-debug-script full-test openwrt-package
