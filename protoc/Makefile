# Makefile for WATR protocol test programs
# Optimized for OpenWRT and embedded systems

CC = gcc
CXX = g++
CFLAGS = -Wall -O2 -std=c11
CXXFLAGS = -Wall -O2 -std=c++11
LDFLAGS = -lpthread

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
PROGRAMS = send-test receive-test

# Source files
SEND_SRC = send-test.cpp
RECEIVE_SRC = receive-test.cpp
COMMON_SRC = watr_protocol.cpp

# Object files
SEND_OBJ = $(SEND_SRC:.cpp=.o)
RECEIVE_OBJ = $(RECEIVE_SRC:.cpp=.o)
COMMON_OBJ = $(COMMON_SRC:.cpp=.o)

# Default target
all: $(PROGRAMS)

# Build rules
send-test: $(SEND_OBJ) $(COMMON_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

receive-test: $(RECEIVE_OBJ) $(COMMON_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Generic rules
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -f $(PROGRAMS) *.o

# Install (for OpenWRT ipkg)
install:
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(PROGRAMS) $(DESTDIR)/usr/bin/

# OpenWRT package info
openwrt-package:
	@echo "Package: watr-protoc"
	@echo "Version: 1.0"
	@echo "Architecture: all"
	@echo "Description: WATR protocol test utilities"

.PHONY: all clean install openwrt-package