XX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2
LIBS = -ltins -lpcap
TARGET = custom_frame
SOURCE = custom.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

install:
	sudo apt-get update
	sudo apt-get install libtins-dev libpcap-dev

.PHONY: clean install
