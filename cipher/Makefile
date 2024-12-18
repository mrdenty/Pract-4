CXX = g++
CXXFLAGS = -g -Wall -std=c++11
LDFLAGS = -lcryptopp

TARGET = main
SRCS = main.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
