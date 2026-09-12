CXX = c++
CXXFLAGS = -std=c++11 -Wall -Wextra -Wpedantic -O2

.PHONY: all test clean
all: crack

crack: crack.cpp crack.h
	$(CXX) $(CXXFLAGS) crack.cpp -o $@

test_crack: crack.cpp crack.h tests/test_crack.cpp
	$(CXX) $(CXXFLAGS) -DPASSWORD_LAB_TEST crack.cpp tests/test_crack.cpp -o $@

test: crack test_crack
	./test_crack
	./crack

clean:
	rm -f crack test_crack
