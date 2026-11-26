CXX     ?= clang++
CXXFLAGS?= -O2 -Wall -Wextra -std=c++17 -D_GNU_SOURCE
TARGET   = sigmaker
OBJS     = main.o elf.o scan.o sig.o out.o reloc.o
all: $(TARGET)
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<
clean:
	rm -f $(OBJS) $(TARGET)
.PHONY: all clean
