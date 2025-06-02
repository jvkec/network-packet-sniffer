CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++14 -I./include
LDFLAGS = -lpcap

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = test

# Source files and object files
SRC_FILES = $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRC_FILES))

# Test files
TEST_SRC = $(TEST_DIR)/packet_parser_test.cpp
TEST_OBJ = $(patsubst $(TEST_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(TEST_SRC))
TEST_TARGET = $(BIN_DIR)/test_runner

# Output binary
TARGET = $(BIN_DIR)/sniffer

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Linking main program
$(TARGET): $(OBJ_FILES)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Compilation for source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compilation for test files
$(OBJ_DIR)/%.o: $(TEST_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Test target (excludes main.o to avoid multiple main functions)
test: directories $(TEST_TARGET)
	$(TEST_TARGET)

$(TEST_TARGET): $(filter-out $(OBJ_DIR)/main.o, $(OBJ_FILES)) $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run with sudo (required for packet capture)
run: all
	sudo $(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: all

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install libpcap-dev

.PHONY: all clean run debug directories test install-deps