# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++14 -I./include -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lpcap

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files and object files
SRC_FILES = $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRC_FILES))

# Output binary
TARGET = $(BIN_DIR)/sniffer

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
    @mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Linking
$(TARGET): $(OBJ_FILES)
    $(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Compilation
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
    $(CXX) $(CXXFLAGS) -c $< -o $@

# Clean
clean:
    rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run
run: all
    sudo $(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: all

.PHONY: all clean run debug directories