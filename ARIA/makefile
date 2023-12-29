CXX := g++
CXXFLAGS := -std=c++11 -Wall -O2

SRC_DIR := .
INC_DIRS := .
OBJ_DIR := obj
BIN_DIR := bin

EXCLUDED_SRCS := 
SRCS := $(filter-out $(addprefix $(SRC_DIR)/,$(EXCLUDED_SRCS)), $(wildcard $(SRC_DIR)/*.cpp))
OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Executable
TARGET := $(BIN_DIR)/test

# Build executable
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(addprefix -I, $(INC_DIRS)) $^ -o $@

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(addprefix -I, $(INC_DIRS)) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Phony target to avoid conflicts with file names
.PHONY: clean
