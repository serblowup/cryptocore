CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -std=c99 -g
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/modes/ecb.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/file_io.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TARGET = cryptocore

.PHONY: all clean directories

all: directories $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

directories:
	@mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

