CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -std=c99 -g
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build
MODES_DIR = $(SRC_DIR)/modes
TESTS_DIR = tests

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/file_io.c $(SRC_DIR)/csprng.c \
       $(MODES_DIR)/ecb.c $(MODES_DIR)/cbc.c $(MODES_DIR)/cfb.c \
       $(MODES_DIR)/ofb.c $(MODES_DIR)/ctr.c \
       $(TESTS_DIR)/keys_tests.c $(TESTS_DIR)/nist_tests.c

OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
TARGET = cryptocore

.PHONY: all clean directories test help

all: directories $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

directories:
	@mkdir -p $(BUILD_DIR)/$(MODES_DIR)
	@mkdir -p $(BUILD_DIR)/$(TESTS_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) nist_test_data.bin

test-keys: $(TARGET)
	./$(TARGET) --input --test-keys

test-nist: $(TARGET)
	./$(TARGET) --input --test-nist

help:
	@echo "Available targets:"
	@echo "  all              - Build the cryptocore tool"
	@echo "  test-keys        - Run CSPRNG key tests (uniqueness, distribution, weak keys)"
	@echo "  test-nist        - Generate 10MB file for NIST tests"
	@echo "  clean            - Clean build artifacts"
	@echo ""
	@echo "Usage examples:"
	@echo "  ./cryptocore --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc"
	@echo "  ./cryptocore --input --test-keys   
	@echo "  ./cryptocore --input --test-nist    

	