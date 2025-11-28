CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -std=c99 -g
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build
MODES_DIR = $(SRC_DIR)/modes
HASH_DIR = $(SRC_DIR)/hash
TESTS_DIR = tests

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/file_io.c $(SRC_DIR)/csprng.c \
       $(MODES_DIR)/ecb.c $(MODES_DIR)/cbc.c $(MODES_DIR)/cfb.c \
       $(MODES_DIR)/ofb.c $(MODES_DIR)/ctr.c \
       $(HASH_DIR)/sha256.c $(HASH_DIR)/sha3_256.c \
       $(TESTS_DIR)/keys_tests.c $(TESTS_DIR)/nist_tests.c $(TESTS_DIR)/hash_tests.c

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
	@mkdir -p $(BUILD_DIR)/$(HASH_DIR)
	@mkdir -p $(BUILD_DIR)/$(TESTS_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) nist_test_data.bin *.tmp

test-keys: $(TARGET)
	./$(TARGET) --input --test-keys

test-nist: $(TARGET)
	./$(TARGET) --input --test-nist

test-hash: $(TARGET)
	./$(TARGET) --input --test-hash

test-all: test-keys test-nist test-hash

help:
	@echo "Available targets:"
	@echo "  all              - Build the cryptocore tool"
	@echo "  test-keys        - Run CSPRNG key tests"
	@echo "  test-nist        - Generate 10MB file for NIST tests"
	@echo "  test-hash        - Run hash function tests"
	@echo "  test-all         - Run all tests"
	@echo "  clean            - Clean build artifacts"
	@echo ""
	@echo "Usage examples:"
	@echo "  Encryption:      ./cryptocore --algorithm aes --mode cbc --encrypt --input file.txt"
	@echo "  SHA-256 hash:    ./cryptocore dgst --algorithm sha256 --input document.pdf"
	@echo "  SHA3-256 hash:   ./cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3"
	@echo "  Run all tests:   make test-all"
