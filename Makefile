CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -std=c99 -g -O2
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build
MODES_DIR = $(SRC_DIR)/modes
AEAD_DIR = $(SRC_DIR)/aead
HASH_DIR = $(SRC_DIR)/hash
MAC_DIR = $(SRC_DIR)/mac
KDF_DIR = $(SRC_DIR)/kdf
TESTS_DIR = tests

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/file_io.c $(SRC_DIR)/csprng.c \
       $(MODES_DIR)/ecb.c $(MODES_DIR)/cbc.c $(MODES_DIR)/cfb.c \
       $(MODES_DIR)/ofb.c $(MODES_DIR)/ctr.c $(MODES_DIR)/gcm.c \
       $(AEAD_DIR)/etm.c \
       $(HASH_DIR)/sha256.c $(HASH_DIR)/sha3_256.c \
       $(MAC_DIR)/hmac.c $(MAC_DIR)/cmac.c \
       $(KDF_DIR)/pbkdf2.c $(KDF_DIR)/hkdf.c \
       $(TESTS_DIR)/keys_tests.c $(TESTS_DIR)/nist_tests.c $(TESTS_DIR)/hash_tests.c \
       $(TESTS_DIR)/mac_tests.c $(TESTS_DIR)/aead_tests.c $(TESTS_DIR)/tests_kdf.c

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
	@mkdir -p $(BUILD_DIR)/$(AEAD_DIR)
	@mkdir -p $(BUILD_DIR)/$(HASH_DIR)
	@mkdir -p $(BUILD_DIR)/$(MAC_DIR)
	@mkdir -p $(BUILD_DIR)/$(KDF_DIR)
	@mkdir -p $(BUILD_DIR)/$(TESTS_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) nist_test_data.bin *.tmp *.enc *.dec *.cmac *.derived

test-keys: $(TARGET)
	./$(TARGET) --input --test-keys

test-nist: $(TARGET)
	./$(TARGET) --input --test-nist

test-hash: $(TARGET)
	./$(TARGET) --input --test-hash

test-mac: $(TARGET)
	./$(TARGET) --input --test-mac

test-aead: $(TARGET)
	./$(TARGET) --input --test-aead

test-kdf: $(TARGET)
	./$(TARGET) --input --test-kdf

test-all: test-keys test-nist test-hash test-mac test-aead test-kdf

help:
	@echo "Available targets:"
	@echo "  all              - Build the cryptocore tool"
	@echo "  test-keys        - Run CSPRNG key tests"
	@echo "  test-nist        - Generate 10MB file for NIST tests"
	@echo "  test-hash        - Run hash function tests"
	@echo "  test-mac        - Run MAC function tests"
	@echo "  test-aead        - Run AEAD (GCM + ETM) tests"
	@echo "  test-kdf         - Run KDF function tests"
	@echo "  test-all         - Run all tests"
	@echo "  clean            - Clean build artifacts"
	@echo ""
	@echo "Usage examples:"
	@echo "  GCM Encryption:  ./cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input plain.txt --output cipher.bin --aad aabbccddeeff"
	@echo "  GCM Decryption:  ./cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input cipher.bin --output decrypted.txt --aad aabbccddeeff"
	@echo "  PBKDF2 Derive:   ./cryptocore derive --algorithm pbkdf2 --password \"MyPassword\" --salt a1b2c3d4e5f601234567890123456789 --iterations 100000 --length 32"
	@echo "  HKDF Derive:     ./cryptocore derive --algorithm hkdf --master-key 00112233445566778899aabbccddeeff --context \"encryption\" --length 32"
	@echo "  Run KDF tests:   make test-kdf"                     
