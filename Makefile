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
UNIT_TESTS_DIR = $(TESTS_DIR)/unit
INTEGRATION_TESTS_DIR = $(TESTS_DIR)/integration
VECTORS_TESTS_DIR = $(TESTS_DIR)/vectors

# Основные исходные файлы
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/file_io.c $(SRC_DIR)/csprng.c \
       $(MODES_DIR)/ecb.c $(MODES_DIR)/cbc.c $(MODES_DIR)/cfb.c \
       $(MODES_DIR)/ofb.c $(MODES_DIR)/ctr.c $(MODES_DIR)/gcm.c \
       $(AEAD_DIR)/etm.c \
       $(HASH_DIR)/sha256.c $(HASH_DIR)/sha3_256.c \
       $(MAC_DIR)/hmac.c $(MAC_DIR)/cmac.c \
       $(KDF_DIR)/pbkdf2.c $(KDF_DIR)/hkdf.c \
       $(TESTS_DIR)/keys_tests.c $(TESTS_DIR)/nist_tests.c $(TESTS_DIR)/hash_tests.c \
       $(TESTS_DIR)/mac_tests.c $(TESTS_DIR)/aead_tests.c $(TESTS_DIR)/tests_kdf.c

# Файлы тестов
UNIT_TEST_SRCS = $(UNIT_TESTS_DIR)/all_unit_tests.c
INTEGRATION_TEST_SRCS = $(INTEGRATION_TESTS_DIR)/all_integration_tests.c
VECTORS_TEST_SRCS = $(VECTORS_TESTS_DIR)/all_vectors_tests.c

# Объектные файлы
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
UNIT_TEST_OBJS = $(UNIT_TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
INTEGRATION_TEST_OBJS = $(INTEGRATION_TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
VECTORS_TEST_OBJS = $(VECTORS_TEST_SRCS:%.c=$(BUILD_DIR)/%.o)

TARGET = cryptocore

.PHONY: all clean directories test test-vectors test-unit test-integration test-keys test-nist test-hash test-mac test-aead test-kdf test-all help

all: directories $(TARGET)

$(TARGET): $(OBJS) $(UNIT_TEST_OBJS) $(INTEGRATION_TEST_OBJS) $(VECTORS_TEST_OBJS)
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
	@mkdir -p $(BUILD_DIR)/$(UNIT_TESTS_DIR)
	@mkdir -p $(BUILD_DIR)/$(INTEGRATION_TESTS_DIR)
	@mkdir -p $(BUILD_DIR)/$(VECTORS_TESTS_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) nist_test_data.bin *.tmp *.enc *.dec *.cmac *.derived *.sha256 *.sha3 *.hmac *.key

test-vectors: $(TARGET)
	@echo "Running Known-Answer Tests (NIST Vectors)..."
	@./$(TARGET) --input --test-vectors

test-unit: $(TARGET)
	@echo "Running Unit Tests..."
	@./$(TARGET) --input --test-unit

test-integration: $(TARGET)
	@echo "Running Integration Tests..."
	@./$(TARGET) --input --test-integration

test-keys: $(TARGET)
	@echo "Running CSPRNG Key Tests..."
	@./$(TARGET) --input --test-keys

test-nist: $(TARGET)
	@echo "Generating NIST Test File..."
	@./$(TARGET) --input --test-nist

test-hash: $(TARGET)
	@echo "Running Hash Function Tests..."
	@./$(TARGET) --input --test-hash

test-mac: $(TARGET)
	@echo "Running MAC Function Tests..."
	@./$(TARGET) --input --test-mac

test-aead: $(TARGET)
	@echo "Running AEAD (GCM + ETM) Tests..."
	@./$(TARGET) --input --test-aead

test-kdf: $(TARGET)
	@echo "Running KDF Function Tests..."
	@./$(TARGET) --input --test-kdf

test-all: test-vectors test-keys test-nist test-hash test-mac test-aead test-kdf test-unit test-integration
	@echo "All tests completed!"

help:
	@echo "CRYPTOCORE BUILD SYSTEM"
	@echo "========================"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build the cryptocore tool"
	@echo ""
	@echo "Test targets:"
	@echo "  test-vectors     - Run known-answer vector tests (NIST standards)"
	@echo "  test-unit        - Run unit tests for all modules"
	@echo "  test-integration - Run integration tests (CLI end-to-end)"
	@echo "  test-keys        - Run CSPRNG key generation tests"
	@echo "  test-nist        - Generate 10MB file for NIST tests"
	@echo "  test-hash        - Run hash function tests (SHA-256, SHA3-256)"
	@echo "  test-mac         - Run MAC function tests (HMAC, CMAC)"
	@echo "  test-aead        - Run AEAD tests (GCM + Encrypt-then-MAC)"
	@echo "  test-kdf         - Run KDF function tests (PBKDF2, HKDF)"
	@echo "  test-all         - Run all tests"
	@echo ""
	@echo "Utility targets:"
	@echo "  clean            - Clean build artifacts"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Direct CLI usage examples:"
	@echo "  Run vector tests:     ./cryptocore --input --test-vectors"
	@echo "  Run unit tests:       ./cryptocore --input --test-unit"
	@echo "  Run integration:      ./cryptocore --input --test-integration"
	@echo "  Run all hash tests:   ./cryptocore --input --test-hash"
	@echo "  Run all MAC tests:    ./cryptocore --input --test-mac"
	@echo "  Run all KDF tests:    ./cryptocore --input --test-kdf"
	@echo ""
	@echo "Make usage examples:"
	@echo "  Build everything:     make all"
	@echo "  Run all tests:        make test-all"
	@echo "  Clean build:          make clean"
	@echo "  Run specific tests:   make test-vectors"
	@echo "                       make test-unit"
	@echo "                       make test-integration"
	