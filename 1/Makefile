# ==============================================================================
# Makefile: Low-Level Production-Grade POSIX File Transfer Utility
# ==============================================================================

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2
TARGET   := sys_transfer
SRC      := sys_transfer.cpp

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
	rm -rf test_sandbox

test: $(TARGET)
	@mkdir -p test_sandbox/dir_target
	@echo "--- 1. Testing Arbitrary Binary Stream (PNG / PDF simulation) ---"
	@head -c 2097152 /dev/urandom > test_sandbox/test.bin
	@chmod 755 test_sandbox/test.bin
	@./$(TARGET) test_sandbox/test.bin test_sandbox/copy.bin
	@cmp test_sandbox/test.bin test_sandbox/copy.bin
	@echo "[PASS] Binary streams are bit-for-bit identical."
	@echo "--- 2. Testing Directory Destination Target ---"
	@./$(TARGET) test_sandbox/test.bin test_sandbox/dir_target/
	@cmp test_sandbox/test.bin test_sandbox/dir_target/test.bin
	@echo "[PASS] Directory target transfer verified."
	@echo "--- 3. Testing Move Mode (--move) ---"
	@./$(TARGET) -m test_sandbox/copy.bin test_sandbox/moved.bin
	@test ! -f test_sandbox/copy.bin && test -f test_sandbox/moved.bin
	@echo "[PASS] Move mode and unlinking verified."
	@echo "--- 4. Testing Self-Overwrite Protection ---"
	@! ./$(TARGET) test_sandbox/moved.bin test_sandbox/moved.bin 2>/dev/null
	@echo "[PASS] Self-overwrite safely aborted."
	@rm -rf test_sandbox
	@echo "=== ALL AUTOMATED TESTS PASSED ==="
