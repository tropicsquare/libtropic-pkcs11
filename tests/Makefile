CC = gcc
CFLAGS = -fPIC -Wall -O2
LDFLAGS = -shared

TARGET = libtropic_pkcs11.so
SRC = pkcs11.c
OBJ = pkcs11.o
TEST = test_direct

all: $(TARGET)
	@echo "Built $(TARGET)"
	@echo "Install with: sudo cp $(TARGET) /usr/lib/aarch64-linux-gnu/ossl-modules/"
	@echo "Build test with: make test"

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ): $(SRC) pkcs11.h
	$(CC) $(CFLAGS) -c $(SRC)

test: $(TEST)
	@echo "Built $(TEST)"
	@echo "Run with: ./$(TEST)"

$(TEST): test_direct.c pkcs11.h
	$(CC) -o $@ $< -ldl

clean:
	rm -f $(TARGET) $(OBJ) $(TEST)

.PHONY: all test clean


