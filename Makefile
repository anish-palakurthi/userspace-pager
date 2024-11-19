CC = gcc
CFLAGS = -Wall -Wextra -g -static
LDFLAGS = -static

TARGETS = apager dpager hpager
TEST_PROGS = test_null test_array test_bss test_random test_mixed

all: $(TARGETS)

# Pager targets
apager: apager.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

dpager: dpager.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

hpager: hpager.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Test programs
$(TEST_PROGS): %: %.c
	$(CC) -static -o $@ $<

test_progs: $(TEST_PROGS)

# Test suite
test: $(TARGETS) test_progs
	@echo "Testing null pointer handling..."
	-./apager test_null
	-./dpager test_null
	-./hpager test_null
	
	@echo "\nTesting sequential access..."
	./apager test_array
	./dpager test_array
	./hpager test_array
	
	@echo "\nTesting BSS handling..."
	./apager test_bss
	./dpager test_bss
	./hpager test_bss
	
	@echo "\nTesting random access..."
	./apager test_random
	./dpager test_random
	./hpager test_random
	
	@echo "\nTesting mixed access patterns..."
	./apager test_mixed
	./dpager test_mixed
	./hpager test_mixed

clean:
	rm -f $(TARGETS) $(TEST_PROGS) *.o

.PHONY: all clean test test_progs