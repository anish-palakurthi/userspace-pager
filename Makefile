CC = gcc
CFLAGS = -Wall -Wextra -g -static
LDFLAGS = -static

TARGETS = apager dpager hpager
TEST_PROGS = test_null test_array test_bss

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
	-./apager test_array


clean:
	rm -f $(TARGETS) $(TEST_PROGS) *.o

.PHONY: all clean test test_progs