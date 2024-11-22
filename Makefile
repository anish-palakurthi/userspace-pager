CC = gcc
CFLAGS = -Wall -Wextra -g -static -O0
LDFLAGS = -static
LDSCRIPT = -Wl,-T,linker.ld

TARGETS = apager dpager hpager
TEST_PROGS = test_mixed test_array test_matrix

all: $(TARGETS)


# gcc -fPIE -pie -Wall -Wextra -g -O0 -o apager apager.c
# Pager targets
apager: apager.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

dpager: dpager.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

hpager: hpager.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Test programs
$(TEST_PROGS): %: %.c
	$(CC) $(LDSCRIPT) -static -O0 -o $@

test_progs: $(TEST_PROGS)

test: $(TARGETS) test_progs
	@echo "Testing null pointer handling..."
	-./apager test_array

clean:
	rm -f $(TARGETS) $(TEST_PROGS) *.o

.PHONY: all clean test test_progs