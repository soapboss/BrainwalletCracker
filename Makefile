CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto -lssl -lscrypt

SRCS = main.c crypto.c util.c
OBJS = $(SRCS:.c=.o)
TARGET = btc_wallet_gen

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean 