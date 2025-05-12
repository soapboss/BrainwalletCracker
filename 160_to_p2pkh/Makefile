CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto -lssl

SRCS = hash160_converter.c
OBJS = $(SRCS:.c=.o)
TARGET = hash160_converter

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean 