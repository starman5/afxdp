CC = gcc
CFLAGS = -O3 -Wall -Wextra -pthread

all: server client tiny_client tinier_client

server:
	$(CC) $(CFLAGS) -o server server.c

client:
	$(CC) $(CFLAGS) -o client client.c

tiny_client:
	$(CC) $(CFLAGS) -o tiny_client tiny_client.c

tinier_client:
	$(CC) $(CFLAGS) -o tinier_client tiner_client.c

clean:
	rm -rf server client tiny_client tinier_client