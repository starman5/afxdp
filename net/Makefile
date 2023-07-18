CC = gcc
CFLAGS = -O3 -Wall -Wextra -pthread

all: server client tiny_client tinier_client pause_client kvserver

server:
	$(CC) $(CFLAGS) -o server server.c

client:
	$(CC) $(CFLAGS) -o client client.c

tiny_client:
	$(CC) $(CFLAGS) -o tiny_client tiny_client.c

tinier_client:
	$(CC) $(CFLAGS) -o tinier_client tinier_client.c

pause_client:
	$(CC) $(CFLAGS) -o pause_client pause_client.c

kvserver:
	$(CC) $(CFLAGS) -o kvserver kvserver.c

clean:
	rm -rf server client tiny_client tinier_client pause_client kvserver