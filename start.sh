#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <number_of_clients> <max_server_clients>"
    exit 1
fi

NUM_CLIENTS=$1
MAX_SERVER_CLIENTS=$2
CWD=$(pwd)

echo "Starting Mini-TLS environment with $NUM_CLIENTS clients (Server max clients: $MAX_SERVER_CLIENTS)..."

docker compose down

MAX_SERVER_CLIENTS=$MAX_SERVER_CLIENTS docker compose up -d --build --scale client=$NUM_CLIENTS

echo "Containers started. Opening terminals..."

# Open terminal for server
xterm -title "Mini-TLS Server" -e "docker attach minitls-server; exec bash" 2>/dev/null || \
echo "[INFO] Could not open terminal for server. Run manually: docker attach minitls-server"

sleep 2

CLIENT_IDS=$(docker ps --format "{{.ID}}" --filter "name=mini-tls-client")

i=1
for id in $CLIENT_IDS
do
   echo "Attaching to Client $i ($id)..."
   xterm -title "Mini-TLS Client $i" -e "docker attach $id; exec bash" 2>/dev/null || \
   echo "[INFO] Could not open terminal for client $i. Run manually: docker attach $id"
   ((i++))
done

echo "---------------------------------------------------"
echo "Environment running."
echo "To capture traffic for Wireshark:"
echo "Run this command in a new terminal:"
echo "docker exec -it minitls-server tcpdump -i eth0 -w /captures/traffic.pcap"
echo "---------------------------------------------------"
