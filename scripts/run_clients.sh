#!/bin/bash

# Build the client and server
echo "Building Reticulum client..."
go build -o bin/reticulum-client ./cmd/client
go build -o bin/reticulum ./cmd/reticulum

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Create directories
mkdir -p logs
mkdir -p bin

# Start the Reticulum server first
echo "Starting Reticulum server..."
./bin/reticulum > logs/server.log 2>&1 &
echo $! > logs/server.pid
sleep 2  # Give server time to start

# Generate identities for both clients
echo "Generating identities..."
CLIENT1_HASH=$(./bin/reticulum-client -config configs/test-client1.toml -generate-identity 2>&1 | grep "Identity hash:" | cut -d' ' -f3)
CLIENT2_HASH=$(./bin/reticulum-client -config configs/test-client2.toml -generate-identity 2>&1 | grep "Identity hash:" | cut -d' ' -f3)

echo "Client 1 Hash: $CLIENT1_HASH"
echo "Client 2 Hash: $CLIENT2_HASH"

# Function to run client
run_client() {
    local config=$1
    local target=$2
    local logfile=$3
    echo "Starting client with config: $config targeting: $target"
    ./bin/reticulum-client -config "$config" -target "$target" > "$logfile" 2>&1 &
    echo $! > "$logfile.pid"
    echo "Client started with PID: $(cat $logfile.pid)"
}

# Run both clients targeting each other
run_client "configs/test-client1.toml" "$CLIENT2_HASH" "logs/client1.log"
run_client "configs/test-client2.toml" "$CLIENT1_HASH" "logs/client2.log"

echo
echo "Both clients are running. To stop everything:"
echo "kill \$(cat logs/*.pid)"
echo
echo "To view logs:"
echo "tail -f logs/client1.log"
echo "tail -f logs/client2.log" 