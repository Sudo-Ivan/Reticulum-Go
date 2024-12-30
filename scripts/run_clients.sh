#!/bin/bash

# Function to show usage
show_usage() {
    echo "Usage: $0 [--type TYPE]"
    echo "  --type    Type of client to run (default: client, options: client, ftp)"
    exit 1
}

# Parse command line arguments
CLIENT_TYPE="client"
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            CLIENT_TYPE="$2"
            shift 2
            ;;
        *)
            show_usage
            ;;
    esac
done

# Validate client type
if [[ "$CLIENT_TYPE" != "client" && "$CLIENT_TYPE" != "ftp" ]]; then
    echo "Error: Invalid client type. Must be 'client' or 'ftp'"
    show_usage
fi

# Build the appropriate binaries
echo "Building Reticulum binaries..."
go build -o bin/reticulum ./cmd/reticulum

case $CLIENT_TYPE in
    "client")
        go build -o bin/reticulum-client ./cmd/client
        CLIENT_BIN="reticulum-client"
        ;;
    "ftp")
        go build -o bin/reticulum-client-ftp ./cmd/client-ftp
        CLIENT_BIN="reticulum-client-ftp"
        ;;
esac

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
CLIENT1_HASH=$(./bin/"$CLIENT_BIN" -config configs/test-client1.toml -generate-identity 2>&1 | grep "Identity hash:" | cut -d' ' -f3)
CLIENT2_HASH=$(./bin/"$CLIENT_BIN" -config configs/test-client2.toml -generate-identity 2>&1 | grep "Identity hash:" | cut -d' ' -f3)

echo "Client 1 Hash: $CLIENT1_HASH"
echo "Client 2 Hash: $CLIENT2_HASH"

# Function to run client
run_client() {
    local config=$1
    local target=$2
    local logfile=$3
    
    case $CLIENT_TYPE in
        "client")
            echo "Starting regular client with config: $config targeting: $target"
            ./bin/"$CLIENT_BIN" -config "$config" -target "$target" > "$logfile" 2>&1 &
            ;;
        "ftp")
            echo "Starting FTP client with config: $config serving directory: $target"
            ./bin/"$CLIENT_BIN" -config "$config" -serve "$target" > "$logfile" 2>&1 &
            ;;
    esac
    
    echo $! > "$logfile.pid"
    echo "Client started with PID: $(cat $logfile.pid)"
}

# Run both clients with appropriate parameters
case $CLIENT_TYPE in
    "client")
        run_client "configs/test-client1.toml" "$CLIENT2_HASH" "logs/client1.log"
        run_client "configs/test-client2.toml" "$CLIENT1_HASH" "logs/client2.log"
        ;;
    "ftp")
        # Create shared directories for FTP clients
        mkdir -p ./shared/client1 ./shared/client2
        run_client "configs/test-client1.toml" "./shared/client1" "logs/client1.log" "$CLIENT2_HASH"
        run_client "configs/test-client2.toml" "./shared/client2" "logs/client2.log" "$CLIENT1_HASH"
        ;;
esac

echo
echo "Both clients are running. To stop everything:"
echo "kill \$(cat logs/*.pid)"
echo
echo "To view logs:"
echo "tail -f logs/client1.log"
echo "tail -f logs/client2.log"

if [ "$CLIENT_TYPE" = "ftp" ]; then
    echo
    echo "FTP shared directories:"
    echo "./shared/client1"
    echo "./shared/client2"
fi 