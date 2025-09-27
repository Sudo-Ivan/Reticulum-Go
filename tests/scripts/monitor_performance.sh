#!/bin/bash
set -e

echo "Starting Reticulum-Go with memory and CPU monitoring..."

# Start the process in background
./bin/reticulum-go &
PID=$!

echo "Process started with PID: $PID"

# Initialize tracking variables
MAX_RSS=0
MAX_VSZ=0
MAX_CPU=0
SAMPLES=0
TOTAL_RSS=0
TOTAL_VSZ=0
TOTAL_CPU=0

END_TIME=$((SECONDS + 40))

while [ $SECONDS -lt $END_TIME ] && kill -0 $PID 2>/dev/null; do
    # Get memory and CPU info using ps
    if PROC_INFO=$(ps -o pid,rss,vsz,pcpu --no-headers -p $PID 2>/dev/null); then
        RSS=$(echo $PROC_INFO | awk '{print $2}')  # RSS in KB
        VSZ=$(echo $PROC_INFO | awk '{print $3}')  # VSZ in KB
        CPU=$(echo $PROC_INFO | awk '{print $4}')  # CPU percentage

        if [ -n "$RSS" ] && [ -n "$VSZ" ] && [ -n "$CPU" ]; then
            SAMPLES=$((SAMPLES + 1))
            TOTAL_RSS=$((TOTAL_RSS + RSS))
            TOTAL_VSZ=$((TOTAL_VSZ + VSZ))
            TOTAL_CPU=$((TOTAL_CPU + CPU))

            if [ $RSS -gt $MAX_RSS ]; then
                MAX_RSS=$RSS
            fi

            if [ $VSZ -gt $MAX_VSZ ]; then
                MAX_VSZ=$VSZ
            fi

            # CPU is already a percentage (0-100), so compare as integers
            CPU_INT=$(echo $CPU | cut -d. -f1)
            if [ $CPU_INT -gt $MAX_CPU ]; then
                MAX_CPU=$CPU_INT
            fi
        fi
    fi

    sleep 0.1  # Sample every 100ms
done

# Stop the process if still running
if kill -0 $PID 2>/dev/null; then
    echo "Stopping process..."
    kill $PID 2>/dev/null || true
    sleep 1
    kill -9 $PID 2>/dev/null || true
fi

# Calculate averages
if [ $SAMPLES -gt 0 ]; then
    AVG_RSS=$((TOTAL_RSS / SAMPLES))
    AVG_VSZ=$((TOTAL_VSZ / SAMPLES))
    AVG_CPU=$((TOTAL_CPU / SAMPLES))
else
    AVG_RSS=0
    AVG_VSZ=0
    AVG_CPU=0
fi

# Convert to MB and GB
MAX_RSS_MB=$((MAX_RSS / 1024))
MAX_RSS_GB=$((MAX_RSS_MB / 1024))
AVG_RSS_MB=$((AVG_RSS / 1024))
AVG_RSS_GB=$((AVG_RSS_MB / 1024))

MAX_VSZ_MB=$((MAX_VSZ / 1024))
MAX_VSZ_GB=$((MAX_VSZ_MB / 1024))
AVG_VSZ_MB=$((AVG_VSZ / 1024))
AVG_VSZ_GB=$((AVG_VSZ_MB / 1024))

# Output results
echo "=== Performance Usage Report ==="
echo "Monitoring duration: 40 seconds"
echo "Samples collected: $SAMPLES"
echo ""

echo "## CPU Usage - Processor Utilization (since process start)"
echo "- Max CPU: ${MAX_CPU}%"
echo "- Avg CPU: ${AVG_CPU}%"
echo "- Note: Low CPU usage is normal for I/O-bound network applications"
echo ""

echo "## RSS (Resident Set Size) - Actual Memory Used"
echo "- Max RSS: ${MAX_RSS} KB (${MAX_RSS_MB} MB / ${MAX_RSS_GB} GB)"
echo "- Avg RSS: ${AVG_RSS} KB (${AVG_RSS_MB} MB / ${AVG_RSS_GB} GB)"
echo ""

echo "## VSZ (Virtual Memory Size) - Total Virtual Memory"
echo "- Max VSZ: ${MAX_VSZ} KB (${MAX_VSZ_MB} MB / ${MAX_VSZ_GB} GB)"
echo "- Avg VSZ: ${AVG_VSZ} KB (${AVG_VSZ_MB} MB / ${AVG_VSZ_GB} GB)"
echo ""

# Output for potential future use
echo "MAX_CPU=$MAX_CPU" >> $GITHUB_OUTPUT
echo "AVG_CPU=$AVG_CPU" >> $GITHUB_OUTPUT
echo "MAX_RSS_MB=$MAX_RSS_MB" >> $GITHUB_OUTPUT
echo "AVG_RSS_MB=$AVG_RSS_MB" >> $GITHUB_OUTPUT
echo "MAX_VSZ_MB=$MAX_VSZ_MB" >> $GITHUB_OUTPUT
echo "AVG_VSZ_MB=$AVG_VSZ_MB" >> $GITHUB_OUTPUT
