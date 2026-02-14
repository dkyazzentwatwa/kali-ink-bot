#!/bin/bash
# Kali Ink Bot - Boot Script
# Launches bettercap API and web mode together

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/.venv"
LOG_DIR="$HOME/.inkling/logs"
PID_DIR="$HOME/.inkling/pids"

# Bettercap settings (override in config.local.yml or environment)
BETTERCAP_USER="${BETTERCAP_USER:-inkling}"
BETTERCAP_PASS="${BETTERCAP_PASS:-changeme}"
BETTERCAP_PORT="${BETTERCAP_PORT:-8083}"

# Create directories
mkdir -p "$LOG_DIR" "$PID_DIR"

# Load environment variables from .env if exists
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

start_bettercap() {
    echo "Starting bettercap API..."

    # Check if already running
    if [ -f "$PID_DIR/bettercap.pid" ]; then
        if kill -0 "$(cat "$PID_DIR/bettercap.pid")" 2>/dev/null; then
            echo "Bettercap already running (PID: $(cat "$PID_DIR/bettercap.pid"))"
            return 0
        fi
    fi

    # Start bettercap in background
    sudo bettercap \
        -api-rest \
        -api.rest.address 127.0.0.1 \
        -api.rest.port "$BETTERCAP_PORT" \
        -api.rest.username "$BETTERCAP_USER" \
        -api.rest.password "$BETTERCAP_PASS" \
        -silent \
        > "$LOG_DIR/bettercap.log" 2>&1 &

    echo $! > "$PID_DIR/bettercap.pid"
    echo "Bettercap started (PID: $!)"

    # Wait for API to be ready
    for i in {1..10}; do
        if curl -s -u "$BETTERCAP_USER:$BETTERCAP_PASS" "http://127.0.0.1:$BETTERCAP_PORT/api/session" > /dev/null 2>&1; then
            echo "Bettercap API ready"
            return 0
        fi
        sleep 1
    done
    echo "Warning: Bettercap API not responding (may still be starting)"
}

start_webmode() {
    echo "Starting Kali Ink Bot web mode..."

    # Check if already running
    if [ -f "$PID_DIR/inkbot.pid" ]; then
        if kill -0 "$(cat "$PID_DIR/inkbot.pid")" 2>/dev/null; then
            echo "Ink Bot already running (PID: $(cat "$PID_DIR/inkbot.pid"))"
            return 0
        fi
    fi

    # Activate virtual environment and start
    cd "$PROJECT_DIR"
    source "$VENV_DIR/bin/activate"

    python main.py --mode web > "$LOG_DIR/inkbot.log" 2>&1 &

    echo $! > "$PID_DIR/inkbot.pid"
    echo "Ink Bot started (PID: $!)"
}

stop_bettercap() {
    echo "Stopping bettercap..."
    if [ -f "$PID_DIR/bettercap.pid" ]; then
        PID=$(cat "$PID_DIR/bettercap.pid")
        if kill -0 "$PID" 2>/dev/null; then
            sudo kill "$PID" 2>/dev/null || true
            sleep 1
            sudo kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f "$PID_DIR/bettercap.pid"
    fi
    # Also kill any orphaned bettercap processes
    sudo pkill -f "bettercap.*api-rest" 2>/dev/null || true
    echo "Bettercap stopped"
}

stop_webmode() {
    echo "Stopping Kali Ink Bot..."
    if [ -f "$PID_DIR/inkbot.pid" ]; then
        PID=$(cat "$PID_DIR/inkbot.pid")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            sleep 1
            kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f "$PID_DIR/inkbot.pid"
    fi
    # Also kill any orphaned python processes running main.py
    pkill -f "python.*main.py.*--mode web" 2>/dev/null || true
    echo "Ink Bot stopped"
}

status() {
    echo "=== Kali Ink Bot Status ==="
    echo ""

    # Bettercap status
    if [ -f "$PID_DIR/bettercap.pid" ] && kill -0 "$(cat "$PID_DIR/bettercap.pid")" 2>/dev/null; then
        echo "Bettercap:  RUNNING (PID: $(cat "$PID_DIR/bettercap.pid"))"
        if curl -s -u "$BETTERCAP_USER:$BETTERCAP_PASS" "http://127.0.0.1:$BETTERCAP_PORT/api/session" > /dev/null 2>&1; then
            echo "            API: OK (port $BETTERCAP_PORT)"
        else
            echo "            API: NOT RESPONDING"
        fi
    else
        echo "Bettercap:  STOPPED"
    fi

    # Ink Bot status
    if [ -f "$PID_DIR/inkbot.pid" ] && kill -0 "$(cat "$PID_DIR/inkbot.pid")" 2>/dev/null; then
        echo "Ink Bot:    RUNNING (PID: $(cat "$PID_DIR/inkbot.pid"))"
        if curl -s "http://127.0.0.1:8081/api/state" > /dev/null 2>&1; then
            echo "            Web UI: OK (port 8081)"
        else
            echo "            Web UI: NOT RESPONDING"
        fi
    else
        echo "Ink Bot:    STOPPED"
    fi

    echo ""
    echo "Logs: $LOG_DIR/"
}

logs() {
    SERVICE="${2:-all}"
    case "$SERVICE" in
        bettercap)
            tail -f "$LOG_DIR/bettercap.log"
            ;;
        inkbot|web)
            tail -f "$LOG_DIR/inkbot.log"
            ;;
        *)
            tail -f "$LOG_DIR/bettercap.log" "$LOG_DIR/inkbot.log"
            ;;
    esac
}

case "$1" in
    start)
        start_bettercap
        sleep 2
        start_webmode
        echo ""
        echo "Kali Ink Bot started!"
        echo "Web UI: http://localhost:8081"
        echo "WiFi Dashboard: http://localhost:8081/wifi"
        echo "Terminal: http://localhost:8081/terminal"
        ;;
    stop)
        stop_webmode
        stop_bettercap
        echo "Kali Ink Bot stopped"
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        status
        ;;
    logs)
        logs "$@"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs [bettercap|inkbot]}"
        exit 1
        ;;
esac
