#!/bin/bash

echo "============================================"
echo "Mosquitto MQTT Broker Setup for RAM-USB"
echo "============================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -f /etc/debian_version ]; then
        OS="debian"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
    else
        OS="linux"
    fi
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Step 1: Install Mosquitto
echo "Step 1: Installing Mosquitto..."

case $OS in
    macos)
        if ! command -v mosquitto &> /dev/null; then
            echo "Installing Mosquitto via Homebrew..."
            brew install mosquitto
        else
            echo "Mosquitto is already installed"
        fi
        MOSQUITTO_DIR="/usr/local/opt/mosquitto"
        CONFIG_DIR="/usr/local/etc/mosquitto"
        ;;
    
    debian)
        if ! command -v mosquitto &> /dev/null; then
            echo "Installing Mosquitto via apt..."
            sudo apt-get update
            sudo apt-get install -y mosquitto mosquitto-clients
        else
            echo "Mosquitto is already installed"
        fi
        MOSQUITTO_DIR="/usr"
        CONFIG_DIR="/etc/mosquitto"
        ;;
    
    redhat)
        if ! command -v mosquitto &> /dev/null; then
            echo "Installing Mosquitto via yum..."
            sudo yum install -y epel-release
            sudo yum install -y mosquitto
        else
            echo "Mosquitto is already installed"
        fi
        MOSQUITTO_DIR="/usr"
        CONFIG_DIR="/etc/mosquitto"
        ;;
    
    *)
        echo "Please install Mosquitto manually for your OS"
        exit 1
        ;;
esac

# Step 2: Create directories
echo ""
echo "Step 2: Creating directories..."

# Create necessary directories
sudo mkdir -p $CONFIG_DIR
sudo mkdir -p /var/log/mosquitto
sudo mkdir -p /var/lib/mosquitto

# Set permissions on non MacOs systems
if [ "$OS" != "macos" ]; then
    sudo useradd -r -s /bin/false mosquitto 2>/dev/null || true
    sudo chown -R mosquitto:mosquitto /var/log/mosquitto
    sudo chown -R mosquitto:mosquitto /var/lib/mosquitto
fi

# Set correct permissions on macOS
if [ "$OS" = "macos" ]; then
    sudo chown -R $(whoami):staff /usr/local/var/lib/mosquitto/
    sudo chown -R $(whoami):staff /usr/local/var/log/mosquitto/
fi

# Step 3: Check certificates
echo ""
echo "Step 3: Checking certificates..."

CERT_BASE="../certificates"

# Check if certificates exist
if [ ! -f "$CERT_BASE/mqtt-broker/server.crt" ]; then
    echo "ERROR: MQTT broker certificates not found!"
    echo "Run the certificate generation script first:"
    echo "  cd scripts && ./generate_key.sh"
    exit 1
fi

echo "Certificates found"

# Step 4: Copy configuration files
echo ""
echo "Step 4: Copying configuration files..."

# Create symbolic links to certificates (or copy them)
sudo mkdir -p $CONFIG_DIR/certificates
sudo cp -r $CERT_BASE/* $CONFIG_DIR/certificates/ 2>/dev/null || {
    echo "Warning: Could not copy certificates. Creating symbolic links instead..."
    sudo ln -sf $(pwd)/$CERT_BASE $CONFIG_DIR/certificates
}

# Copy main configuration
if [ -f "mosquitto.conf" ]; then
    sudo cp mosquitto.conf $CONFIG_DIR/mosquitto.conf
    echo "Copied mosquitto.conf"
else
    echo "ERROR: mosquitto.conf not found in current directory"
    exit 1
fi

# Copy ACL configuration
if [ -f "acl.conf" ]; then
    sudo mkdir -p $CONFIG_DIR/config
    sudo cp acl.conf $CONFIG_DIR/config/acl.conf
    echo "Copied acl.conf"
else
    echo "ERROR: acl.conf not found in current directory"
    exit 1
fi

# Step 5: Update configuration paths
echo ""
echo "Step 5: Updating configuration paths..."

# Update paths in mosquitto.conf based on OS
case $OS in
    macos)
        sudo sed -i '' "s|/mosquitto/certificates|$CONFIG_DIR/certificates|g" $CONFIG_DIR/mosquitto.conf
        sudo sed -i '' "s|/mosquitto/config|$CONFIG_DIR/config|g" $CONFIG_DIR/mosquitto.conf
        sudo sed -i '' "s|/var/run/mosquitto|/usr/local/var/run|g" $CONFIG_DIR/mosquitto.conf
        sudo sed -i '' "s|/var/lib/mosquitto|/usr/local/var/lib/mosquitto|g" $CONFIG_DIR/mosquitto.conf
        sudo sed -i '' "s|/var/log/mosquitto|/usr/local/var/log/mosquitto|g" $CONFIG_DIR/mosquitto.conf
        
        # Create macOS specific directories
        sudo mkdir -p /usr/local/var/run
        sudo mkdir -p /usr/local/var/lib/mosquitto
        sudo mkdir -p /usr/local/var/log/mosquitto
        ;;
    
    *)
        sudo sed -i "s|/mosquitto/certificates|$CONFIG_DIR/certificates|g" $CONFIG_DIR/mosquitto.conf
        sudo sed -i "s|/mosquitto/config|$CONFIG_DIR/config|g" $CONFIG_DIR/mosquitto.conf
        ;;
esac

# Step 6: Test configuration
echo ""
echo "Step 6: Testing configuration..."

# Test the configuration
if mosquitto -c $CONFIG_DIR/mosquitto.conf -t 2>/dev/null; then
    echo "✓ Configuration test passed"
else
    echo "✗ Configuration test failed"
    echo "Run with verbose mode to see errors:"
    echo "  mosquitto -c $CONFIG_DIR/mosquitto.conf -v"
    exit 1
fi

# Step 7: Create systemd service (Linux only)
if [ "$OS" != "macos" ]; then
    echo ""
    echo "Step 7: Creating systemd service..."
    
    sudo tee /etc/systemd/system/mosquitto-ramusb.service > /dev/null << EOF
[Unit]
Description=Mosquitto MQTT Broker for RAM-USB
After=network.target
Wants=network.target

[Service]
Type=simple
User=mosquitto
ExecStart=/usr/sbin/mosquitto -c $CONFIG_DIR/mosquitto.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    echo "Systemd service created: mosquitto-ramusb"
fi

# Step 8: Start Mosquitto
echo ""
echo "Step 8: Starting Mosquitto..."

case $OS in
    macos)
        # Stop any existing Mosquitto instance
        brew services stop mosquitto 2>/dev/null || true
        
        echo "To start Mosquitto on macOS:"
        echo "  mosquitto -c $CONFIG_DIR/mosquitto.conf -v"
        echo ""
        echo "Or run as a service:"
        echo "  brew services start mosquitto"
        ;;
    
    *)
        # Stop default mosquitto if running
        sudo systemctl stop mosquitto 2>/dev/null || true
        sudo systemctl disable mosquitto 2>/dev/null || true
        
        # Start our configured instance
        sudo systemctl start mosquitto-ramusb
        sudo systemctl enable mosquitto-ramusb
        
        if sudo systemctl is-active --quiet mosquitto-ramusb; then
            echo "✓ Mosquitto is running"
        else
            echo "✗ Failed to start Mosquitto"
            echo "Check logs: sudo journalctl -u mosquitto-ramusb -f"
            exit 1
        fi
        ;;
esac

# Step 9: Test MQTT connectivity
echo ""
echo "Step 9: Testing MQTT connectivity..."

# Wait for Mosquitto to start
sleep 2

# Test with mosquitto_pub/sub (requires client certificates)
echo "To test MQTT publishing (replace with your certificate paths):"
echo "  mosquitto_pub -h localhost -p 8883 \\"
echo "    --cafile $CERT_BASE/certification-authority/ca.crt \\"
echo "    --cert $CERT_BASE/entry-hub/mqtt-publisher.crt \\"
echo "    --key $CERT_BASE/entry-hub/mqtt-publisher.key \\"
echo "    -t metrics/entry-hub \\"
echo "    -m '{\"service\":\"entry-hub\",\"timestamp\":1234567890,\"name\":\"test\",\"value\":1.0,\"labels\":{},\"type\":\"gauge\"}'"
echo ""
echo "To test MQTT subscribing:"
echo "  mosquitto_sub -h localhost -p 8883 \\"
echo "    --cafile $CERT_BASE/certification-authority/ca.crt \\"
echo "    --cert $CERT_BASE/metrics-collector/mqtt-subscriber.crt \\"
echo "    --key $CERT_BASE/metrics-collector/mqtt-subscriber.key \\"
echo "    -t 'metrics/+' -v"

# Step 10: Display summary
echo ""
echo "============================================"
echo "Mosquitto Setup Complete!"
echo "============================================"
echo ""
echo "Configuration:"
echo "  Config file: $CONFIG_DIR/mosquitto.conf"
echo "  ACL file: $CONFIG_DIR/config/acl.conf"
echo "  Certificates: $CONFIG_DIR/certificates/"
echo "  Port: 8883 (TLS only)"
echo "  Protocol: MQTT with TLS 1.3"
echo ""
echo "Service Management:"
case $OS in
    macos)
        echo "  Start: mosquitto -c $CONFIG_DIR/mosquitto.conf"
        echo "  Stop: Ctrl+C or kill process"
        echo "  Logs: /usr/local/var/log/mosquitto/mosquitto.log"
        ;;
    *)
        echo "  Start: sudo systemctl start mosquitto-ramusb"
        echo "  Stop: sudo systemctl stop mosquitto-ramusb"
        echo "  Status: sudo systemctl status mosquitto-ramusb"
        echo "  Logs: sudo journalctl -u mosquitto-ramusb -f"
        ;;
esac
echo ""
echo "Next Steps:"
echo "  1. Update Tailscale ACLs if needed"
echo "  2. Start Metrics-Collector service"
echo "  3. Configure services to publish metrics"
echo "  4. Monitor logs for any issues"