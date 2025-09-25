#!/bin/bash

echo "Testing R.A.M.-U.S.B. Monitoring System"
echo "======================================="

# Check if all services are running
echo "Checking services..."

# Check PostgreSQL
if pg_isready > /dev/null 2>&1; then
    echo "✓ PostgreSQL is running"
else
    echo "✗ PostgreSQL is not running"
    exit 1
fi

# Check Mosquitto
if pgrep mosquitto > /dev/null 2>&1; then
    echo "✓ Mosquitto is running"
else
    echo "✗ Mosquitto is not running"
    exit 1
fi

# Check Metrics-Collector
if curl -k -s https://localhost:8447/metrics > /dev/null 2>&1; then
    echo "✓ Metrics-Collector is responding"
else
    echo "✗ Metrics-Collector is not responding"
fi

# Check Prometheus
if curl -s http://localhost:9090/-/healthy > /dev/null 2>&1; then
    echo "✓ Prometheus is running"
else
    echo "✗ Prometheus is not running"
fi

# Send test metric via MQTT
echo ""
echo "Sending test metric..."
mosquitto_pub -h localhost -p 8883 \
    --cafile certificates/certification-authority/ca.crt \
    --cert certificates/entry-hub/mqtt-publisher.crt \
    --key certificates/entry-hub/mqtt-publisher.key \
    -t metrics/entry-hub \
    -m '{"service":"entry-hub","timestamp":'$(date +%s)',"name":"test_metric","value":1.0,"labels":{"test":"true"},"type":"gauge"}'

echo "Test metric sent"

# Wait and check if metric was stored
sleep 5
echo ""
echo "Checking if metric was stored..."

STORED_COUNT=$(psql -U metrics_user -d metrics_db -t -c "SELECT COUNT(*) FROM metrics WHERE metric_name = 'test_metric';" 2>/dev/null)

if [ "$STORED_COUNT" -gt "0" ]; then
    echo "✓ Test metric was successfully stored in TimescaleDB"
else
    echo "✗ Test metric was not stored"
fi

echo ""
echo "Monitoring system test complete!"