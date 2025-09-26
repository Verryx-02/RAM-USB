#!/bin/bash

echo "==============================================="
echo "RAM-USB Environment Variables Setup"
echo "==============================================="

# Database-Vault Configuration
export DATABASE_URL='postgres://ramusb_user:ramusb_secure_2024@localhost:5432/ramusb_vault?sslmode=disable'
export RAMUSB_ENCRYPTION_KEY=$(openssl rand -hex 32)

# MQTT Configuration for ALL services
export MQTT_BROKER_URL='ssl://localhost:8883'

# Metrics-Collector Configuration  
export METRICS_DATABASE_URL='postgres://metrics_user:metrics_secure_2024@localhost:5432/metrics_db?sslmode=disable'
export MQTT_CLIENT_ID='metrics-collector-subscriber'

# PostgreSQL Path (for psql commands)
export PATH="$(brew --prefix postgresql@17)/bin:$PATH"

echo "Environment variables configured successfully!"
echo ""
echo "Database URLs:"
echo "  Main DB: postgres://ramusb_user:***@localhost:5432/ramusb_vault"
echo "  Metrics DB: postgres://metrics_user:***@localhost:5432/metrics_db"  
echo ""
echo "MQTT Configuration:"
echo "  Broker URL: $MQTT_BROKER_URL"
echo ""
echo "Encryption Key: ${RAMUSB_ENCRYPTION_KEY:0:16}... (truncated)"
echo ""
echo "Ready to start RAM-USB services!"
echo "==============================================="
