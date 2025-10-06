// Entry-Hub module for RAM-USB distributed backup system
// Implements HTTPS REST API with mTLS client for Security-Switch communication
module https_server

go 1.24.1

require github.com/eclipse/paho.mqtt.golang v1.5.1

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
)
