// Package env holds the one environment-variable helper every service's
// main.go needs at startup: reading a required config value and failing
// closed (RD-04) if it is unset or empty, rather than silently proceeding
// with a zero value.
package env

import (
	"fmt"
	"os"
)

// Require reads the environment variable name, returning an error if it is
// unset or empty. Every service's own startup wiring calls this for each
// piece of required configuration (mesh join parameters, mTLS material
// paths, MQTT broker address, etc.) so a missing value is caught before
// the service starts serving traffic, instead of surfacing later as a
// confusing failure deep in some unrelated code path.
func Require(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}
