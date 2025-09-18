// user-client/main.go
package main

import (
	"fmt"
	"log"
	"user-client/registration"
)

func main() {
	fmt.Println("R.A.M.-U.S.B. Simple Registration Client")
	fmt.Println("========================================")

	// Execute registration
	if err := registration.RegisterUser(); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}

	fmt.Println("Registration process completed successfully!")
}
