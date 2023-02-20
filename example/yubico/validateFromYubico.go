package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dsggregory/yubiv/pkg/yubico"

	log "github.com/sirupsen/logrus"
)

func gets(prompt string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	resp = strings.TrimRight(resp, "\r\n")
	return resp, nil
}

func main() {
	// This example reads the API creds from stdin.
	// You could instead set them in environment variables and use WithAPIEnvironment() when calling NewYubiClient().
	id, _ := gets("Enter Yubico API ID: ")
	apikeyB64, _ := gets("Enter Yubico API Key: ") // Yubico presents them as base64-encoded
	y, err := yubico.NewYubiClient(yubico.WithAPICreds(id, apikeyB64))
	if err != nil {
		log.Fatal(err)
	}

	// this reads from a yubi press from stdin
	otp, err := gets("Enter OTP: ")
	if err != nil {
		log.Fatal(err)
	}
	resp, err := y.VerifyOTP(otp)
	if err != nil {
		log.Fatal(fmt.Sprintf("Validation failed: %s", err.Error()))
	}
	fmt.Println("Validation success!")
	fmt.Println(json.NewEncoder(os.Stdout).Encode(resp))
}
