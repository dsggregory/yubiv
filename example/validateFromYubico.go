package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dsggregory/yubiv/pkg/yubikey"
	log "github.com/sirupsen/logrus"
)

func main() {
	y, err := yubikey.NewYubiAuth("")
	if err != nil {
		log.Fatal(err)
	}

	// this reads from a yubi press from stdin
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	otp, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	otp = strings.TrimRight(otp, "\r\n")
	y.SetToken(otp)

	user, err := y.Validate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(json.NewEncoder(os.Stdout).Encode(user))
}
