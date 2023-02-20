package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dsggregory/yubiv/pkg/selfhosted/model"

	"github.com/dsggregory/yubiv/pkg/selfhosted"

	log "github.com/sirupsen/logrus"
)

// OpStr options for the app
type OpStr struct {
	dbPath     string
	addUser    bool
	printUsers bool
	otp        string
	secret     string

	y *selfhosted.YubiAuth
}

// gets reads a string from stdin
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

// printAllUsers prints all user records from the database
func (o *OpStr) printAllUsers() {
	users, err := o.y.GetDB().GetAll()
	if err != nil {
		log.Fatal(err)
	}
	js, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(js))
}

// addDeviceUser add a user and their Yubikey to the database.
func (o *OpStr) addDeviceUser() {
	otp, err := gets("Press Yubi device (from device to add): ")
	if err != nil {
		log.Fatal(err)
	}
	yubiID := otp[:selfhosted.PubLen]
	if exu, _ := o.y.GetDB().Get(yubiID); exu != nil {
		js, err := json.MarshalIndent(exu, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(js))
		log.Fatal("user already exists")
	}

	secret, err := gets("Enter secret for device to add: ")
	if err != nil {
		log.Fatal(err)
	}

	email, err := gets("Enter email of user to add: ")
	if err != nil {
		log.Fatal(err)
	}

	u := model.YubiUser{
		IsEnabled: true,
		Public:    yubiID,
		Secret:    model.ColumnSecret(secret),
		Email:     email,
	}
	if err = o.y.GetDB().Add(u); err != nil {
		log.Fatal(err)
	}
	o.printAllUsers()
}

// validate a Yubi key press (OTP) against known devices in the DB
func (o *OpStr) validate() {
	otp, err := gets("Enter Yubi token to verify: ")
	o.y.SetToken(otp)

	user, err := o.y.Validate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("OTP Validated: user record of device to follow")
	js, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(js))
}

func main() {
	opts := OpStr{}

	flag.StringVar(&opts.dbPath, "d", "file:///tmp/yubiuser.db", "Path to the sqlite3 DB")
	flag.BoolVar(&opts.addUser, "a", false, "Add a user (Yubi device) instead of verify OTP")
	flag.BoolVar(&opts.printUsers, "p", false, "Print all users")
	flag.Parse()

	// This will create the tables if necessary and return an object for you to use to manage self-hosted users and verify OTPs
	y, err := selfhosted.NewYubiAuth(opts.dbPath)
	if err != nil {
		log.Fatal(err)
	}
	// Specify the secret DB column encryption key for this application.
	// WARNING: Real world production code should get this value from vault, k8s secret, et.al.
	dbEncKey := "foobar"
	y.GetDB().SetSecretColumnKeyFunc(func() string {
		return dbEncKey
	})
	opts.y = y

	if opts.addUser {
		opts.addDeviceUser()
	} else if opts.printUsers {
		opts.printAllUsers()
	} else {
		opts.validate()
	}
}
