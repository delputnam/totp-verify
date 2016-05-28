package main

import (
	"encoding/base32"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/hgfischer/go-otp"
)

var (
	token    string
	secret   string
	isBase32 bool
	length   uint
	period   uint
	counter  uint64
)

func main() {
	flag.StringVar(&token, "token", "", "totp token to verify")
	flag.StringVar(&secret, "secret", "", "Secret key")
	flag.BoolVar(&isBase32, "base32", true, "If true, the secret is interpreted as a Base32 string")
	flag.UintVar(&length, "length", otp.DefaultLength, "OTP length")
	flag.UintVar(&period, "period", otp.DefaultPeriod, "Period in seconds")
	flag.Uint64Var(&counter, "counter", 0, "Counter")
	flag.Parse()

	if secret == "" {
		log.Fatal("Must provide a secret.")
	}

	key := secret
	if !isBase32 {
		key = base32.StdEncoding.EncodeToString([]byte(secret))
	}

	key = strings.ToUpper(key)

	if token == "" {
		log.Fatal("Must provide a token.")
	}

	totp := &otp.TOTP{
		Secret:         key,
		Length:         uint8(length),
		Period:         uint8(period),
		IsBase32Secret: true,
	}
	fmt.Println(totp.Verify(token))
}
