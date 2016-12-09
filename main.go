package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"

	"encoding/json"
)

func main() {
	sha256 := flag.String("sha256", "", "sha256 hash of a file")
	flag.Parse()

	sha256Regex := regexp.MustCompile("^[a-fA-F0-9]{64}$")

	if !sha256Regex.MatchString(*sha256) {
		log.Fatalln("Cannot match sha256 with regex ^[a-fA-F0-9]{64}$")
	}

	result, err := virustotal{}.CheckSHA256(*sha256)
	if err != nil {
		log.Fatal(err)
	}

	resultJSON, _ := json.MarshalIndent(result, "", "\t")
	fmt.Println(string(resultJSON))
}

type source interface {
	CheckSHA256(string) (reputation, error)
}

type reputation struct {
	Source                    string
	Good, Bad, Known, Unknown bool
	Confidence                float64
	Date                      string
}
