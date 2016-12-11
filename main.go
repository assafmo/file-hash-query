package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"regexp"
)

func main() {
	sha256 := flag.String("sha256", "", "sha256 of a file")
	flag.Parse()

	sha256Regex := regexp.MustCompile("^[a-fA-F0-9]{64}$")

	if !sha256Regex.MatchString(*sha256) {
		log.Fatalln("Cannot match sha256 with regex ^[a-fA-F0-9]{64}$")
	}

	result, _ := virustotal{}.CheckSHA256(*sha256)
	resultJSON, _ := json.MarshalIndent(result, "", "\t")
	fmt.Println(string(resultJSON))
}
