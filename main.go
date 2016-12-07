package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"strings"

	"gopkg.in/xmlpath.v2"
)

func main() {
	sha256 := flag.String("sha256", "", "sha256 hash of a file")
	flag.Parse()

	sha256Regex := regexp.MustCompile("^[a-fA-F0-9]{64}$")

	if !sha256Regex.MatchString(*sha256) {
		log.Fatalln("cannot match sha256 with regex ^[a-fA-F0-9]{64}$")
	}

	vt, err := virustotal(*sha256)

	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(vt)
}

func virustotal(sha256 string) (string, error) {
	url := fmt.Sprintf("https://www.virustotal.com/en/file/%s/analysis/", sha256)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	request.Header.Set("user-agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Mobile Safari/537.36")
	request.Header.Set("referer", "https://google.com/")
	request.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Header.Set("accept-language", "en-US,en;q=0.8,he;q=0.6")
	request.Header.Set("cache-control", "max-age=0")
	request.Header.Set("dnt", "1")
	request.Header.Set("upgrade-insecure-requests", "1")

	response, err := new(http.Client).Do(request)
	if err != nil {
		return "", err
	}

	xmlRoot, err := xmlpath.ParseHTML(response.Body)
	defer response.Body.Close()
	if err != nil {
		return "", err
	}

	scoreXPath := xmlpath.MustCompile(`//*[@id="basic-info"]/div/div[1]/table/tbody/tr[3]/td[2]`)
	dateXPath := xmlpath.MustCompile(`//*[@id="basic-info"]/div/div[1]/table/tbody/tr[4]/td[2]`)
	score, okScore := scoreXPath.String(xmlRoot)
	date, okDate := dateXPath.String(xmlRoot)

	if okDate && okScore {
		score = strings.Replace(strings.Trim(score, " \n"), " ", "", -1)
		date = strings.Trim(date, " \n")[:19]

		return fmt.Sprintf("score: %s, date: %s", score, date), nil
	}

	return "", fmt.Errorf("Not found on VirusTotal")
}
