package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"

	"strings"

	"encoding/json"

	"gopkg.in/xmlpath.v2"
)

func main() {
	sha256 := flag.String("sha256", "", "sha256 hash of a file")
	flag.Parse()

	sha256Regex := regexp.MustCompile("^[a-fA-F0-9]{64}$")

	if !sha256Regex.MatchString(*sha256) {
		log.Fatalln("cannot match sha256 with regex ^[a-fA-F0-9]{64}$")
	}

	result, _ := virustotal(*sha256)
	resultJSON, _ := json.MarshalIndent(result, "", "\t")
	fmt.Println(string(resultJSON))
}

type reputation struct {
	Bad, Good, Known, Unknown bool
	Confidence                float64
	Date, Source              string
}

func virustotal(sha256 string) (reputation, error) {
	url := fmt.Sprintf("https://www.virustotal.com/en/file/%s/analysis/", sha256)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return reputation{}, err
	}

	request.Header.Set("user-agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Mobile Safari/537.36")
	request.Header.Set("referer", "https://google.com/")
	request.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Header.Set("accept-language", "en-US,en;q=0.8,he;q=0.6")
	request.Header.Set("cache-control", "max-age=0")
	request.Header.Set("dnt", "1")
	request.Header.Set("upgrade-insecure-requests", "1")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return reputation{}, err
	}

	xmlRoot, err := xmlpath.ParseHTML(response.Body)
	defer response.Body.Close()
	if err != nil {
		return reputation{}, err
	}

	scoreXPath := xmlpath.MustCompile(`//*[@id="basic-info"]/div/div[1]/table/tbody/tr[3]/td[2]`)
	dateXPath := xmlpath.MustCompile(`//*[@id="basic-info"]/div/div[1]/table/tbody/tr[4]/td[2]`)
	score, okScore := scoreXPath.String(xmlRoot)
	date, okDate := dateXPath.String(xmlRoot)
	if !okDate || !okScore {
		return reputation{}, fmt.Errorf("Not found on VirusTotal")
	}

	date = strings.Trim(date, " \n")[:19]

	score = strings.Replace(strings.Trim(score, " \n"), " ", "", -1)
	scoreSplited := strings.Split(score, "/")
	if len(scoreSplited) != 2 {
		return reputation{Known: true, Confidence: 0.5, Date: date, Source: "VirusTotal"}, fmt.Errorf("Error parsing score")
	}

	detectedStr, totalStr := scoreSplited[0], scoreSplited[1]
	detected, err := strconv.Atoi(detectedStr)
	if err != nil {
		return reputation{Known: true, Confidence: 0.5, Date: date, Source: "VirusTotal"}, fmt.Errorf("Error parsing score")
	}

	if detected == 0 {
		return reputation{
			Good:       true,
			Confidence: 1,
			Date:       date,
			Source:     "VirusTotal"}, nil
	}

	total, err := strconv.Atoi(totalStr)
	if err != nil {
		return reputation{Known: true, Confidence: 0.5, Date: date, Source: "VirusTotal"}, fmt.Errorf("Error parsing score")
	}

	return reputation{
		Bad:        true,
		Confidence: float64(detected) / float64(total),
		Date:       date,
		Source:     "VirusTotal"}, nil

}
