package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	xmlpath "gopkg.in/xmlpath.v2"
)

type virustotal struct{}

var (
	scoreXPath = xmlpath.MustCompile(`//*[@id="basic-info"]/div/div[1]/table/tbody/tr[3]/td[2]`)
	dateXPath  = xmlpath.MustCompile(`//*[@id="basic-info"]/div/div[1]/table/tbody/tr[4]/td[2]`)
)

func (vt virustotal) CheckSHA256(sha256 string) (reputation, error) {
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

	score, okScore := scoreXPath.String(xmlRoot)
	date, okDate := dateXPath.String(xmlRoot)
	if !okDate || !okScore {
		return reputation{
			Unknown:    true,
			Confidence: 1,
			Source:     "VirusTotal"}, nil
	}

	date = strings.Trim(date, " \n")[:19]

	score = strings.Replace(strings.Trim(score, " \n"), " ", "", -1)
	scoreSplited := strings.Split(score, "/")
	if len(scoreSplited) != 2 {
		return reputation{
			Known:  true,
			Date:   date,
			Source: "VirusTotal"}, fmt.Errorf("Error parsing score")
	}

	detectedStr, totalStr := scoreSplited[0], scoreSplited[1]
	detected, err := strconv.Atoi(detectedStr)
	if err != nil {
		return reputation{
			Known:  true,
			Date:   date,
			Source: "VirusTotal"}, fmt.Errorf("Error parsing score")
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
		return reputation{
			Known:  true,
			Date:   date,
			Source: "VirusTotal"}, fmt.Errorf("Error parsing score")
	}

	return reputation{
		Bad:        true,
		Confidence: float64(detected) / float64(total),
		Date:       date,
		Source:     "VirusTotal"}, nil
}
