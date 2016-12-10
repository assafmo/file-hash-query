package main

import "net/http"
import "log"

import "encoding/json"

func main() {
	http.Handle("/", http.FileServer(http.Dir("static")))
	http.HandleFunc("/search", search)
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

func search(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sha256 := req.URL.Query().Get("sha256")
	rep, err := virustotal{}.CheckSHA256(sha256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.MarshalIndent(rep, "", "\t")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
