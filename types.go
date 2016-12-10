package main

type source interface {
	CheckSHA256(string) (reputation, error)
}

type reputation struct {
	Source                    string
	Good, Bad, Known, Unknown bool
	Confidence                float64
	Date                      string
}
