package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/IxDay/janus/pkg/janus"
)

func main() {
	client, err := janus.NewClient()
	if err != nil {
		log.Fatalf("failed to instanciate client: %q", err)
	}
	bytes, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("failed to open file: %q", err)
	}
	resp, err := client.Extension(janus.ExtensionAge, bytes)
	if err != nil {
		log.Fatalf("failed to whatever: %q", err)
	}
	fmt.Printf("%s", resp)
}
