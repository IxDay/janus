package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"

	"github.com/IxDay/janus/pkg/janus"
)

func main() {
	conn, err := net.Dial("unix", os.Getenv(janus.EnvSSHAuthSock))
	if err != nil {
		log.Fatalf("failed to connect to agent: %q", err)
	}
	client, err := agent.NewClient(conn), err
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