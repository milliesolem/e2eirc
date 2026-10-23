package e2eirc

import (
	"fmt"
	"log"
	"net"
	"strconv"
)

func serverAddr() string {
	return net.JoinHostPort(sharedConfig.ircHost, strconv.Itoa(sharedConfig.ircPort))
}

func localAddr() string {
	return net.JoinHostPort(sharedConfig.localHost, strconv.Itoa(sharedConfig.localPort))
}

// Start listens for local IRC clients and proxies each to the IRC server.
func Start() {
	fmt.Println("Listening for your IRC client on " + localAddr())
	fmt.Println("Relaying to IRC server " + serverAddr())
	fmt.Print("\n---------------------------------------------------\n\n")

	l, err := net.Listen("tcp", localAddr())
	if err != nil {
		log.Fatalf("listen on %s: %v", localAddr(), err)
	}
	defer l.Close()

	for {
		client, err := l.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go serveClient(client)
	}
}

func serveClient(client net.Conn) {
	server, err := net.Dial("tcp", serverAddr())
	if err != nil {
		log.Printf("connect to IRC server %s: %v", serverAddr(), err)
		client.Close()
		return
	}
	newConnection(client, server).run()
}
