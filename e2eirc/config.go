package e2eirc

import "flag"

type config struct {
	ircPort int
	ircHost string

	localPort int
	localHost string

	keyPassword string
	dirPath     string
}

var sharedConfig config

// ParseFlags populates the shared configuration from the command line.
func ParseFlags() {
	flag.IntVar(&sharedConfig.ircPort, "port", 6667, "The port of the remote IRC server")
	flag.StringVar(&sharedConfig.ircHost, "host", "127.0.0.1", "The host of the remote IRC server")

	flag.IntVar(&sharedConfig.localPort, "local_port", 6666, "The local port your IRC client connects to")
	flag.StringVar(&sharedConfig.localHost, "local_host", "127.0.0.1", "The local address to listen on")

	flag.StringVar(&sharedConfig.keyPassword, "key", "", "The password protecting your identity key (visible to other local users via the process list; leave blank to be prompted)")
	flag.StringVar(&sharedConfig.dirPath, "dir", "", "The directory containing your identity key and trusted keys, leave blank for ~/.e2eirc")

	flag.Parse()
}
