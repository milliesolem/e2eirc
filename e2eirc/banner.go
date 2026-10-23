package e2eirc

import (
	"fmt"
	"strings"
)

const version = "0.2.0-Beta"

// PrintBanner prints the logo, version and beta warning.
func PrintBanner() {
	fmt.Print(`
███████╗██████╗ ███████╗██╗██████╗  ██████╗
██╔════╝╚════██╗██╔════╝██║██╔══██╗██╔════╝
█████╗   █████╔╝█████╗  ██║██████╔╝██║
██╔══╝  ██╔═══╝ ██╔══╝  ██║██╔══██╗██║
███████╗███████╗███████╗██║██║  ██║╚██████╗
╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝
`)
	fmt.Println("Version: " + version)

	if strings.HasSuffix(version, "Beta") {
		fmt.Print(`
WARNING: YOU ARE ON A BETA RELEASE!
THE PURPOSE OF THIS RELEASE IS FOR EVALUATION,
SECURITY RESEARCH, AND DEVELOPMENT! THE SECURITY
OF THIS RELEASE IS NOT GUARANTEED IN ANY WAY.
DO NOT USE THIS VERSION FOR MISSION CRITICAL
COMMUNICATIONS. YOU MAY NOT BE SAFE.
`)
	}
}
