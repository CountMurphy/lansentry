package main

import (
	"fmt"
	"os/exec"
)

func arpscan(iface string) {
	output, err := exec.Command("arp-scan", "-glNx", "-I", iface).Output()
	if err != nil {
		fmt.Println("wtf")
		fmt.Println(err)
	} else {
		fmt.Println(string(output))
	}
}

func main() {
	arpscan("wlp170s0")
}
