package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"

	"ewp-core/log"
)

func ConfigureRouting(gateway string) error {
	iface, err := net.InterfaceByName("ECH-TUN")
	if err != nil {
		log.Printf("[TUN] Get interface index failed: %v, trying direct gateway route", err)
		cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", gateway, "metric", "1")
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[TUN] Route config warning: %s (may already exist)", output)
		}
	} else {
		cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", gateway,
			"metric", "1", "if", strconv.Itoa(iface.Index))
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[TUN] Route config warning: %s (may already exist)", output)
		}
	}

	log.Printf("[TUN] Route table configured (global proxy)")
	return nil
}

func CleanupRouting(gateway string) {
	log.Printf("[TUN] Deleting routes...")
	cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", gateway)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[TUN] Route delete warning: %s", output)
	}
}

func SetInterfaceMTU(mtu int) error {
	if mtu <= 0 {
		return nil
	}

	interfaceName := "ECH-TUN"
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		interfaceName,
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set IPv4 MTU failed: %v (%s)", err, output)
	}

	cmd = exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
		interfaceName,
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent")
	_, _ = cmd.CombinedOutput()

	log.Printf("[TUN] MTU set: %d", mtu)
	return nil
}
