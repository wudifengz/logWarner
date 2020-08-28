package main

import (
	"log"
	"net"
)

type IPChecker struct {
	IPNets map[string][]*net.IPNet
}

func (ipch *IPChecker) init() {
	ipch.IPNets = map[string][]*net.IPNet{}
	netArea := map[string][]string{}
	for name, nets := range netArea {
		for _, netString := range nets {
			_, ipnet, err := net.ParseCIDR(netString)
			if err != nil {
				log.Fatal(err)
			}
			ipch.IPNets[name] = append(ipch.IPNets[name], ipnet)
		}
	}
}
func (ipch *IPChecker) checkIP(ipString string) string {
	ip := net.ParseIP(ipString)
	for name, nets := range ipch.IPNets {
		for _, ipnet := range nets {
			if ipnet.Contains(ip) {
				return name
			}
		}
	}
	return "省外"
}
