package main

import (
	"log"
	solstice "spewwerrier/solstice/internal"
	"sync"
)

func main() {
	v := solstice.Server{}

	ip := make(chan []byte, 1024)
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		solstice.ListenBlocked()
	}()

	go func() {
		for ipaddr := range ip {
			v.Ipdata = ipaddr
			log.Printf("Blocked IP: %v\n", ipaddr)
		}
		defer wg.Done()
	}()
	v.Start()

	wg.Wait()
}
