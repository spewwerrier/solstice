package main

import (
	solstice "spewwerrier/solstice/internal"
	"spewwerrier/solstice/utils"
	"sync"
)

func main() {
	serv := solstice.Server{}
	block := solstice.InitBlockXDP()

	ipaddr := make(chan []byte, 10)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		block.ListenBlocked(ipaddr)
	}()

	go func() {
		defer wg.Done()
		for data := range ipaddr {
			utils.ParseIpAddr(data)
		}
	}()

	serv.Start()

	wg.Wait()
}
