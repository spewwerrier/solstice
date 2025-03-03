package main

import (
	"fmt"
	solstice "spewwerrier/solstice/internal"
	"spewwerrier/solstice/utils"
	"sync"
)

func main() {
	serv := solstice.Server{}
	xdp := solstice.InitXDP()

	var wg sync.WaitGroup
	solstice.FilterMaps(xdp.Objs)

	wg.Add(4)

	go func() {
		defer wg.Done()
		xdp.ListenBlocked()
	}()

	go func() {
		defer wg.Done()
		xdp.ListenLogs()
	}()

	go func() {
		// for v := range ipaddr {
		// fmt.Println(utils.ParseIpAddr(v))
		// }
	}()

	go func() {
		for v := range solstice.BlockedIpaddrChan {
			fmt.Println(utils.ParseIpAddr(v))
		}
	}()

	serv.Start()

	wg.Wait()
}
