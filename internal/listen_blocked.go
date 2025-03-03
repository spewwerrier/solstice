package solstice

import (
	"log"

	"github.com/cilium/ebpf/ringbuf"
)

func (b *XDP) ListenBlocked() {

	// ipblocked is a ringbuffer that gives the blocked ip address
	rb, err := ringbuf.NewReader(b.Objs.IpBlocked)
	if err != nil {
		log.Fatal("opening ringbuffer: ", err)
	}
	defer rb.Close()
	log.Println("reading blocked ip")
	for {
		record, err := rb.Read()
		if err != nil {
			log.Fatal("Failed reading from reader: ", err)
		}
		data := record.RawSample
		BlockedIpaddrChan <- data

	}
}
