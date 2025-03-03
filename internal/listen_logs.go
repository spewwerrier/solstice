package solstice

import (
	"log"

	"github.com/cilium/ebpf/ringbuf"
)

func (b *XDP) ListenLogs() {

	rb, err := ringbuf.NewReader(b.Objs.IpLog)
	if err != nil {
		log.Fatal("opening ringbuffer: ", err)
	}
	defer rb.Close()
	log.Println("reading unblocked ip")
	for {
		record, err := rb.Read()
		if err != nil {
			log.Fatal("Failed reading from reader: ", err)
		}
		data := record.RawSample
		LogsIpaddrChan <- data

	}
}
