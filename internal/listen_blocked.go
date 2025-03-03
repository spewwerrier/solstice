package solstice

import (
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Block struct {
	Objs *packetObjects
}

func InitBlockXDP() *Block {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock: ", err)
	}

	var objs packetObjects
	if err := loadPacketObjects(&objs, nil); err != nil {
		log.Fatal("Loading objects: ", err)
	}
	ifname := "wlp3s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatal("Failed getting interface: ", err)
	}

	_, err = link.AttachXDP(
		link.XDPOptions{
			Program:   objs.PacketFilter,
			Interface: iface.Index,
		},
	)
	if err != nil {
		log.Fatal("Failed attaching xdp: ", err)
	}
	// defer link.Close()
	block := &Block{
		Objs: &objs,
	}
	return block

}

func (b *Block) ListenBlocked(ipbytes chan<- []byte) {

	// ipblocked is a ringbuffer that gives the blocked ip address
	rb, err := ringbuf.NewReader(b.Objs.IpBlocked)
	if err != nil {
		log.Fatal("opening ringbuffer: ", err)
	}
	defer rb.Close()
	log.Println("reading into ringbuffer")

	var ipv4 []uint32 = []uint32{
		// ip of github.com hardcoded
		2800995604,

		// ip of wikipedia.com
		3802556007,
		3769001575,
	}
	for _, ips := range ipv4 {
		err = b.Objs.BlacklistIpv4.Update(ips, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv4: ", err)
		}

	}

	type packetIpv6Addr struct {
		High uint64 `bpf:"high"`
		Low  uint64 `bpf:"low"`
	}

	// ip of wikipedia.com hardcoded
	var ipv6 []packetIpv6Addr = []packetIpv6Addr{
		{
			High: 2306139821065694490,
			Low:  3,
		},
		{
			High: 2306139821065694490,
			Low:  1,
		},
	}

	for _, ips := range ipv6 {
		err = b.Objs.BlacklistIpv6.Update(ips, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv6: ", err)
		}

	}

	for {
		record, err := rb.Read()
		if err != nil {
			log.Fatal("Failed reading from reader: ", err)
		}
		data := record.RawSample
		ipbytes <- data
		IpaddrChan <- data

	}
}
