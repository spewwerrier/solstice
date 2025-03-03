package solstice

import (
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type XDP struct {
	Objs *packetObjects
}

func InitXDP() *XDP {
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

	block := &XDP{
		Objs: &objs,
	}
	return block

}
func FilterMaps(objs *packetObjects) {
	var ipv4 []uint32 = []uint32{
		// ip of github.com hardcoded
		2800995604,

		2226068441,

		// ip of wikipedia.com
		3802556007,
		3769001575,
	}
	for _, ips := range ipv4 {
		err := objs.BlacklistIpv4.Update(ips, true, ebpf.UpdateAny)
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
		err := objs.BlacklistIpv6.Update(ips, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv6: ", err)
		}

	}
}
