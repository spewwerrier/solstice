package solstice

import (
	"log"
	"net"
	solstice "spewwerrier/solstice/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ipdata is a channel that recevies data and puts the value in sequelite
func ListenBlocked() {

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

	link, err := link.AttachXDP(
		link.XDPOptions{
			Program:   objs.PacketFilter,
			Interface: iface.Index,
		},
	)
	if err != nil {
		log.Fatal("Failed attaching xdp: ", err)
	}
	defer link.Close()

	// ipblocked is a ringbuffer that gives the blocked ip address
	rb, err := ringbuf.NewReader(objs.IpBlocked)
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
		err = objs.BlacklistIpv4.Update(ips, true, ebpf.UpdateAny)
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
		err = objs.BlacklistIpv6.Update(ips, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv6: ", err)
		}

	}

	// db, err := sql.Open("sqlite3", "./logs.db")
	// if err != nil {
	// 	log.Fatal("Failed opening sqlite: ", err)
	// }
	// defer db.Close()

	// stmt := `insert into `

	for {
		record, err := rb.Read()
		if err != nil {
			log.Fatal("Failed reading from reader: ", err)
		}
		data := record.RawSample
		solstice.ParseIpAddr(data)
		// ipdata <- record.RawSample

		// if len(data) == 4 {

		// data := binary.LittleEndian.Uint32(record.RawSample)

		// log.Printf("Blocking Ipv4\t Ipv4: %d.%d.%d.%d\t RawInt: %d",
		// 	((data >> 0) & 0xFF),
		// 	((data >> 8) & 0xFF),
		// 	((data >> 16) & 0xFF),
		// 	((data >> 24) & 0xFF),
		// 	data,
		// )

		// } else {
		// var ip = net.IP(data)

		// ipv6Bytes := ip.To16()

		// high := binary.BigEndian.Uint64(ipv6Bytes[:8])
		// low := binary.BigEndian.Uint64(ipv6Bytes[8:])

		// log.Printf("Blocking IPv6\t Ipv6: %s\t RawInt: %d %d\n", ip, high, low)

		// }

	}
}
