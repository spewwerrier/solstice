package solstice

import (
	"database/sql"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	_ "github.com/mattn/go-sqlite3"
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

func AppendIpv4(objs *packetObjects, ipv4 uint32) {
	err := objs.BlacklistIpv4.Update(ipv4, true, ebpf.UpdateNoExist)
	if err != nil {
		// log.Fatal("cannot append ipv4 to the blacklist: ", err)
	}
}

func AppendIpv6(objs *packetObjects, ipv6 packetIpv6Addr) {
	err := objs.BlacklistIpv6.Update(ipv6, true, ebpf.UpdateNoExist)
	if err != nil {
		// log.Fatal("cannot append ipv6 to the blacklist: ", err)
	}
}

func FilterMaps(objs *packetObjects) {
	db, err := sql.Open("sqlite3", "./solstice.db")
	if err != nil {
		log.Panic("cannot open db to read initial filters:", err)
	}
	rows, err := db.Query("select ip from filter_ipv4")
	if err != nil && err != sql.ErrNoRows {
		log.Panic("failed to read ipv4")
	}
	var db_ipv4 uint32
	for rows.Next() {
		rows.Scan(&db_ipv4)
		err := objs.BlacklistIpv4.Update(db_ipv4, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv4: ", err)
		}
		log.Println(db_ipv4)
	}
	var ipv4 []uint32 = []uint32{
		// ip of github.com hardcoded
		// 2800995604,
		// 1380568852,

		// 2226068441,

		// ip of wikipedia.com
		// 3802556007,
		// 3769001575,
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

	rows_6, err := db.Query("select high, low from filter_ipv6")
	if err != nil && err != sql.ErrNoRows {
		log.Panic("failed to read ipv6: ", err)
	}
	var db_ipv6 packetIpv6Addr

	for rows_6.Next() {
		rows_6.Scan(&db_ipv6.High, &db_ipv6.Low)
		err := objs.BlacklistIpv6.Update(db_ipv6, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv4: ", err)
		}
		log.Println(db_ipv6)
	}

	// ip of wikipedia.com hardcoded
	var ipv6 []packetIpv6Addr = []packetIpv6Addr{

		// 2306129364758298897
		// 1
		// {
		// 	High: 2306139821065694490,
		// 	Low:  3,
		// },
		// {
		// 	High: 2306139821065694490,
		// 	Low:  1,
		// },
	}

	for _, ips := range ipv6 {
		err := objs.BlacklistIpv6.Update(ips, true, ebpf.UpdateAny)
		if err != nil {
			log.Fatal("cannot update blacklist ipv6: ", err)
		}

	}
}
