package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)

func ParseIpAddr(data []byte) string {
	if len(data) == 8 {
		data_u32 := binary.LittleEndian.Uint32(data)
		packetSize := binary.LittleEndian.Uint32(data[4:])

		str := fmt.Sprintf("Blocking Ipv4\t %d.%d.%d.%d\t RawInt: %d\t PacketSize: %d",
			((data_u32 >> 0) & 0xFF),
			((data_u32 >> 8) & 0xFF),
			((data_u32 >> 16) & 0xFF),
			((data_u32 >> 24) & 0xFF),
			data_u32,
			packetSize,
		)
		return str

	} else {
		var ip = net.IP(data[0:16])
		packetSize := binary.LittleEndian.Uint32(data[16:])

		ipv6Bytes := ip.To16()

		high := binary.BigEndian.Uint64(ipv6Bytes[:8])
		low := binary.BigEndian.Uint64(ipv6Bytes[8:])

		str := fmt.Sprintf("Blocking IPv6\t %s\t RawInt: %d %d\t PacketSize: %d\n", ip, high, low, packetSize)
		return str
	}

}
