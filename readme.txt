Solstice is a kernel level packet filter done using xdp.

Client program (currently in go) can edit the ip that are to be blocked by xdp.
Both ipv4 and ipv6 ip are supported and can be edited in runtime without restarting
any services.

Running Solstice
go generate && go build && sudo ./solstice

Future plans for this project are
- runtime editable interfaces (currently ip are hardcoded but updated on runtime)
- a web ui dashboard (packet size, source and throughput: +total count)
- attack prevention like ddos and filtering based on protocol

