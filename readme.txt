Solstice is a kernel level packet filter done using xdp.

Client program (currently in go) can edit the ip that are to be blocked by xdp.
Both ipv4 and ipv6 ip are supported and can be edited in runtime without restarting
any services.

Running Solstice
---------------
go generate ./... && go build -o solstice cmd/main.go && sudo ./solstice;

To edit the ip filter list on runtime, you can find the ip using
dig AAA +short website.com (ivp4)
dig AAAA +short website.com (ipv6)
and its related int conversion at http://localhost:3000/logs

Example
-------
To block luitelaagaman.com.np (ipv6)
curl -X POST http://localhost:3000/savefilter -d high=2739955489435877376 -d low=1746215171
These high/low digits are beside the ipv6 in logs page

To block github.con (ipv4)
curl -X POST http://localhost:3000/savefilter -d ipv4=2800995604
curl -X POST http://localhost:3000/savefilter -d ipv4=1380568852

Future plans for this project are
- attack prevention like ddos and filtering based on protocol
