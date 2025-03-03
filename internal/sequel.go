package solstice

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type Sequel struct {
	db *sql.DB
}

func InitSqlite() *Sequel {
	dba, err := sql.Open("sqlite3", "./solstice.db")
	if err != nil {
		log.Fatal(err)
	}
	// defer db.Close()

	// https://pkg.go.dev/github.com/mattn/go-sqlite3#hdr-Supported_Types
	sqlStmt := `
	create table if not exists filter_ipv4(id integer not null primary key, ip integer);
	create table if not exists filter_ipv6(id integer not null primary key, high integer, low integer);
	`
	_, err = dba.Exec(sqlStmt)
	if err != nil {
		log.Fatal("%q: %s\n", err, sqlStmt)
		return &Sequel{}
	}
	return &Sequel{
		db: dba,
	}

}

func (s *Sequel) DbAppendIpv4(ipv4 uint32) {
	stmt := fmt.Sprintf("insert into filter_ipv4 (ip) values (%d)", ipv4)
	_, err := s.db.Exec(stmt)
	if err != nil {
		log.Panic("failed to insert into ipv4", err)
	}
}

func (s *Sequel) DbAppendIpv6(ipv6 packetIpv6Addr) {
	stmt := fmt.Sprintf("insert into filter_ipv6 (high, low) values (%d, %d)", ipv6.High, ipv6.Low)
	_, err := s.db.Exec(stmt)
	if err != nil {
		log.Panic("failed to insert into ipv6", err)
	}
}
