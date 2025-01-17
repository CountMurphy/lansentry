package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"os/exec"
	"strings"
	"time"
)

type host_obj struct {
	ip      string
	mac     string
	vendor  string
	isknown bool
	isGuest bool
}

func arpscan(iface string) []host_obj {
	output, err := exec.Command("arp-scan", "-glNx", "-I", iface).Output()
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var retVal []host_obj
	hosts := strings.Split(string(output), "\n")
	for _, host := range hosts {
		machines := strings.Split(host, "\t")
		if len(machines) < 3 {
			continue
		}
		tmp_host := host_obj{ip: string(machines[0]), mac: string(machines[1]), vendor: string(machines[2])}
		retVal = append(retVal, tmp_host)
	}
	return retVal
}

func db_init() *sql.DB {
	db, err := sql.Open("mysql", "lansentry:3WKbnuzBEgM7ysuYVg68ogwMvcf7zfRu@10.20.1.102/lansentry")
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	return db
}

func write_new_hosts(db *sql.DB, data host_obj) {
	sql := "insert into hosts(ip, mac, vendor, isknown, isGuest) values(?, ?, ?, ?, ?)"
	stmt, err := db.Prepare(sql)
	if err != nil {
		panic(err)
	}
	stmt.Query(sql, data.ip, data.mac, data.vendor, data.isknown, data.isGuest)
	stmt.Close()
}

func db_maccheck(db *sql.DB, data host_obj) host_obj {
	sql := "select mac, ip from hosts where mac = ?"
	stmt, err := db.Prepare(sql)
	if err != nil {
		panic(err)
	}
	stmt.Query(sql, data.mac)
}

func main() {
	arpscan("wlp170s0")
}
