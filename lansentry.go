package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
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
	connStr := "postgres://lansentry:3WKbnuzBEgM7ysuYVg68ogwMvcf7zfRu@localhost/lansentry"
	db, err := sql.Open("postgres", connStr)
	//db, err := sql.Open("mysql", "lansentry:3WKbnuzBEgM7ysuYVg68ogwMvcf7zfRu@10.20.1.102/lansentry")
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	return db
}

func write_new_hosts(db *sql.DB, data host_obj) {
	query := "insert into hosts(ip, mac, vendor, isknown, isGuest) values(?, ?, ?, ?, ?)"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query(query, data.ip, data.mac, data.vendor, data.isknown, data.isGuest)
	stmt.Close()
}

func db_maccheck(db *sql.DB, data host_obj) host_obj {
	query := "select mac, ip from hosts where mac = ?"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	row := stmt.QueryRow(query, data.mac)

	var ret_val host_obj
	err = row.Scan(&ret_val.mac, &ret_val.ip)
	if err != sql.ErrNoRows {
		update_ips(db, ret_val, data)
		return data
	}
	if err != nil {
		panic(err)
	}
	stmt.Close()
	return ret_val

}

func update_ips(db *sql.DB, data host_obj, arp_data host_obj) {
	query := "update hosts set ip = ? where mac = ?"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query(query, arp_data.ip, data.mac)
	stmt.Close()
}

func db_get_foriegn_boxen(db *sql.DB) []host_obj {
	query := "select ip from hosts where isknown = 0 and isGuest = 0"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	rows, err := stmt.Query(query)
	if err != nil {
		panic(err)
	}
	var ret_val []host_obj
	for rows.Next() {
		var data host_obj
		err = rows.Scan(&data.ip)
		if err != nil {
			panic(err)
		}
		mark_foriegn_as_guest(db, data)
		ret_val = append(ret_val, data)
	}
	return ret_val
}

func mark_foriegn_as_guest(db *sql.DB, data host_obj) {
	query := "update hosts set isGuest = 1 where ip = ?"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query(query, data.ip)
	stmt.Close()
}

func alert_on_bad_boxen(data []host_obj) {
	//
}

func purge_bad_boxen(db *sql.DB) {
	query := "delete from hosts where isGuest = 1"
	stmt, _ := db.Prepare(query)
	stmt.Query(query)
}

func main() {
	connection := db_init()
	if time.Now().Hour() == 13 && time.Now().Minute() == 7 {
		purge_bad_boxen(connection)
	}
	data := arpscan("wlp170s0")
	for i := 0; i < len(data); i++ {
		if db_maccheck(connection, data[i]).ip == "" {
			write_new_hosts(connection, data[i])
		}
	}
	bad_boxen := db_get_foriegn_boxen(connection)
	alert_on_bad_boxen(bad_boxen)
	connection.Close()
	time.Sleep(60)
}
