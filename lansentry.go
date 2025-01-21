package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type host_obj struct {
	ip      string
	mac     string
	vendor  string
	isknown bool
	isGuest bool
}

type config_obj struct {
	postgres   string
	ntfy_creds string
	ntfy_link  string
}

var config config_obj

func parse_config() {
	settings, err := os.ReadFile("/etc/lansentry/app.conf")
	if err != nil {
		fmt.Println("Can't read config file")
		panic(err)
	}
	settings_array := strings.Split(strings.TrimSpace(string(settings)), "\n")
	config_map := make(map[string]string)
	for i := 0; i < len(settings_array); i++ {
		keyvalue := strings.Split(settings_array[i], "=")
		config_map[keyvalue[0]] = keyvalue[1]
	}
	if config_map["postgres_ssl"] == "false" {
		config.postgres = config_map["postgres"] + "?sslmode=disable"
	} else {
		config.postgres = config_map["postgres"]
	}
	config.ntfy_link = config_map["ntfy"]
	config.ntfy_creds = config_map["ntfy_creds"]
}

func create_table(db *sql.DB) {
	query := "CREATE TABLE hosts ( id SERIAL PRIMARY KEY, ip VARCHAR(45), mac VARCHAR(100), vendor VARCHAR(100), isknown BOOLEAN, Notes VARCHAR(500), isGuest BOOLEAN);"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query()
	stmt.Close()
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
	connStr := config.postgres
	db, err := sql.Open("postgres", connStr)
	//db, err := sql.Open("mysql", "lansentry:3WKbnuzBEgM7ysuYVg68ogwMvcf7zfRu@10.20.1.102/lansentry")
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	return db
}

func write_new_hosts(db *sql.DB, data host_obj) {
	query := "insert into hosts(ip, mac, vendor, isknown, isGuest) values($1, $2, $3, $4, $5)"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query(data.ip, data.mac, data.vendor, data.isknown, data.isGuest)
	stmt.Close()
}

func db_maccheck(db *sql.DB, data host_obj) host_obj {
	query := "select mac, ip from hosts where mac = $1"
	stmt, err := db.Prepare(query)
	// needs both checks or will seg fault trying to get error message
	if err != nil && err.Error() == "pq: relation \"hosts\" does not exist" {
		create_table(db)
		return db_maccheck(db, data)
	}
	if err != nil {
		panic(err)
	}
	row := stmt.QueryRow(data.mac)

	var ret_val host_obj
	err = row.Scan(&ret_val.mac, &ret_val.ip)
	if err != sql.ErrNoRows {
		update_ips(db, ret_val, data)
		return data
	}
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	stmt.Close()
	return ret_val

}

func update_ips(db *sql.DB, data host_obj, arp_data host_obj) {
	query := "update hosts set ip = $1 where mac = $2"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query(arp_data.ip, data.mac)
	stmt.Close()
}

func db_get_foriegn_boxen(db *sql.DB) []host_obj {
	query := "select ip from hosts where isknown = false and isGuest = false"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	rows, err := stmt.Query()
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
	query := "update hosts set isGuest = true where ip = $1"
	stmt, err := db.Prepare(query)
	if err != nil {
		panic(err)
	}
	stmt.Query(data.ip)
	stmt.Close()
}

func alert_on_bad_boxen(data []host_obj) {
	credArray := strings.Split(string(config.ntfy_creds), ":")
	for i := 0; i < len(data); i++ {
		client := &http.Client{}
		data := "Unkown host:" + data[i].ip
		req, err := http.NewRequest(http.MethodPut, config.ntfy_link, strings.NewReader(data))
		if err != nil {
			panic(err)
		}
		req.SetBasicAuth(credArray[0], strings.TrimSpace(credArray[1]))
		req.Header.Add("Tag", "biohazard")
		req.Header.Add("prio", "high")
		client.Do(req)
	}
}

func purge_bad_boxen(db *sql.DB) {
	query := "delete from hosts where isGuest = true"
	stmt, _ := db.Prepare(query)
	stmt.Query()
}

func main() {
	parse_config()
	for {
		connection := db_init()
		if time.Now().Hour() == 13 && time.Now().Minute() == 7 {
			purge_bad_boxen(connection)
		}
		data := arpscan(os.Args[1])
		for i := 0; i < len(data); i++ {
			if db_maccheck(connection, data[i]).ip == "" {
				write_new_hosts(connection, data[i])
			}
		}
		bad_boxen := db_get_foriegn_boxen(connection)
		alert_on_bad_boxen(bad_boxen)
		connection.Close()
		time.Sleep(60 * time.Second)
	}
}
