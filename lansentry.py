#! /usr/bin/python

import sys
import subprocess
import requests
import json
import pymysql.cursors
import time
from datetime import datetime

def arpscan(iface):
    output = subprocess.run(["arp-scan", "-glNx", "-I", iface], capture_output = True)
    retdata = []
    for machine in str(output.stdout).replace("b'","").split("\\n"):
        machine_array = machine.split("\\t")
        if len(machine_array) < 3:
            continue
        json_obj = json.loads('{"ip": "' + machine_array[0] + '", "mac": "' + machine_array[1] + '", "vendor": "' + machine_array[2] +'"}')
        retdata.append(json_obj)
    return retdata

def db_init():
    connection = pymysql.connect(host='localhost',
                             user='lansentry',
                             password='3WKbnuzBEgM7ysuYVg68ogwMvcf7zfRu',
                             database='lansentry',
                             cursorclass=pymysql.cursors.DictCursor)
    return connection

def write_new_hosts(connection, data):
    sql = "insert into hosts(ip, mac, vendor, isknown, isGuest) values(%s, %s, %s, %s, %s)"
    with connection.cursor() as cursor:
        cursor.execute(sql, (data["ip"], data["mac"], data["vendor"], 0, 0))
    connection.commit()

def db_maccheck(connection, data):
    with connection.cursor() as cursor:
        sql = "select count(*) from hosts where mac = %s"
        cursor.execute(sql, (data["mac"]))
        result = cursor.fetchone()
        if result["count(*)"] == 0:
            return data
    return None

def db_get_foriegn_boxen(connection):
    with connection.cursor() as cursor:
        sql = "select ip from hosts where isknown = 0 and isGuest = 0"
        cursor.execute(sql)
        result = cursor.fetchall()
        mark_foriegn_as_guest(result)
        return result

def mark_foriegn_as_guest(data):
    with connection.cursor() as cursor:
        for line in data:
            sql = "update hosts set isGuest = 1 where ip = %s"
            cursor.execute(sql, line["ip"])
        connection.commit()

def alert_on_bad_boxen(data):
    creds = open("/Raid/homes/sarif/beacon.txt","r")
    credArray = creds.read().split(":")
    for line in data:
        r = requests.put("http://localhost:8082/harbinger", data = ("Unknown host:" + line["ip"]), headers={"Tag":"biohazard","prio":"high"}, auth=(credArray[0],credArray[1].strip()))


def purge_bad_boxen():
    with connection.cursor() as cursor:
        sql = "delete from hosts where isGuest = 1"
        cursor.execute(sql)
        connection.commit()


if __name__ == "__main__":
    while(True):
        connection = db_init()
        # purge guest boxen at midnight
        if datetime.now().hour == 13 and datetime.now().minute == 7:
            purge_bad_boxen()
        data = arpscan(sys.argv[1])
        #insert into db if not tracked
        for line in data:
            if db_maccheck(connection, line) is not None:
                write_new_hosts(connection, line)

        bad_boxen = db_get_foriegn_boxen(connection)
        alert_on_bad_boxen(bad_boxen)
        connection.close()
        time.sleep(60)
