import sys
import subprocess
import requests
import json
import pymysql.cursors

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
    sql = "insert into hosts(ip, mac, vendor, isknown) values(%s, %s, %s, %s)"
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, (data["ip"], data["mac"], data["vendor"], 0))
        connection.commit()

def db_maccheck(connection, data):
    with connection:
        with connection.cursor() as cursor:
            sql = "select count(*) from hosts where mac = %s"
            cursor.execute(sql, (data["mac"]))
            result = cursor.fetchone()
            if result["count(*)"] == 0:
                return data
    return None

def db_get_foriegn_boxen(connection):
    with connection:
        with connection.cursor() as cursor:
            sql = "select ip from hosts where isknown = 0"
            cursor.execute(sql)
            result = cursor.fetchall()
            return result

if __name__ == "__main__":
    data = arpscan(sys.argv[1])
    #insert into db if not tracked
    for line in data:
        connection = db_init()
        if db_maccheck(connection, line) is not None:
            connection = db_init()
            write_new_hosts(connection, line)

    connection = db_init()
    db_get_foriegn_boxen(connection)
