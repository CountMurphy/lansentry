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

def db_read(connection):
    with connection:
        with connection.cursor() as cursor:
            sql = "select count(*) from hosts"
            cursor.execute(sql)
            print(cursor.fetchone())

if __name__ == "__main__":
    connection = db_init()
    db_read(connection)
    data = arpscan(sys.argv[1])
