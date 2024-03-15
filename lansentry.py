import sys
import subprocess
import requests
import json

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

if __name__ == "__main__":
    data = arpscan(sys.argv[1])
    #test line
    print(data)
