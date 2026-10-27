# lansentry

Monitor lan for new devices and alert over apprise. Lansentry was born of the need/want to monitor networks looking for unknown devices and systems that may have hacked the WIFI.

To view active devices in the network, you must manually query the lansentry database:
```
select * from hosts order by id;
```
From here you can manually add notes to the device, or mark it as is known to prevent future notifications. Devices marked as isguest will be alerted on once a day until they either disconnect, or are marked as owned.

## Requirements
- nmap
- postgresql
- apprise end-point (tested with ntfy)

Lansentry needs to run as root because of nmap requirements.

## FAQ
- How long does lansentry take to alert on new devices?
    - about a minute
- Will you make a GUI interface?
    - No, get gud squid
- Will you make command line arguments to manage lan assets?
    - No, get gud squid
