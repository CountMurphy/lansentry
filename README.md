# lansentry

Monitor lan for new devices and alert over ntfy. To view active devies in the network, you must manually query the lansentry database:
```
select * from hosts;
```
From here you can manually add notes to the device, or mark it as is known to prevent future notifications. Devices marked as isguest will be alerted on once a day until they either disconnect, or are marked as owned.

## Requirements
- arp-scan
- postgresql
- ntfy end-point
