Find WLAN clients and ethernet LAN stations behind access point through MAC address disclosure in multicast packets.
```
usage: multicast-sniffer.py [-h] -i IFACE [-b BSSID] [-f FILE] [-c CHANNEL]
                            [-t TIMEOUT]

WLAN multicast sniffer. Find WLAN clients and ethernet LAN stations behind
access point through MAC address diclosure in multicast packets. Press Ctrl+C
to exit.

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        WLAN interface in monitor mode
  -b BSSID, --bssid BSSID
                        Display MACs for the selected BSSID
  -f FILE, --file FILE  Output file to store found MACs
  -c CHANNEL, --channel CHANNEL
                        Set channel
  -t TIMEOUT, --timeout TIMEOUT
                        Set timeout to quit
  -j JSON, --json JSON  Output file name in JSON format

```
Example output:
![Example output](Screenshot.jpg?raw=true "Example output")

Also you can scan all available channels with something like this:
```
iwlist wlan0mon channel | sudo gawk 'match($0, /Channel ([0-9]+) : /, m) { system("python3 multicast-sniffer.py -i wlan0mon -t 1200 -c "m[1]" -f "m[1]".txt"); }'
```