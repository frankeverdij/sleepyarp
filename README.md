Sleepyarp
=========
Sleepyarp is a Linux ARP broadcast answering program or daemon which is installed on an always-on server, and will reply on behalf of dormant servers in the local subnet whose entries have expired in the ARP table.

This allows clients to wake and contact a dormant server, f.i. for connecting to a service or for shell access.

This project is inspired by the friendly-neighbour service by Daniel Gross and his excellent blog post explaining all the details.

I opted for a more minimal approach using C and systemd to make it 'just work' for use with Debian or RedHat systems.

How it works
------------
A client which needs to connect to a dormant server will first send an ARP broadcast message asking who has the MAC address for that dormant server.
However, ARP entries are stored in a table in memory and that server entry will expire after four hours if not refreshed. Dormant server MAC addresses can be added permanently to an ARP entry list but this will only work for that specific host.

Instead, the sleepyarp daemon will reply to the client pretending it is the dormant server and will provide the sought MAC address. The client can then build and send a unicast IP packet with the correct MAC address and if the dormant server is configured to perform wake-on-unicast the server will wake up.

The file `/etc/ethers` will be used to match MAC addresses to IP addresses. See `man 5 ethers` for a brief explanation of the format.

Build
-----
There are only a few requirements for a build:
- A Linux system
- gcc
- libpcap development package (libraries and headers)

The build is then straightforward by issuing `make`.

The program can be run standalone, but a systemd service file is included and can be installed using `sudo make install` which will install the program in `/usr/local/sbin` and the systemd service file in `/usr/lib/systemd/system`.

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sleepyarp.service
sudo systemctl start sleepyarp.service
```
...will run the service.
