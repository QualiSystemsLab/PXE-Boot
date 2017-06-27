1. Zip the files in GenericServerDriver so they are in the root of GenericServerDriver.zip, and copy the zip to Generic Server/Resource Drivers - Python.

2. Zip the contents of Generic Server to the root of Generic Server.zip and drag Generic Server.zip into the portal.

3. Zip the contents of Example Resource Package to the root of Example Resource Package.zip and drag Example Resource Package.zip into the portal.

Create a resource of model GenericServer representing the physical machine to be PXE booted and also add a NIC subresource, which has a MAC Address attribute. The MAC is case insensitive and can have "-"" or ":". The first NIC resource will be the one used for PXE. 

Also create a resource of model PXEServer and enter the PXE appliance IP and credentials (root / qa1234). This resource will be located automatically in the domain by the GenericServer driver.

There is a function on the physical server resource that locates the PXE server and configures it for the physical server's MAC address.

The IPMI functions SSH to the PXE appliance and run ipmitool there. So the PXE machine must be able to reach the network where the IPMI interfaces are connected. IPMI programs for Windows exist but are much uglier. Similar approach with the wsman command lines. The SMASH CLP functions SSH directly to the motherboard computer of the physical server.


PXE appliance instructions:

Run /var/www/html/update-ip.sh once you know the static IP *on the PXE network* for the PXE appliance at the customer's site. This will insert the new IP in all PXE config files. It takes up to a minute.

After running the script, also edit /etc/network/interfaces to manually set the IP for the management NIC or get rid of it, depending on whether you will use separate networks for PXE and the rest of the lab. 

You may need to reboot after changing /etc/network/interfaces, or try ifdown eth0 ; ifup eth0 ; ifdown eth1 ; ifup eth1


eth0 and eth1 can randomly switch places. If the networking isn't working, that is probably what happened. You can compare the new MAC addresses in vSphere with the output of ifconfig and possibly switch eth1 and eth0 in /etc/network/interfaces.


There are multiple ways to use it the PXE server:

- Single NIC of the VM connected to the PXE network which doubles as the management network
- One NIC of the VM connected to the management network, the other to an isolated PXE network

dnsmasq is smart about this -- just set /etc/dnsmasq.conf to deal with IP addresses on the right network and it will figure out which NIC to operate on.


- Acting as the DHCP server for the PXE network -- in this case, define an IP range on the dhcp-range line in /etc/dnsmasq.conf
- Coexisting with the customer's DHCP server on the PXE network -- in this case, comment out the dhcp-range line and uncomment the dhcp-range line containing the word "proxy" in /etc/dnsmasq.conf. Reload with "service dnsmasq restart".

Apparently there can be multiple "DHCP helpers" set up on the switch. Our server can supposedly be added to the list in either mode.
