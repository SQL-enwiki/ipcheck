# Interperting Results

## Proxycheck.io

* Api Documentation at: https://proxycheck.io/api/
* Will typically give a vanilla yes/no
** May also give a type (e.g. "VPN", "SOCKS", etc)
** May also give a port number to check

## GetIPIntel.net

* API Documentation at: https://getipintel.net/#API
* Gives a 0-100% chance of the IP in question being a proxy/VPN

## IP Quality Score

* API Documentation at: https://www.ipqualityscore.com/user/proxy-detection-api/documentation (Requires login - FREE)
* Provides an ISP Name
* Provides a yes/no: Proxy, VPN, Mobile

## IPHub

* API Documentation at: https://iphub.info/api
* Returns a "block number", or connection type.
** Block 0: Residential or unknown
** Block 1: Non-residential (e.g. webhost / proxy / vpn )

## Teoh.io

* API Documentation at: https://ip.teoh.io/vpn-proxy-api
* Returns a yes/no: Hosting, Proxy
* Returns a risk factor (Low, Medium, High, etc)
* Returns an ISP type ( isp, Hosting/Datacenter, etc )
* Teoh has generously donated an API key to us

## IPHunter

* API Documentation at: https://www.iphunter.info/api
* Provides an ISP Name
* Returns a "block number", or connection type.
** Block 0: Residential or unknown
** Block 1: Non-residential (e.g. webhost / proxy / vpn )

## NoFraud.co

* API Documentation at: https://nofraud.co/v1/api.php
* Gives a 0-100% chance of the IP in question being a proxy/VPN

## Compute hosts

* Detects the big 3: Google Cloud, Amazon AWS, and Microsoft Azure
** A hit here is a gauranteed colocation webhost.
* Amazon detection via an easily accessible JSON file: https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
* Microsoft Azure detection via XML. File location must be scraped from: https://www.microsoft.com/en-us/download/details.aspx?id=41653
* Google Cloud detection via convoluted DNS queries: https://cloud.google.com/compute/docs/faq#find_ip_range
** Google cloud does not appear to list all of it's IP's via the officially supported method. I have manually hardcoded several ranges that I have found as a long-time google cloud customer.

## SORBS

* DNSBL Documentation at: http://www.sorbs.net/general/using.shtml
* The "Spam and Open Relay Blocking System"
* SORBS blacklists a variety of spam sources.
* The main results to be interested in are: 
** 127.0.0.2 (HTTP Proxy)
** 127.0.0.2 (SOCKS Proxy)
** 127.0.0.2 (Misc Proxy)
** Other results may help determine if a host is compromised. Many spam sources are compromised hosts or open proxies.

## Spamhaus

* DNSBL Documentation at: https://www.spamhaus.org/zen/
* Very similar to SORBS
* Results will normally have a link to a report explaining why the IP is listed
* Primarily interesting results are 127.0.0.2, and 127.0.0.4-7.
** 127.0.0.4-7 can be a strong indicator of a compromised host, or a proxy. See the linked report for more information.
** 127.0.0.2 indicates that a host is sending, or has sent spam email. Many spam sources are compromised hosts or open proxies.

## DShield / internet storm center

* API Documentation at: https://dshield.org/api/
** This is a more advanced/experimental feed, and requires additional manual research
* Attacks: Number of attacks originating from this IP
** This number should not be taken as 100% accurate - see: https://en.wikipedia.org/wiki/Denial-of-service_attack#Backscatter
* Threatfeeds: Threat feeds that this IP appears in, as well as the last time that this IP was seen. 
** Google the threat feed name for more information.
*** Many will allow a lookup of the IP in question

## Hola

* Confirmed Hola VPN Nodes
** Hola VPN is a peer-to-peer free VPN application
** See: https://en.wikipedia.org/wiki/Denial-of-service_attack#Backscatter
* Hola nodes often look like residential / non-proxy connections
* There are two detection methods, both are 100% accurate, and are evidence of a recent Hola node.
** I am unable to publicly disclose my detection methods at this time, as this might encourage Hola to make changes to avoid detection
* Results will indicate the last time that the IP was seen, and by which method.

## Cache

* As we have a finite amount of resources, most results are cached.
** More information at: https://en.wikipedia.org/wiki/Cache_(computing)
* This will indicate a yes/no as to wether the results were cached, as well as when they were cached, and when they will expire.

## Port Scan

* NO SCANS ARE MADE FROM TOOLFORGE.
* For performance reasons, this check is not enabled by default.
* More information on ports can be found at: https://en.wikipedia.org/wiki/Port_scanner and https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
** The tool checks the most common 1221 proxy ports, and returns if they are open or not.
* This is a fairly advanced feed technique that often requires experience in interperting this sort of result.
* Common indicators:
** 1723: VPN: Not 100% evidence of an open proxy in and of itself. Some residential users (myself included) run a VPN out of the home to connect to various resources (cameras, home automation, etc)
** 1080, 8080: Often a proxy server
** 25, 109. 110, 585, 587, 993: Often evidence of a mail server. Most residential ISP's dissalow this sort of server, and explicitly block it.
** 53: DNS - Domain name server. This service translates domain names into IP addresses. Uncommon on residential connections.
** 80, 443: Web servers. This should be uncommon on residential connections, but is becoming more common. Often times on residential connections, it is a router configuration page
** 21: FTP: File Transfer Protocol, Commonly used to upload / download files from a host. Becoming less common with SFTP operating on port 22. Can be an indicator of a webhost with other factors, but is not uncommon on residential connections
** 22: SSH / SFTP: Typically a remote commandline used to configure and control linux/unix boxes. Traffic can be tunneled over SSH just like with a VPN / Proxy, and this can be an indicator of a webhost with other factors (behavioral, and other indicators listed above).
* Further investigation:
** nmap can be helpful.
*** If you want to know what's running on a port, you can use:
**** nmap -sV -p (port number, range, or numbers - comma seperated) (IP)
***** e.g.: nmap -sV -p 1-1000,1080,8080,923 127.0.0.1
**** Googling the port number can also be helpful
* Port scans alone are rarely useful evidence of an open proxy.
** Commonly used to confirm theories based on behavioral evidence

## Other useful tools

* IPRange: https://tools.wmflabs.org/ipcheck/iprange.php
** Resolves an IP range
** Often useful to look for nearby hosts with names like "mail.example.com" or "www.foo.bar".
*** This can be very helpful in mapping host ranges, such as when mixed with residential ranges (looking at you, OVH)
* ISP Rangefinder: https://tools.wmflabs.org/isprangefinder/index.php
** Attempts to find all IP ranges owned by a specific ISP
*** Provides links to block / unblock each range
* Hurricane BGP Toolkit: https://bgp.he.net/
** Similar to ISP Rangefinder, but can help catch some hosts that it misses
** Can be given an IP range, and be used to find more hosts

## Addittions or errors

* Everything above is based on my own personal experience, and may be completely wrong!
* Please, feel free to leave a message for me at https://en.wikipedia.org/wiki/User_talk:SQL
** Or, issue a pull request with changes

