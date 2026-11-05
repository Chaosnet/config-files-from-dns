Generate Chaos host info from DNS
- ITS H3TEXT [see e.g. https://github.com/PDP-10/its/blob/master/build/h3text.2018]
- Lispm HOSTS TEXT or BSD 4.1 hosts file [see e.g. https://tumbleweed.nu/r/sys/file?name=site/hosts.text.392&ci=tip]

Output format selection - one of the following (required):
 - `-3` to generate HOSTS3 format ("extended" [RFC 810](https://www.ietf.org/rfc/rfc810.txt)) for e.g. ITS
 
 - `-l` to generate LISPM format ([RFC 752](https://www.ietf.org/rfc/rfc752), I think) which looks like it matches the 4.1BSD format.
 
 - `-i` to create a list of ITS shortnames, suitable for def of [ITSIRP in SYSTEM;CONFIG](https://github.com/PDP-10/its/blob/5a068bb1da329f829221076cd25bb6a38baf8272/build/klh10/config.203#L1001). Note: prunes any "-ITS" suffix (e.g. `ES-ITS` becomes just `ES`) and only includes short (2-3 characters) names, since longer ones are not useful as ITS shortnames.


Other options:
 - `-a` to add aliases for .Chaosnet.NET hosts by removing the trailing .Chaosnet.NET (so you can e.g. parse two-letter abbrevs easily)
 
 - `-d` *domain* to set the local domain, so aliases without the domain are added

 - `-I` to add IP addresses to those that have them (including private IP addresses)
 
 - `-G` to add non-private (global) IP addresses only

Requires dnspython, which is at https://github.com/rthalley/dnspython.
