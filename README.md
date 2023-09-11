Generate Chaos host info from DNS
- ITS H3TEXT [see e.g. https://github.com/PDP-10/its/blob/master/build/h3text.2017#L134-L150]
- Lispm HOSTS TEXT or BSD 4.1 hosts file [see e.g. https://tumbleweed.nu/r/sys/file?name=site/hosts.text.392&ci=tip]

Options:

 -3 to generate hosts3 format ("extended" [RFC 810](https://www.ietf.org/rfc/rfc810.txt)) for ITS
 
 -l to generate lispm format ([RFC 752](https://www.ietf.org/rfc/rfc752), I think) which looks like it matches the 4.1BSD format.
 
 -a to add aliases for .Chaosnet.NET hosts by removing the trailing .Chaosnet.NET (so you can parse two-letter abbrevs easily)
 
 -i to create a list of ITS shortnames, suitable for def of [ITSIRP in SYSTEM;CONFIG](https://github.com/PDP-10/its/blob/5a068bb1da329f829221076cd25bb6a38baf8272/build/klh10/config.203#L1001)

 -d domain to set local domain, which is also adds aliases without the domain

Requires dnspython, which is at https://github.com/rthalley/dnspython.

