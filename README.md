Generate Chaos host info from DNS
- ITS H3TEXT [see https://github.com/PDP-10/its/blob/master/build/h3text.2014#L134-L150]
- Lispm HOSTS TEXT [see https://github.com/LM-3/chaos/issues/61]
- BSD hosts file [see https://github.com/LM-3/chaos/issues/61] (same format as LISPM?)

Options:

 -3 to generate hosts3 format ("extended" RFC 810) for ITS
 
 -l to generate lispm format (RFC 608, I think) which looks like it matches the 4.1BSD format?
 
 -a to remove trailing .aosnet.CH domain in aliases (so you can parse two-letter abbrevs easily)
 
 -d domain to set local domain, which is also removed from aliases

Requires dnspython, which is at https://github.com/rthalley/dnspython,

