#!/usr/bin/python

# Generate Chaos host info from DNS
# - ITS H3TEXT [see https://github.com/PDP-10/its/blob/master/build/h3text.2014#L134-L150]
# - Lispm HOSTS TEXT [see https://github.com/LM-3/chaos/issues/61]
# - BSD hosts file [see https://github.com/LM-3/chaos/issues/61] (same format as LISPM?)
# - global ITS config [see e.g. https://github.com/PDP-10/its/pull/532]
# - MINITS code? [https://github.com/LM-3/chaos/issues/61]

# Options:
# -3 to generate hosts3 format ("extended" RFC 810) for ITS
# -l to generate lispm format (RFC 608, I think) which looks like it matches the 4.1BSD format?
# -i to generate a list of short ITS names, suitable for ITSIRP in SYSTEM;CONFIG
# -a to remove trailing .Chaosnet.NET domain in aliases (so you can parse two-letter abbrevs easily)
# -d domain to set local domain, which is also removed from aliases
# -I include IP addresses, if they exist, including private addresses
# -G include global IP addresses, if they exist (not private addresses https://en.wikipedia.org/wiki/Private_network)

# Should perhaps retain the original aliases?
# Should perhaps strip the local domain from the main name too, if the short one should be the canonical?

# Note to self:
# don't forget PYTHONPATH=whereverdnspythonsis:
# or similar

# dnspython is at https://github.com/rthalley/dnspython.
# Support for Chaosnet A records was introduced in 2018.
# Version 2.9.2 patched 2.9, which broke Chaosnet A records, to make it work again.

import dns.resolver
import dns.zone
# import dns.query
# import dns.rdataclass
import struct
import sys
import getopt
from datetime import date
from socket import gethostbyname

aosnet_its_pruning = False
local_domain = None
add_ip = False
add_ip_global = False

def get_host_info(name, printJunk=False):
    hinfo = {}
    rpdict = {}
    a = []
    txt = ""
    try:
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.ANY, rdclass=dns.rdataclass.CH), gethostbyname('dns.chaosnet.net'))
        # answer is a set, find only the interesting ones
        for t in h.answer:
            # t is a dns.rrset.RRset object
            if t.rdtype == dns.rdatatype.HINFO:
                for d in t:
                    hinfo['OS'] = str(d.os.decode())
                    hinfo['CPU'] = str(d.cpu.decode())
            elif t.rdtype == dns.rdatatype.TXT:
                # Not used
                for d in t:
                    txt += d.to_text()
            elif t.rdtype == dns.rdatatype.RP:
                # Not used
                for d in t:
                    (u, dom) = d.mbox.split(len(d.mbox.labels)-1)
                    # @@@@ should unescape u (\. => .)
                    em = "{0}@{1}".format(u.to_text(), dom.to_text(omit_final_dot=True))
                    rptxt = []
                    if not(d.txt == dns.name.root):
                        rps = dns.query.udp(dns.message.make_query(str(d.txt), dns.rdatatype.TXT, rdclass=dns.rdataclass.CH), gethostbyname('dns.chaosnet.net'))
                        for rp in rps.answer:
                            for t in rp:
                                rptxt.append(t.to_text())
                    rpdict[em] = rptxt
            elif t.rdtype == dns.rdatatype.A:
                try:
                    for d in t:
                        a.append(d.address)
                except AttributeError:
                    # dnspython not updated with support for Chaos A records
                    print("## A failure for {}".format(name), file=sys.stderr)
                    a = a
            elif printJunk:
                print(dns.rdatatype.to_text(t.rdtype), end=' ', file=sys.stderr)
                for d in t:
                    print("-", d.to_text(), file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error", e, file=sys.stderr)
    return (a, hinfo, rpdict, txt)

soas = {}

def get_ch_addr_zone():
    z = dns.zone.from_xfr(dns.query.xfr(gethostbyname('dns.chaosnet.net'), 'ch-addr.net.', rdclass=dns.rdataclass.CH))
    soa = z.find_rdataset('@', dns.rdatatype.SOA)
    print(";;; Generated on", date.today().isoformat())
    # soas['CH-ADDR.NET.'] = soa[0].serial
    print(";; based on serial", soa[0].serial, "of CH-ADDR.NET.")
    return z

haddrs = {}
doms = set()
nets = {}

# Collect all hosts being PTRed to, and all their addresses
def collect_all_hosts(z):
    global haddrs, doms, nets
    for (addr, ttl, rdata) in z.iterate_rdatas('PTR'):
        if rdata.rdtype == dns.rdatatype.PTR:
            if int(addr.to_text(), 8) & 0xff != 0:
                hname = rdata.target.to_text()
                addstr = addr.to_text()
                if hname not in haddrs:
                    haddrs[hname] = []
                haddrs[hname].append(int(addstr, 8))
                # Only collect non-TLDs
                pdom = rdata.target.parent().to_text(omit_final_dot=True)
                domstr = "{}.".format(pdom) if "." in  pdom else rdata.target.to_text()
                doms.add(domstr)
            else:
                nname = rdata.target.to_text(omit_final_dot=True)
                addstr = "{:o}".format(int(addr.to_text(), 8) >> 8)
                nets[addstr] = nname

# Scan for CNAMEs in relevant zones
# Should use the right NS for xfr (but Psilo has everything so far, so punt)
aliases = {}
def scan_for_cnames(doms):
    global aliases, soas
    for dom in doms:
        #### Should look up the NS (in the IN class) of the domain, and use the NS for that
        # need to try all NS, and perhaps all their addresses.
        # Too much bother as long as Psilo knows everything
        za = dns.zone.from_xfr(dns.query.xfr(gethostbyname('dns.chaosnet.net'), dom, rdclass=dns.rdataclass.CH, relativize=False), relativize=False)
        soa = za.find_rdataset(dom, dns.rdatatype.SOA)
        soas[dom] = soa[0].serial
        for (name, ttl, rdata) in za.iterate_rdatas('CNAME'):
            alias = name.to_text(omit_final_dot=True)
            host = rdata.target.to_text().lower()
            if host not in aliases:
                aliases[host] = []
            aliases[host].append(alias)

def parent_domain_equal_to(child, domain):
    # BUG: doing == on dns.name.Name should be case insensitive!!
    ll = dns.name.from_text(child)
    # for python 3?
    # return ll.parent().to_text().casefold() == dom.casefold()
    return ll.parent().to_text().lower() == domain.lower()

# return the first label of dom (a string)
def domain_first_label(dom):
    ll = dns.name.from_text(dom)
    (hd, tl) = ll.split(len(ll.labels)-1)
    return hd.to_text()

# based on aosnet_its_pruning and local_domain
def maybe_prune_domain_parent(a, hinfo):
    global aosnet_its_pruning, local_domain
    if (aosnet_its_pruning and parent_domain_equal_to(a, "Chaosnet.NET.")) \
       or (local_domain != None and parent_domain_equal_to(a, local_domain)):
        return domain_first_label(a)
    else:
        return a

# Print a NET entry in h3text format - hack
h3netprinted = False
def h3textnet(net, name):
    global h3netprinted
    if False and not h3netprinted:
        # @@@@ look up where it is wired, and fix it?
        print(";;; Definition of Chaosnet for HOSTS3 UNTERNET scheme.")
        print(";;; This is not a value you can change, it's wired into the ITS monitor.")
        print("NET : UN 7.0.0.0 : CHAOS :")
        h3netprinted = True

# print a HOST entry in h3text format
def h3texthost(hname, haliases, addrs, hinfo):
    import socket
    global aosnet_its_pruning
    cha = ", ".join(["CHAOS {:o}".format(s) for s in addrs])
    if add_ip:
        try:
            import ipaddress
            (hn, ipaliases, ipas) = socket.gethostbyname_ex(hname)
            ipas = [i for i in ipas if not ipaddress.ip_address(i).is_private] if add_ip_global else ipas
            if len(ipas) > 0:
                cha = ", ".join(ipas)+", "+cha
        except socket.gaierror:
            ipas = []
    print("HOST", ":", cha,
          ":", maybe_prune_domain_parent(dns.name.from_text(hname).to_text(omit_final_dot=True), hinfo) +
          (len(haliases) > 0 and ", " or "") +
          ", ".join(set(haliases+[maybe_prune_domain_parent(x, hinfo) for x in haliases])),
          ":", hinfo['CPU'].upper() if 'CPU' in hinfo else "", ":", hinfo['OS'].upper() if 'OS' in hinfo else "", ": :")

def itslist(haddrs):
    global aliases
    hnames = list(haddrs.keys())
    itses = []
    for n in hnames:
        (a, hinfo, x, y) = get_host_info(n)
        if 'OS' in hinfo and hinfo['OS'] == 'ITS':
            l = domain_first_label(n)
            if l.endswith("-ITS"): # Prune "-ITS" endings
                l = l[:-4]
            if len(l) <= 3:     # Only include short names
                itses.append(l)
    print(" ".join(set(itses))) # and remove duplicates


# Print a lispm format NET entry
def lispmnet(net, name):
    # Oddly, the NET number is decimal
    hack = int(net,8)
    print("NET", str(hack)+",", name)

# Print a lispm format HOST entry
def lispmhost(hname, haliases, addrs, hinfo):
    import socket
    global aosnet_its_pruning
    ## USER vs SERVER vs TIP vs UNKNOWN - does anybody care? I don't.
    cha = ", ".join(["CHAOS {:o}".format(s) for s in addrs])
    if add_ip:
        try:
            import ipaddress
            (hn, ipaliases, ipas) = socket.gethostbyname_ex(hname)
            ipas = [i for i in ipas if not ipaddress.ip_address(i).is_private] if add_ip_global else ipas
            if len(ipas) > 0:
                cha = ", ".join(["INTERNET {}".format(s) for s in ipas])+", "+cha
        except socket.gaierror:
            ipas = []
    print("HOST", maybe_prune_domain_parent(dns.name.from_text(hname).to_text(omit_final_dot=True), hinfo)+",",
          (len(addrs) > 1 and "["+cha+"]"
           or "CHAOS {:o}".format(addrs[0])) +
          ", USER, "+(hinfo['OS'].upper() if 'OS' in hinfo else "UNKNOWN")+", " +
          (hinfo['CPU'].upper() if 'CPU' in hinfo else "UNKNOWN") +
          (len(haliases) > 0 and ", ["+", ".join(set([maybe_prune_domain_parent(x, hinfo) for x in haliases]))+"]"
           or ""))

# Print a hosts file in some format
def hostsfile(soas, haddrs, hostformatter, netformatter):
    for d in soas:
        print(";; and on serial", soas[d], "of", d)
    print()
    # sorted by net number
    nnums = list(nets.keys())
    nnums.sort(key=lambda x: int(x, 8))
    if len(nnums) > 0:
        print(";; Network{} (decimal):".format("s" if len(nnums) != 1 else ""))
    for n in nnums:
        netformatter(n, nets[n])
    print()
    # Sorted by reversed domain name
    if len(haddrs) > 0:
        print(";; Host{}:".format("s" if len(haddrs) != 1 else ""))
    hnames = list(haddrs.keys())
    hnames.sort(key=lambda x: ".".join(reversed(list(str(dns.name.from_text(x).labels)))))
    for n in hnames:
        (a, hinfo, rp, txt) = get_host_info(n)
        # check if dnspython supports Chaos A records (len(a) > 0), otherwise ignore difference
        if len(a) > 0 and len(set(haddrs[n])) != len(set(a)):
            print("## For", n, "A is", list(map(oct, set(a))), "which is different from CH-ADDR.NET",
                  list(map(oct, set(haddrs[n]))), file=sys.stderr)
            if len(set(a)) < 3 and len(set(haddrs[n])) >= 3:
                # See https://gitlab.isc.org/isc-projects/bind9/issues/562
                print("## This is probably caused the DNS server not being updated yet", file=sys.stderr)
        # Use the longer list
        if len(a) < len(haddrs[n]):
            a = haddrs[n]
        if n.lower() in aliases:
            al = aliases[n.lower()]
        else:
            al = []
        hostformatter(n, al, a, hinfo)

def main(argv):
    global aosnet_its_pruning, local_domain, add_ip, add_ip_global
    import argparse
    parser = argparse.ArgumentParser(description='Host file generator')
    parser.add_argument("-d",'--domain',dest='local_domain',
                            help='Set local domain, which gets stripped from host names')
    parser.add_argument("-3",'--hosts3',dest='hosts3',action='store_true',
                            help='Use HOSTS3 format (RFC 810)')
    parser.add_argument("-l",'--lispm',dest='lispm',action='store_true',
                            help='Use LISPM format (RFC 752)')
    parser.add_argument("-i",'--its',dest='its',action='store_true',
                            help='Make ITS shortnames list, suitable for ITSIRP in SYSTEM;CONFIG')
    parser.add_argument("-a",'--alias',dest='aliases',action='store_true',
                            help='Use short aliases for Chaosnet.NET hosts')
    parser.add_argument("-I",'--ip',dest='add_ip',action='store_true',
                            help='Add IP addresses to output (including private addresses)')
    parser.add_argument("-G",'--global-ip',dest='add_ip_global',action='store_true',
                            help='Add non-private IP addresses to output')
    args = parser.parse_args()

    if (args.hosts3 and args.lispm) or (args.hosts3 and args.its) or (args.lispm and args.its):
        print("Only one format can be used at a time (-3 -l -i)", file=sys.stderr)
        sys.exit(1)
    if not(args.hosts3 or args.lispm or args.its):
        print("Must select one output format (-3 -l -i)", file=sys.stderr)
        sys.exit(1)

    h3 = args.hosts3
    lispm = args.lispm
    its_shortnames_only = args.its
    aosnet_its_pruning = args.its or args.aliases
    if args.local_domain:
        local_domain = dns.name.from_text(args.local_domain).to_text()
    add_ip = args.add_ip or args.add_ip_global
    add_ip_global = args.add_ip_global
        
    z = get_ch_addr_zone()
    collect_all_hosts(z)
    scan_for_cnames(doms)
    if h3:
        hostsfile(soas, haddrs, h3texthost, h3textnet)
    elif lispm:
        hostsfile(soas, haddrs, lispmhost, lispmnet)
    elif its_shortnames_only:
        itslist(haddrs)

if __name__ == "__main__":
    main(sys.argv[1:])
