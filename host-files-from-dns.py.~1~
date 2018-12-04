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
# -a to remove trailing .aosnet.CH domain in aliases (so you can parse two-letter abbrevs easily)
# -d domain to set local domain, which is also removed from aliases

# Should perhaps retain the original aliases?
# Should perhaps strip the local domain from the main name too, if the short one should be the canonical?

# TODO:
#  Generate ITS config for the "global ITS" (Lars?)

# Note to self:
# don't forget PYTHONPATH=whereverdnspythonsis:
# or similar

# dnspython is at https://github.com/rthalley/dnspython,
# and a fork which supports Chaos A records is at https://github.com/bictorv/dnspython/tree/chaos-addresses
# (a PR has been done on Nov 12, 2018)

import dns.resolver
import dns.zone
# import dns.query
# import dns.rdataclass
import struct
import sys
import getopt
from datetime import date

aosnet_its_pruning = False
local_domain = None

def get_host_info(name, printJunk = False):
    hinfo = {}
    rpdict = {}
    a = []
    txt = ""
    try:
        h = dns.query.udp(dns.message.make_query(name,dns.rdatatype.ANY,rdclass=dns.rdataclass.CH),'130.238.19.25')
        # answer is a set, find only the interesting ones
        for t in h.answer:
            # t is a dns.rrset.RRset object
            if t.rdtype == dns.rdatatype.HINFO:
                for d in t:
                    hinfo['OS'] = d.os
                    hinfo['CPU'] = d.cpu
            elif t.rdtype == dns.rdatatype.TXT:
                # Not used
                for d in t:
                    txt += d.to_text()
            elif t.rdtype == dns.rdatatype.RP:
                # Not used
                for d in t:
                    (u,dom) = d.mbox.split(len(d.mbox.labels)-1)
                    # @@@@ should unescape u (\. => .)
                    em = "{0}@{1}".format(u.to_text(),dom.to_text(omit_final_dot=True))
                    rptxt = []
                    if not(d.txt == dns.name.root):
                        rps = dns.query.udp(dns.message.make_query(str(d.txt),dns.rdatatype.TXT,rdclass=dns.rdataclass.CH),'130.238.19.25')
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
                    a = a
            elif printJunk:
                print >> sys.stderr, dns.rdatatype.to_text(t.rdtype),
                for d in t:
                    print >> sys.stderr, "-",d.to_text()
    except dns.exception.DNSException as e:
        print >> sys.stderr, "Error",e
    return (a,hinfo,rpdict,txt)

soas = {}

def get_ch_addr_zone():
    z = dns.zone.from_xfr(dns.query.xfr('130.238.19.25','ch-addr.net.',rdclass=dns.rdataclass.CH))
    soa = z.find_rdataset('@',dns.rdatatype.SOA)
    print ";;; Generated on",date.today().isoformat(),\
          "based on CH-ADDR.NET serial",soa[0].serial
    # soas['CH-ADDR.NET.'] = soa[0].serial
    return z

haddrs = {}
doms = set()
nets = {}

# Collect all hosts being PTRed to, and all their addresses
def collect_all_hosts(z):
    global haddrs, doms, nets
    for (addr, ttl, rdata) in z.iterate_rdatas('PTR'):
        if rdata.rdtype == dns.rdatatype.PTR:
            if int(addr.to_text(),8) & 0xff != 0:
                hname = rdata.target.to_text()
                addstr = addr.to_text()
                if hname not in haddrs:
                    haddrs[hname] = []
                haddrs[hname].append(int(addstr,8))
                doms.add(rdata.target.parent().to_text())
            else:
                nname = rdata.target.to_text(omit_final_dot=True)
                addstr = "{:o}".format(int(addr.to_text(),8)>>8)
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
        za = dns.zone.from_xfr(dns.query.xfr('130.238.19.25',dom,rdclass=dns.rdataclass.CH,relativize=False),relativize=False)
        soa = za.find_rdataset(dom, dns.rdatatype.SOA)
        soas[dom] = soa[0].serial
        for (name,ttl,rdata) in za.iterate_rdatas('CNAME'):
            alias = name.to_text(omit_final_dot=True)
            host = rdata.target.to_text()
            if host not in aliases:
                aliases[host] = []
            aliases[host].append(alias)

def parent_domain_equal_to(child,domain):
    # BUG: doing == on dns.name.Name should be case insensitive!!
    ll = dns.name.from_text(child)
    # for python 3?
    # return ll.parent().to_text().casefold() == dom.casefold()
    return ll.parent().to_text().lower() == domain.lower()

# return the first label of dom (a string)
def domain_first_label(dom):
    ll = dns.name.from_text(dom)
    (hd,tl) = ll.split(len(ll.labels)-1)
    return hd.to_text()

# based on aosnet_its_pruning and local_domain
def maybe_prune_domain_parent(a,hinfo):
    global aosnet_its_pruning, local_domain
    if (aosnet_its_pruning and hinfo['OS'] == "ITS" and parent_domain_equal_to(a,"aosnet.CH.")) \
           or (local_domain != None and parent_domain_equal_to(a,local_domain)):
        return domain_first_label(a)
    else:
        return a

# Print a NET entry in h3text format - hack
h3netprinted = False
def h3textnet(net,name):
    global h3netprinted
    if not h3netprinted:
        # @@@@ look up where it is wired, and fix it?
        print ";;; Definition of Chaosnet for HOSTS3 UNTERNET scheme."
        print ";;; This is not a value you can change, it's wired into the ITS monitor."
        print "NET : UN 7.0.0.0 : CHAOS :"
        h3netprinted = True

# print a HOST entry in h3text format
def h3texthost(hname,haliases,addrs,hinfo):
    global aosnet_its_pruning
    print "HOST",":",", ".join(map(lambda (s): "CHAOS {:o}".format(s),addrs)),\
          ":",dns.name.from_text(hname).to_text(omit_final_dot=True)+(len(haliases) > 0 and ", " or "")+\
          ", ".join(map(lambda (x):maybe_prune_domain_parent(x,hinfo), haliases)),\
          ":",hinfo['CPU'],":",hinfo['OS'],": :"

# Print a lispm format NET entry
def lispmnet(net,name):
    print "NET",net+",",name

# Print a lispm format HOST entry
def lispmhost(hname,haliases,addrs,hinfo):
    global aosnet_its_pruning
    ## USER vs SERVER vs TIP vs UNKNOWN - does anybody care? I don't.
    print "HOST",dns.name.from_text(hname).to_text(omit_final_dot=True)+",",\
              (len(addrs) > 1 and "["+", ".join(map(lambda (s): "CHAOS {:o}".format(s),addrs))+"]" \
               or "CHAOS {:o}".format(addrs[0]))+\
               ", USER, "+hinfo['OS']+", "+hinfo['CPU']+\
               (len(haliases) > 0 and ", ["+", ".join(map(lambda (x):maybe_prune_domain_parent(x,hinfo),haliases))+"]" \
                or "")

# Print a hosts file in some format
def hostsfile(soas,haddrs,hostformatter,netformatter):
    for d in soas:
        print ";; and on serial",soas[d],"of",d
    print
    # sorted by net number
    nnums = nets.keys()
    nnums.sort(key=lambda (x): int(x,8))
    for n in nnums:
        netformatter(n,nets[n])
    print
    # Sorted by reversed domain name
    hnames = haddrs.keys()
    hnames.sort(key=lambda(x): ".".join(reversed(list(dns.name.from_text(x).labels))))
    for n in hnames:
        (a,hinfo,rp,txt) = get_host_info(n)
        # check if dnspython supports Chaos A records (len(a) > 0), otherwise ignore difference
        if len(a) > 0 and len(set(haddrs[n])) != len(set(a)):
            print >> sys.stderr,"## For",n,"A is",map(oct,set(a)),"which is different from CH-ADDR.NET",\
                  map(oct,set(haddrs[n]))
            if len(set(a)) < 3 and len(set(haddrs[n])) >= 3:
                # See https://gitlab.isc.org/isc-projects/bind9/issues/562
                print >> sys.stderr,"## This is probably caused the DNS server not being updated yet"
        # Use the longer list
        if len(a) < len(haddrs[n]):
            a = haddrs[n]
        if n in aliases:
            al = aliases[n]
        else:
            al = []
        hostformatter(n, n in aliases and aliases[n] or [], a, hinfo)
        

def main(argv):
    global aosnet_its_pruning, local_domain
    try:
        opts, args = getopt.getopt(argv,"3lad:")
    except getopt.GetoptError:
        print >> sys.stderr, "use\n -3 for hosts3 format,\n",\
              " -l for lispm format\n",\
              " -d dom for local domain\n",\
              " -a to remove aosnet.CH from ITS aliases"
        sys.exit(1)
    h3 = False
    lispm = False
    for opt,arg in opts:
        if opt == '-3':
            h3 = True
        elif opt == '-l':
            lispm = True
        elif opt == '-a':
            aosnet_its_pruning = True
        elif opt == '-d':
            local_domain = arg
            if dns.name.from_text(local_domain) == None:
                print >> sys.stderr,"Bad -d domain",arg
                sys.exit(1)
    if not(h3 or lispm):
        print >> sys.stderr, "use\n -3 for hosts3 format,\n",\
              " -l for lispm format\n",\
              " -d dom for local domain\n",\
              " -a to remove aosnet.CH from ITS aliases"
        sys.exit(1)
    z = get_ch_addr_zone()
    collect_all_hosts(z)
    scan_for_cnames(doms)
    if h3:
        hostsfile(soas,haddrs,h3texthost,h3textnet)
    elif lispm:
        hostsfile(soas,haddrs,lispmhost,lispmnet)

if __name__ == "__main__":
    main(sys.argv[1:])
