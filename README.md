<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/readme/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/readme/banner-light.svg">
  <img src="docs/images/readme/banner-light.svg" alt="os-useridentity - Firewall rules by user, not by address" width="100%">
</picture>

<p align="center">
  <img alt="status: written, not released" src="https://img.shields.io/badge/status-written%2C%20not%20released-lightgrey.svg?style=flat-square">
  <a href="https://github.com/AbdelmonemAwad/os-useridentity/actions/workflows/checks.yml"><img alt="checks on main" src="https://img.shields.io/github/actions/workflow/status/AbdelmonemAwad/os-useridentity/checks.yml?branch=main&amp;style=flat-square&amp;label=checks"></a>
  <a href="LICENSE"><img alt="licence: BSD-2-Clause" src="https://img.shields.io/badge/licence-BSD--2--Clause-blue.svg?style=flat-square"></a>
  <a href="#what-is-tested"><img alt="OPNsense 26.7" src="https://img.shields.io/badge/OPNsense-26.7-d94f00.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/opnsense-arabic"><img alt="the page in English and in Arabic" src="https://img.shields.io/badge/GUI-English%20%C2%B7%20Arabic-2da44e.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/os-xgs-npu"><img alt="part of os-xgs-npu" src="https://img.shields.io/badge/part%20of-os--xgs--npu-9a6700.svg?style=flat-square"></a>
</p>

# User Identity for OPNsense

Who is behind an address: logons read from the Active Directory domain controllers, RADIUS accounting from os-freeradius and the captive portal's sessions, with the directory asked for each user's groups, kept as pf tables per group and per user, for rules, traffic priority and web policies.

> ~~**Planned - nothing here runs yet.** This repository was opened on 2026-11-16 to hold
> User Identity as a plugin of its own. No code has been written or moved into it, and there is no
> release.~~
>
> **Written, not released (2026-11-18).** The first part is here: the engine and the Active Directory
> source - each address mapped to its user from the domain controllers' logon events, the user's groups
> asked of the directory, a table for each group chosen and each user named. Off by default. It has
> not run on an appliance yet: what was run is under [What is tested](#what-is-tested).
>
> **The second part, written 2026-11-19 and corrected after its review on 2026-11-20, not released:**
> RADIUS accounting - of the RADIUS clients Settings names - and the captive portal's sessions as
> sources beside the domain controllers - each off until Settings turns it on - the latest logon
> winning an address whichever source it came from, and the page showing two sources that clash over
> one. It has not run on an appliance: what was run is under [What is tested](#what-is-tested).

<p align="center"><b>Contents:</b> <a href="#what-it-does">What it does</a> &middot; <a href="#how-a-logon-becomes-a-table">How a logon becomes a table</a> &middot; <a href="#radius-and-the-captive-portal">RADIUS and the captive portal</a> &middot; <a href="#not-yet-and-why">Not yet, and why</a> &middot; <a href="#what-is-tested">What is tested</a> &middot; <a href="#installation">Installation</a> &middot; <a href="#updates">Updates</a> &middot; <a href="#where-it-fits">Where it fits</a> &middot; <a href="#licence">Licence</a></p>

## What it does

**Firewall: User Identity** (XGS: User Identity, order 60, when os-xgs-npu is installed), one page, off
by default:

- **the map** - each address on the network with the user a source last saw on it. Three sources, each
  chosen in Settings:
  - **the domain controllers** - two events of the Windows Security log: 4768, a ticket-granting ticket
    issued, and 4624, a logon to the domain controller with the client's address. NXLog Community
    Edition on each domain controller sends them as JSON over TCP; the page shows its configuration to
    copy - each event's time sent as seconds since 1970, in UTC (`$EventTime = integer($EventTime) /
    1000000`), and the event's long text left out (`delete($Message)`), which nothing here reads;
  - **RADIUS accounting** - the records os-freeradius writes of each Accounting-Request the RADIUS
    clients named in Settings send: a Start maps the session's Framed-IP-Address to its user, each
    Interim-Update renews it, a Stop takes it out ([below](#radius-and-the-captive-portal), with what a
    client must be to be named);
  - **the captive portal** - each session of its zones, read from the portal's own database: the
    session's addresses are its user's from the logon to the logout or the portal's own timeout;
- **the latest wins** - an address another user is seen on later is that user's, whichever source said
  it; the page marks the address shared, and a clash when the two users came from two sources;
- **the groups** - the directory chosen in System: Access: Servers is asked which of the chosen groups
  each user is in: directly, or, with Nested groups on, through a group inside it, by Active
  Directory's in-chain rule;
- **the tables** - for each group row, the addresses of its users; for each user named, that user's
  addresses. Each is an alias of type External in Firewall: Aliases, `uid_` and a name the row gives -
  proposed from the group's or the user's name, 31 characters at most - so a rule's source or
  destination can name it. A table is made from the map each time, never edited by an event alone;
- **the cut** - where os-xgs-npu is installed, XGS: Settings' "Cut open connections when listed" holds
  these tables, beside the owner's own entries: an address that joins one has the connections it
  already had cut within a minute, in hardware first. Each table is put there once, when it is made (or
  when os-xgs-npu comes after it), and the plugin keeps a record of it: one the owner takes out stays
  out. Leaving a table cuts nothing. Without os-xgs-npu nothing is cut, and the page says so;
- **the cards and tabs** - users present with the addresses shared and the clashes between sources,
  groups and the directory's state, the sources heard, the last event; then Users (the live map, each
  address's source, an address shared or clashed over marked, Forget every mapping, and the user rows),
  Groups (the group rows, the addresses each table holds, and a Test that asks the directory about one
  user), Sources (each domain controller, RADIUS client and portal zone: when it was last heard, its last
  event, how late it came, what was taken, mapped, renewed, ended, stale and refused and why; and
  NXLog's configuration) and Settings;
- **alerts** - a domain controller silent for the minutes Settings gives, the directory failing, an
  address newly shared: one file each in os-xgs-npu's form under `/var/db/os-useridentity/alerts`, for
  os-netreport to send.

Only the live map is kept. The system log says how many addresses were mapped, changed user or left;
it names them only with Log user names on. A history of the mappings is kept only for the days Settings
gives, none by default.

## How a logon becomes a table

The design is phase 0's, settled on 2026-11-17 by the plan, the new-plugin standard and a lab with a
Windows Server 2025 domain controller, a Windows 11 client and NXLog CE on the second XGS 3300 -
NXLog's and the domain controller's behaviour, not this plugin's:

- **received by OPNsense's own syslog-ng** - a source of the plugin's on 127.0.0.1, TCP, port 5141, in
  `/usr/local/etc/syslog-ng.conf.d/useridentity.conf`, and a pf redirect, on the chosen interfaces, from
  each domain controller named in Settings and no other address, of the port the domain controllers send
  to (514 by default) to that source - os-xgs-npu's way for the coprocessor's log. Never a port the
  firewall itself serves - SSH, DNS, the web GUI on 80, 443 or its own port - which the domain
  controllers would then no longer reach: Settings refuses one, and no redirect is registered on one the
  web GUI or SSH is moved to afterwards. The redirect is the gate: phase 0's lab saw a line from a
  machine that is no domain controller arrive as easily, so the plugin reads only what the named
  addresses send, and syslog-ng's source is reached by nothing else from the network. syslog-ng cannot
  listen on an interface's address, and one source that cannot bind stops it whole, with every log of
  OPNsense's: so the source is written only on a port no other program holds, and only when syslog-ng
  takes its whole configuration with it - when it does not, the file before is put back and syslog-ng is
  not restarted, since the refusal may be another file's. When it is not written the page says why, and
  no redirect is registered. The lines go to no log file: syslog-ng hands each to the plugin's collector, over a
  socket, with the address it came from;
- **what maps** - a ticket issued (4768, Status 0x0), its address written `::ffff:a.b.c.d` for IPv4,
  comes 1.5 to 2.4 seconds after a logon, and again at an unlock; network logons to the domain
  controller (4624) renew an idle session - in the lab's idle hour, 37 lines about the user in six
  bursts, the longest gap 22 minutes. Every other event is counted and set aside;
- **what never maps** - a computer account (every logon through a task or runas gives one first), an
  account that is no domain user (SYSTEM, ANONYMOUS LOGON, the virtual accounts), an event older than
  Stale after when it arrives - NXLog CE sends again, when it starts, what it held while stopped, ten
  minutes old in the lab - the firewall's own addresses (OPNsense's own LDAP connector binds as a user
  from one of them), a domain controller's, loopback, link-local, multicast and broadcast addresses,
  Never map's addresses and Ignore users' users. An event's time with a zone - the page's NXLog
  configuration sends one - is read as it says; one with none, NXLog CE's default, in the firewall's own
  time zone;
- **the latest wins** - an address another user logs on from takes that user, and is marked shared
  while the one before is still within the lifetime: in the lab a runas on a client moved its address
  to the runas user while another sat at its screen. Never map is for terminal servers and NAT inside
  the network;
- **nothing says a user left** - a lock and a logoff send nothing that does, and a logoff event carries
  no address. A mapping ends at the end of its lifetime - 480 minutes with no event about it: in phase
  0's four hours a signed-in user's domain controller wrote nothing about it for up to 55 minutes, idle
  or busy, so a shorter one would drop users who are there - when the address's MAC in the firewall's ARP
  or neighbour table changes, checked every minute (behind a router the firewall sees no MAC), or when
  forgotten on the page;
- **the groups** - asked when a user is first seen and again after 15 minutes, in a thread of their
  own, so a directory slow to answer never holds the events back; the user's addresses join its own
  table at once and its groups' when the directory answers. Windows Server 2025 refuses a simple bind
  in the clear: the entry of System: Access: Servers must use StartTLS or SSL, with the domain's
  certificate authority in System: Trust and the domain controller named as its certificate names it -
  the plugin checks the certificate and the name as OPNsense's own connector does, with its own CA file.
  OPNsense's connector reads memberOf alone; the lab found a user in a group only through a group
  inside it by the in-chain rule;
- **every minute** - from cron, whether the collector runs or not: the lifetimes ended, the MAC check,
  the mappings of a source switched off - RADIUS accounting or the captive portal turned off, a RADIUS
  client no longer named, a zone switched off; a domain controller no longer named leaves its mappings
  to their lifetime, as they were made true - and every table made again from the map, so one emptied
  by hand or written while the collector was down is right within a minute.

## RADIUS and the captive portal

The plan's second part, top-03: sources beside the domain controllers, each off until Settings turns
it on, read by the same collector and judged as the domain controllers' events are - the firewall's own
addresses, a domain controller's, Never map's and the users of Ignore users map nothing - with the
user's groups asked of the same directory, whichever source mapped it:

- **RADIUS accounting** - os-freeradius sends every Accounting-Request through FreeRADIUS's detail
  module, which appends it to `/var/log/radacct/<client>/detail-YYYYMMDD`, one file a day, 0600
  root:freeradius, in the second the request comes (phase 0's A9: os-freeradius 1.10.3, freeradius3
  3.2.10). The collector reads what is written each second, as root - only the files of the days a
  record within the lifetime can be in, since nothing takes the older ones away - and goes on where it
  stopped after a restart (`radius.json`, written at most every ten seconds and when it stops). A NAS,
  or another RADIUS server that forwards its accounting, must be a client of Services: FreeRADIUS, and
  named in Settings' **RADIUS clients** by its address - the name of the directory FreeRADIUS writes
  its records in. A record from any other client is refused, and with none named none maps;
- **whose name a record carries** - the name its NAS reports. With EAP - PEAP, TTLS or TLS, most
  802.1X - that is the outer name the device itself gives, which its user may set to anyone's: a
  student with a valid account who gives "ceo" there is mapped as ceo, into ceo's tables - unless
  FreeRADIUS makes it the name it authenticated: for TLS, os-freeradius's Check TLS Common-Name (off by
  default) refuses a name the certificate does not carry; for PEAP and TTLS, FreeRADIUS's
  `filter_inner_identity` policy, which os-freeradius leaves out, refuses an outer name that is neither
  the inner one nor anonymous; or FreeRADIUS returns the authenticated name to the NAS in the
  Access-Accept, which the NAS then puts in its accounting (RFC 2865 5.1) - os-freeradius does not. So
  name a client only when its names are those FreeRADIUS authenticated: a NAS whose users log on with
  PAP or CHAP, or one behind a FreeRADIUS set up so. A client of Services: FreeRADIUS may also be a
  whole network sharing one secret: naming each NAS by its own address keeps every other device of that
  network out;
- **what a record does** - a Start maps Framed-IP-Address (and Framed-IPv6-Address) to User-Name, as a
  logon: the latest wins. An Interim-Update renews it - one without an address renews the address the
  session had, one with another moves it - but takes back no address a later logon of another user
  took: that user keeps it, and the session's is noted beside it, the clash shown. A Stop takes the
  session's addresses out, but not one another open session of the same user holds - a device that
  roamed, the second access point's Start before the first one's Stop - nor a mapping renewed after the
  Stop's own time - a Stop read late. Accounting-On and Accounting-Off end, the same way, every session
  of the NAS they name by NAS-IP-Address, NAS-IPv6-Address or NAS-Identifier - behind a RADIUS server
  that forwards several, that NAS's alone - and every session of their client when they name none. A
  record's time is when FreeRADIUS wrote it, less the seconds the NAS said it waited: the firewall's
  clock. Read late - after a restart - a Start or an Interim-Update still counts unless it is older than
  the mapping lifetime (stale). Refused: no user, or one that names nobody (anonymous); a computer
  (`host/...`, a name ending in `$`); a MAC address as the name, as a NAS sends for a device let in by
  its MAC alone; with a directory chosen in Groups from, a name written with a realm or a domain that is
  not the directory's - the domain its base DN names, or that domain's first label - as another
  directory's: its groups would be those of a user of the same name in the directory;
- **the captive portal** - the sessions of the zones switched on, read every two seconds from the
  portal's own database (`/var/captiveportal/captiveportal.sqlite`, read-only), as the portal's own
  API lists them and os-xgs-npu's `cp_users.py` reads them: each session's address and its roaming
  addresses are its user's for as long as the portal holds the session - which is as long as it lets
  them through - and leave the map at the first reading after it ends. Refused: the portal's sessions
  of an allowed address or MAC address, those of a zone with no login, and those a voucher opened -
  System: Access: Servers names its server a voucher, and a code anyone may hold is not a user - and,
  with a directory chosen in Groups from, those another server let in, the Local Database among them, as
  the portal says in each session: their users' groups and user tables would be those of a user of the
  same name in the directory;
- **a clash** - two sources that give one address to two users within the lifetime: the later logon
  wins, as between two logons, and the Users tab names the other user and its source. A portal session
  or a RADIUS session that lost its address to a later logon of another user does not take it back
  while that mapping lives; it stays among the others, and the clash shown, until one of them ends. A
  clash that lasts - one account many share on one source, as a shared 802.1X account, each user's own
  logon on the other - ends with that account in Ignore users;
- **a logoff** - a RADIUS Stop and the end of a portal session take the address out when it is still
  their user's, whichever source renewed it last - the surest word there is - unless another session of
  the same user holds it, or, for a Stop, the mapping was renewed after it. A domain controller says
  none, and its mappings end as before;
- **the MAC check** - for the domain controllers' and RADIUS's mappings; a portal session's address is
  the portal's to end;
- **Forget every mapping** - a portal session still open maps its address again within half a minute,
  a RADIUS session at its next Interim-Update, a domain controller's user at its next logon.

## Not yet, and why

- **the page in a browser** - everything below ran on two appliances and a plain OPNsense through the
  page's own paths (its models, configd's actions, its Apply sequence); the page itself has not been
  opened in a browser yet, in either theme or language. Its script runs under node in the checks.
- **the second part on an appliance** - RADIUS accounting and the captive portal ran in the checks
  alone: not yet with os-freeradius and a NAS (or radclient, as phase 0's A9), nor with a portal zone
  and a login, nor with a clash between them and a domain controller.
- **TLS from the domain controllers** - ~~phase 2.~~ Not in the plan's second part, which is RADIUS
  and the captive portal: phase 0's report offered TLS with a client certificate for each domain
  controller as an option, and no part of the plan has taken it up. Today the redirect from the named
  addresses is the gate; a machine on a domain controller's own segment that spoofs its address could
  still send a line.
- **another RADIUS server read directly** - only os-freeradius's accounting, on the firewall: another
  server is read when it forwards its accounting to os-freeradius as one of its clients. Nothing of the
  plugin's listens for RADIUS.
- **the name FreeRADIUS authenticated, checked here** - a record is taken with the name its NAS reports,
  from the RADIUS clients named alone ([above](#radius-and-the-captive-portal)). Nothing os-freeradius
  writes as installed ties the name FreeRADIUS authenticated to a session - its log of authentications,
  off by default, names a tunnel's inner user without the device it came from - so the plugin cannot
  check a record's name against it. An 802.1X client that gives an anonymous outer name maps nobody.
- **a NAS without Interim-Update** - its sessions renew nothing: a mapping ends at the end of its
  lifetime, even while the session goes on. A Framed-IPv6-Prefix maps nothing: an address does.
- **the groups of another directory's users** - groups come from the directory chosen in Settings alone.
  With one chosen, a portal session another server let in - the Local Database among them - and a
  RADIUS name of another realm map nothing; with none chosen, every source's names are one: a user of
  the Local Database is in the table of a user row of the same name. OPNsense's local groups are not
  read.
- **a rule's gateway by user** - phase 3, with os-xgs-npu's hardware side (its pull request for
  route-to in the coprocessor).
- **several domains** - users are known by their logon name: two domains of one forest with a user of
  the same name are one user here, and a forest needs a global catalog.
- **a domain controller sending over IPv6** - the redirect and syslog-ng's source are IPv4; a client's
  IPv6 address maps as any other.
- **a cut when an address leaves a table** - only joining cuts, through XGS: Settings; a connection open
  before its address left a table keeps going until it ends.

## What is tested

On 2026-11-18, from this branch, away from an appliance - the checks, run under Python 3.14 and PHP 8.5:

- **the domain controllers' lines** - `tools/test-events.py`, 103 checks: the 25 lines of phase 0's lab
  (A2, A6, A4) in `tools/fixtures/lab-events.txt`, every address made a documentation one, every name an
  example, each read as the lab saw it - tickets and network logons map, computer accounts, SYSTEM and
  the virtual accounts, a logon with no address, a logoff and a service ticket do not - and lines made
  from them: a refused ticket, a ticket with no pre-authentication, loopback, link-local, multicast,
  broadcast and unspecified addresses, IPv6, a name written `user@REALM` or `DOMAIN\name`, a syslog
  header before the JSON, EventTime in two time zones, in ISO form and as the seconds since 1970 the
  page's NXLog configuration sends, the stale window's edges, the firewall's and a domain
  controller's addresses, Never map, Ignore users, a line nested deeper than json reads; and that
  configuration on the page - no DateFormat, which NXLog CE refuses, integer($EventTime) and
  delete($Message), the note saying what they do, the longest of the lab's lines without its text well
  within one datagram;
- **the map and its tables** - `tools/test-engine.py`, 74 checks: join, renew, latest wins and the
  shared mark, an older event noted, the lifetime's end, the MAC check, the MAC forgotten when another
  user takes the address, the flush, the lab's A6 - three logons on one client in a row - played
  through, the tables of groups and of users, pf through a stand-in (64 addresses a call, a failure
  said, the tables of aliases gone killed), the log's counts without names, the history and its pruning,
  the map's file, its writer and its lock, FreeBSD's `ifconfig -a`, `arp -an` and `ndp -an` output, and
  the settings read from a `config.xml` fixture;
- **the directory** - `tools/test-ldap.py`, 44 checks against a stand-in of ldap3: the filter's escaping
  of a name or a DN, the filters from the entry of System: Access: Servers, TLS for StartTLS, SSL and
  Standard with OPNsense's CA file, direct and nested membership, a group not there, a server refusing
  the in-chain rule - by one of the result codes of a refusal - asked it no more, a timeout or a busy
  server not taken for a refusal, Nested groups off, the Test's answer, a refused bind with the password
  taken out. Its last part runs ldap3 2.9.1's own constructors and filter code, where ldap3 is
  installed, in CI; it was not installed here, so that part has not run yet;
- **the service** - `tools/test-service.py`, 78 checks in a temporary directory: syslog-ng's source
  written, kept, refused for a port in use, a port it may not take, sockstat unreadable and syslog-ng's
  check refusing it, with the file before put back and syslog-ng not restarted, its socket opened again
  after one second, taken away when off; the collector reading the lab's lines through a real datagram
  socket, its counts by reason, a machine that is no domain controller refused, the directory's answer
  filling a group's table and waking the collector at once, latest wins emptying a user's, no directory
  asked when none is chosen, its answers forgotten once their users leave the map, a change of the group
  rows keeping them, marked old, and asking every mapped user again at once, a logon after the minute's
  run written at once, Forget all while it runs - the user asked again at its next logon, and its group's
  table kept by the minute's run after it; the minute's run, Forget all, the plugin off and a
  switched-off alias's table kept empty; the alerts; what `status.py` gives the page;
- **the firewall hook** - `tools/test-firewall-hook.py`, 32 checks, os-xgs-npu's harness: the redirects
  through each OPNsense's own method name (26.7, 26.7.3 to 26.7.8, 27.1), a bad domain controller entry
  left out, a refusing object not stopping the reload, nothing while off or with the source not there,
  nothing on a port the firewall itself serves - SSH, DNS, the web GUI, and where the web GUI or SSH is
  moved - nor without the library that says which those are;
- **the aliases** - `tools/test-aliases.php`, 47 checks, with stand-ins for OPNsense's Alias model whose
  validation is OPNsense 26.7's own for the fields written, pf's reserved words included: the names
  proposed - Latin, spaced, in another script, too long, taken - each taken by that validation; aliases
  made, switched off where a rule names them, the plugin's own rows not counted as naming them,
  described in at most 255 bytes; XGS: Settings' cut list keeping the owner's entries, each table put
  there once and recorded, one the owner took out not put back; and `aliases.php` run as configd runs
  it;
- **the model** - `tools/test-model.php`, 13 checks, with stand-ins for OPNsense's BaseModel and Config:
  the port the domain controllers send to refused when the firewall itself serves it - 22, 53, 80, 443,
  and the ports the web GUI and SSH are moved to - only when it is changed or the whole model checked,
  any other taken; two rows giving one alias name each told;
- **the page's API** - `tools/test-mvc.php`, 34 checks: the status, the grids, Apply's order on and off,
  syslog-ng restarted only when its source changed, Forget all, the Test's names quoted or refused, the
  alias names proposed;
- **the installation** - `tools/test-install.py`, 33 checks, the installer, the removal, the package's
  scripts, `place-menu.sh` and the rc script in a temporary root: every file laid down with its mode and
  taken away, the menu at XGS 60 or under Firewall, nothing copied with a syntax error, syslog-ng's
  source taken away by every removal, nothing done by the old package in an upgrade;
- **the self-update** - `tools/test-self-update.py`, 45 checks, as os-blocklists has it;
- **the strings** - `tools/check-strings.py`: each of the 150 strings the GUI shows is in `source.json`;
  35 have their Arabic in opnsense-arabic already, the other 115 wait for it there;
- **the rest** - every installed file removed by the uninstaller (`tools/check-uninstall.sh`), `php -l`,
  `py_compile` and pyflakes, `sh -n`, XML and JSON, nothing private, no Arabic in the code, the
  copyright line; and, by hand, the page kit (kit) and the page's script run under node with a stand-in
  jQuery - a status, an error, no answer, the plugin off, the source not written, and each grid's
  formatters.

On the appliances, the same day - the second XGS 3300 and the XGS 136 (OPNsense 26.7.9_1, os-xgs-npu at
38a8cc9) and a plain OPNsense 26.7.7 in qemu, every step through the page's own paths (its models,
configd's actions, the Apply sequence of `ServiceController`), config.xml and its backups put back as they
were after each run. The test domain: Windows Server 2025 as its domain controller, a Windows 11 client
joined to it, NXLog CE 3.2.2329 on the domain controller. The photographs are in
`docs/images/measurements/`, each named `phase1-<part>-2026-11-18.png`:

- **install, update, removal** - `install.sh` ended 0 in 4 to 8 s on each, the page at XGS 60 on both
  appliances and under Firewall on the plain OPNsense; run again over the installed plugin from a newer
  commit, as an update, it kept the settings, the map and the tables and started the collector again;
  Apply with the plugin off took out the aliases, their tables and syslog-ng's source; `uninstall.sh`
  ended 0 and left none of its paths (`up`, `update`, `down`, `136-up`, `136-apply`, `136-down`,
  `vm-up`, `vm-apply`, `vm-down`);
- **the way in** - Apply wrote syslog-ng's source on 127.0.0.1:5141 (`time-reopen(1)` accepted), one
  redirect from the domain controller on the chosen interface to it beside os-xgs-npu's own on its
  management port, the three aliases, and their tables in XGS: Settings' cut list. NXLog CE with the
  configuration the page shows, put after the head of its own file, started and connected, and its lines
  reached the collector through syslog-ng with none dropped - 489 in, 489 written (`nxlog`, `refuse`);
- **the map** - u1's logon on the client: mapped, in G-Staff, the client in both its tables; u3's logon
  there next: the address moved to u3, shown shared with u1, out of u1's table and still in G-Staff's -
  u3 is in it through G-Sales; the minute's run after it changed no table. The same after Forget all,
  the directory asked again (`map`, `map-again`);
- **the directory** - the page's Test: u1 in G-Staff directly, u3 through the in-chain rule, by StartTLS
  on 389 to the domain controller's name with the lab's CA in System: Trust, about 125 ms each (`map`);
- **refused** - a line from another machine to the redirected port: no connection; one written to
  syslog-ng's source on the firewall itself: refused, not a domain controller; a logon from the
  firewall's own address (the plugin's LDAP binds): refused; a ticket issued with no pre-authentication -
  a user set so on the domain controller for the test, PreAuthType 0 in its own log: refused, not
  mapped; what NXLog CE kept while stopped, sent six minutes late: stale, not mapped (`refuse`,
  `preauth`, `stale`);
- **logon to let through** - ten runs, each after Forget all, a rule passing G-Staff's table: median
  1.75 s, 1.69 to 3.04 s, from the logon's start to the client's first try let through, on the client's
  own clock; before the directory's answer woke the collector, 3.02 s, 2.82 to 3.25 (`latency`,
  `latency-before-wake`);
- **the cut** - a session from another machine to the client through the 3300 left open; u1's logon put
  the client in G-Staff's table, and at os-xgs-npu's next minute the client's open connections were cut,
  one dropped in hardware first - the session's last line was the second before (`cut`);
- **the MAC check** - another machine told the firewall alone, in three ARP replies, that the client's
  address was its own: at the next minute the mapping ended and both tables emptied; the ARP entry made
  again after (`mac`);
- **the ports** - 22, 53, 80 and 443 refused for the redirect, with the reason; 514 taken (`ports`);
- **a restart** - the 3300 restarted with the plugin on: the collector running 170 s after, syslog-ng's
  source, the redirect, the aliases and the tables as the map held them; NXLog CE connected again by
  itself 3 s after the collector, nothing it kept late enough to be stale (`boot`).

Found by the lab and fixed in this branch: the configuration the page gave NXLog CE did not start it, CE
having no `DateFormat` (bbe3feb); after Forget all a group's table was emptied at each minute while its
user stayed mapped (58f99c9); a group's table was written up to a second after the directory's answer
(1a43c82). `up`, `nxlog`, `map`, `map-again`, `refuse` and `latency-before-wake` ran at 58f99c9, the rest
at 1a43c82.

Not tested: the page in a browser (above).

On 2026-11-19, the second part, from this branch, away from an appliance - the checks, run under
Python 3.14, PHP 8.5 and node 24, every one of the first part's with them:

- **RADIUS accounting and the captive portal** - `tools/test-sources.py`, 71 checks: the three records
  phase 0's lab had FreeRADIUS write for its A9 (Start, Interim-Update, Stop, in
  `tools/fixtures/radacct-detail.txt`, the address a documentation one) and records made from them -
  the detail file's quoting, a record still being written left for the next reading, the record's time
  (Timestamp less Acct-Delay-Time, or its first line), each status by name and by number, what is
  refused and why; the sessions an Interim-Update renews, a Stop ends, another address moves,
  Accounting-On ending its client's sessions alone; the files read as they grow - one never read taken
  whole when written within the lifetime, else from its end, what was read kept across a restart, one
  cut short or made again read from its start, one gone forgotten, a large one read a part at a time.
  The portal: a database with core's tables - the zones switched on, not the sessions deleted, the
  roaming addresses, no database, one that cannot be read, one without its roaming table; the sessions
  refused; and what the map is to do - mapped at the first reading, renewed once a minute, taken out at
  the end, a roaming address added and dropped, the same user logging on again no logoff, another user
  on the device no clash, a later event of another source not taken back but noted, a mapping forgotten
  made again, and a session ended while the collector was down;
- **the map** - `tools/test-engine.py`, 96 checks now: with the first part's, each mapping's source and
  who said it, renewed by another source, an older event naming none, latest wins across two sources and
  the clash, a note that keeps the clash, a logoff - of the user that holds the address or of one among
  the others - the mappings of a source switched off, the MAC check leaving a portal session's address
  alone, and a map the first part wrote read as the domain controllers';
- **the service** - `tools/test-service.py`, 111 checks now: the collector with RADIUS and the portal
  on - a Start mapped, its table and its group's once the directory answered, an Interim-Update renewing,
  a Stop emptying both, read once a second; a computer, the firewall's own address and a stale record
  refused, each counted; a portal session mapped, a voucher's and a zone switched off's not, read every
  two seconds; a domain controller's later event on the same address winning it - the alert naming the
  two sources, the Users tab the clash; the portal's session ending without taking the address back;
  roaming addresses mapped and taken out at the logout; a collector started again ending a session gone
  meanwhile and reading RADIUS on from where it stopped; RADIUS switched off - its sessions forgotten,
  its mapping taken out at the minute; and what `status.py` gives the page;
- **the page's API** - `tools/test-mvc.php`, 36 checks now: each mapping's source - a map of the first
  part's a domain controller's - the other users with theirs, a clash marked; each sender's kind and
  what it ended, in `status.py`'s order;
- **the page's script** - `tools/test-page.js`, 21 checks, under node with stand-ins for jQuery and
  OPNsense's page: the four cards for each status - the clashes said, each source heard or why not, no
  source chosen, the warning about syslog-ng's source only where domain controllers are named, a status
  that cannot be read - and the grids' formatters: each mapping's source, a clash and a share, each
  sender's source and name, the refusals in their source's words;
- **the installation** - `tools/test-install.py`, 33 checks, Python's cache of the sources taken by the
  package's removal too; every file of `src/` removed by the uninstaller (`tools/check-uninstall.sh`);
- **the strings** - `tools/check-strings.py`: each of the 171 strings the GUI shows is in `source.json`;
  28 of them are new - four, Captive Portal, Source, Sender and Zone, are OPNsense's own and have their
  Arabic in opnsense-arabic already; the other 24 wait for it there;
- **the rest** - `php -l`, `py_compile` and pyflakes, `sh -n`, XML and JSON, nothing private, no Arabic in
  the code, the copyright line, and the page kit (kit).

On 2026-11-20, after the second part's review, from this branch, away from an appliance - the same
checks, with one for each thing the review found, each failing without its fix:

- **RADIUS accounting and the captive portal** - `tools/test-sources.py`, 98 checks now: a client not
  named refused before anything else is read of its record - the review's student who gives "ceo" as
  the outer name maps nothing - and a client named by its IPv6 address however its directory writes it;
  a name of another realm or domain refused, its Stop too, while a directory is chosen; a device that
  roams - the second access point's Start, then the first one's Stop - ending nothing, and the second
  Stop ending it; three switches behind one forwarding server, the Accounting-On of one ending its
  session alone, by its address or by its identifier, and one that names no NAS every session of its
  client; an Interim-Update a renewal of the address its session had and a logon of a new one; where
  the reading stood put back; radius.json written at most every ten seconds, and at the end; only the
  days a record within the lifetime can be in read - a day a week old, a compressed file and another
  module's never - and the file of a day past the lifetime forgotten; a portal session the Local
  Database let in refused as another directory's; every reason refused for named on the page;
- **the map** - `tools/test-engine.py`, 110 checks now: a logoff said before the mapping's last renewal,
  as a Stop read an hour late, ending nothing, and a user noted after a logoff staying among the others;
  an Interim-Update of an address a later domain logon took noted, not taken back, at every interval;
  a domain controller no longer named leaving its mappings to their lifetime; the RADIUS clients named
  and the directory's realms read from `config.xml`;
- **the service** - `tools/test-service.py`, 127 checks now, through the collector: a client not named
  counted as refused and listed as not named; a roam between two clients keeping the address and its
  table; a Stop an hour older than a domain logon a second before ending nothing; a shared account's
  Interim-Updates after a domain logon leaving the address with the domain user, the clash shown; /var
  full while a Stop and a portal logout come - the map not saved, both read again at the next reading
  and applied, each counted once; a Local Database portal session and a RADIUS name of another realm
  refused and counted; a RADIUS client taken out of Settings - its sessions forgotten, its mapping out at
  the minute - beside a domain controller taken out, whose mappings stay;
- **the page's script** - `tools/test-page.js`, 23 checks now: no RADIUS client named said on the
  sources card, and a client not named and a user of another directory among Sources' refusals;
- **the strings** - `tools/check-strings.py`: each of the 177 strings the GUI shows is in `source.json`;
  30 of them wait for their Arabic in opnsense-arabic;
- **the rest** - the other checks as on 2026-11-19, each passing, and `php -l`, `py_compile` and
  pyflakes, `sh -n`, XML and JSON, nothing private, no Arabic in the code, the copyright line, and the
  page kit (kit).

## Installation

It is not in the OPNsense plugin repository, so there is no `pkg install os-useridentity`, and there is
no release yet.

**From a checkout** of this repository, on the firewall, as root:

```sh
sh install/install.sh
```

It checks the PHP with `php -l` and the Python with `py_compile` before anything is copied, copies
`src/` onto `/usr/local`, puts the page in the menu (`place-menu.sh`: XGS with os-xgs-npu, Firewall
without), and does what the page's Apply does. Nothing is mapped until it is on, with domain
controllers named in Settings, a directory chosen and group or user rows given. Safe to run again: the
settings in config.xml are kept. No package is needed beside it: py-ldap3 is part of OPNsense's core.

Then, on each domain controller: NXLog Community Edition, with the configuration Sources shows. For
RADIUS accounting: os-freeradius, each NAS a client of it with its accounting sent there, and named in
Settings' RADIUS clients when its names are the ones FreeRADIUS authenticated
([above](#radius-and-the-captive-portal)). For the captive portal: a zone of Services: Captive Portal
with a login.

`sh install/uninstall.sh` stops the collector, forgets the map, takes the plugin's aliases out of
Firewall: Aliases and XGS: Settings' cut list (switched off instead where a rule or a setting still
names one), takes syslog-ng's source away, removes its files and its state, and takes the tables of the
aliases gone out of pf. The settings stay in config.xml.

**From a package**, once there is a release: `tools/make-package.sh` builds it on a firewall, and
`release.yml` in a FreeBSD virtual machine for each release, as os-blocklists does.

## Updates

As os-blocklists: taken by hand, to this repository's **releases** - from **XGS: Updates**, its
*Plugins* tab, where an os-xgs-npu that lists this plugin is installed, or by running
`/usr/local/opnsense/scripts/useridentity/self-update.py` (`check` to ask). A release is installed only
as its owner signed it (`release.json` and its Ed25519 signature, the public key in `release-keys/`),
only forward, by the `install/install.sh` it carries. No cron entry runs it.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue. It installs the same on a plain OPNsense, where pf alone holds the tables and the page says that no open connection is cut.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE).
