# Attack Surface Monitor — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 6 September 2026*

---

## The problem starts with something perfectly reasonable
Someone spins up staging.company.com for a client demo. The demo goes well, the client is happy, everyone moves on to the next thing.
That server is still running. It is still running the version of the application from eight months ago. Its admin panel still has the password someone picked in a hurry. And nobody in the company remembers it exists.
No one was careless. This is how organisations normally work: things built to be temporary are rarely switched off, because switching them off was never anyone's job.
Everything like that — exposed to the internet, reachable by outsiders — is what people mean by your attack surface.
## Why an attacker finds it before you do
There is a difference in point of view that decides everything:
- You see your infrastructure from the inside — from a server list, from documentation, from memory.
- An attacker sees it from the outside, and carries no assumptions about what is supposed to be there.
They are not looking for your important servers. They scan the whole internet, note what answers, and look for the weakest thing. That forgotten staging box is the ideal target precisely because it is real, connected to the same network, and watched by no one.
## How forgotten assets can be found without guessing
Here is where one little-known detail becomes decisive.
Every time a site is issued an HTTPS certificate, the issuer is required to record it in a Certificate Transparency log — a public ledger anyone can read. The rule exists for a good reason: if someone issues a fraudulent certificate for your domain, the evidence is visible.

The side effect: a company's list of subdomain names is often already public, with no guessing required. staging., vpn-old., backup., test2. — if it ever had a certificate, the name is in there.
ASM reads that list, then checks which of those names are still actually alive. Anything that does not resolve is discarded. What remains is your real attack surface.
## What gets checked once an asset is found
On assets you have proven you own, ASM checks the things that most often turn out to be real ways in:
- Databases reachable from the internet. PostgreSQL, MySQL, MongoDB, Redis. A database should only be reachable by your application, not by anyone on the internet. This shows up far more often than people expect — usually because of one firewall rule added for debugging and never removed.
- Open remote access. RDP, VNC or Telnet facing the internet is a standing invitation to try passwords over and over.
- Every other open port, so you know what is actually answering.
## The part that makes it useful every day: what changed
Scanning once produces a long list that makes people give up.
What is genuinely useful is the difference from yesterday:
- A new subdomain appears → a new finding
- A port that used to be closed is now open → a new finding
- A port you closed → the finding disappears on its own
So after the first day you are no longer looking at a long list, but at a short list of things that changed. That is something a real person can work through each morning.
## One limit you should know before you judge the results
When we ran ASM against our own domain, hexwardlabs.com, it returned one asset — even though bridge.hexwardlabs.com is plainly alive and reachable by anyone.
Why? Because that domain uses a wildcard certificate — a single *.hexwardlabs.com certificate covering every subdomain at once.

So there was nothing to find from that source, and ASM does not guess names.
We put this up front rather than hiding it, because if you run it against a wildcard domain and see a small number, you deserve to know why. A small number on a domain like that is not evidence that your surface is small.
Since 5 September, ASM tells you this itself: when it detects a wildcard certificate it raises a coverage note before showing the inventory, so the report admits its own blind spot instead of letting a low number speak for itself. That note is filed as informational, not as a problem with your setup — owning a wildcard certificate is perfectly sensible. The limitation is ours, and it would be wrong to score you for it.
## Why ASM refuses to scan until you prove ownership
Before it scans anything, ASM asks for proof that the domain is yours — via a single DNS TXT record, or a file on that server.
This is not a formality. Port-scanning someone else's systems without permission is a legal problem in many countries, and a tool that scans whatever its user types in is a tool that sooner or later gets used for exactly that.
The boundary is permanent and cannot be switched off.
## What changes once you are using it
Before: you have a list of the servers you remember, and you hope it is complete.
After: you have a list of what is provably alive and visible from outside, plus a notice every time something is added to it.
That sounds like a small change, right up until the day the thing that was added is not something you built.
## Try it yourself — 15 minutes
The free Apache-2.0 edition on GitHub runs the same engine, one domain, with no time limit.
```
curl -LO https://github.com/nizartuanku/attack-surface-monitor/releases/latest/download/asm-free-0.1.1-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/attack-surface-monitor/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf asm-free-0.1.1-linux-amd64.tar.gz && ./asm
```
Open 127.0.0.1:8423, enter one domain you own, publish its verification TXT record, and see what comes back.
If what comes back surprises you — that is rather the point.
Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/attack-surface-monitor

## Terms used above

- Certificate Transparency (CT) — a public list of every HTTPS certificate ever issued. Readable by anyone, including you, and including an attacker.
- Wildcard certificate — one certificate for all subdomains. Convenient for the administrator, but it means no individual subdomain name has ever appeared in a CT log.
