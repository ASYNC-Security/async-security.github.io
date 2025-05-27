---
layout: page
author: "Zavier Lee"
author_avatar: "./assets/img/authors/zavier.png"
author_title: "Offensive Security Engineer"
author_twitter: "https://x.com/gatariee"
author_github: "https://github.com/gatariee"
---

# SINCON CTF 2025: Too Much Administration

This is the second, and final part of the SINCON CTF 2025 writeup series where I covered the more "challenging" parts of the CTF. I'd highly recommend reading the first part: [SINCON 2025: All Too Relayxing](https://blog.async.sg/sincon-2025-adcs-relay.html) as it provides a lot of necessary context for this writeup.

In this writeup, I'll be covering the solve path for Flag 8 - which involved bypassing [Just Enough Administration (JEA)](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview?view=powershell-7.5). For many participants, this was their first time encountering WinRM endpoints protected by JEA, and you'll rarely see this in engagements aside from some hardened environments. However, JEA can be a double-edged sword; if not properly configured, it opens up opportunities for abuse and privilege escalation.

## Introduction

![](./assets/img/sincon-2/scenario.jpg)

The current scenario is explained in more depth in the first part of the writeup, but to summarize, we have compromised `TABULARIUM` and `SCRIPTORIUM`. Additionally, we have access to a `JESS\Doros_ARCHIVON` user from a previous attack path. The next target is `PORTICUS`.