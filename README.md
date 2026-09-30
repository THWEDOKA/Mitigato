<div align="center">

<img src="assets/mitigato-hero.gif" alt="Animated Mitigato banner" width="960" />

# Mitigato

**Spot a DDoS attack early. Get alerted. Apply a first line of defense.**

An upcoming server-side tool for quick setup, traffic monitoring, DDoS alerts, and basic firewall protection.

[**English**](README.md) · [Русский](README.ru.md)

![Project status: early development](https://img.shields.io/badge/status-early%20development-153347?style=flat-square&labelColor=0d1a27&color=30bfa9)
![License: not chosen yet](https://img.shields.io/badge/license-to%20be%20decided-153347?style=flat-square&labelColor=0d1a27&color=30bfa9)

</div>

---

## The idea

Install Mitigato on a server, finish a short setup, and keep an eye on its traffic. When the monitoring rules detect a possible DDoS attack, Mitigato will send an alert through your configured SMTP server and Telegram bot. Basic firewall rules will provide an initial layer of server protection.

<div align="center">
<img src="assets/mitigato-signal.gif" alt="Animated traffic signal" width="520" />
</div>

| Planned capability | What it is for |
| :--- | :--- |
| ⚡ **Fast setup** | Install on a server and complete the initial configuration in a few steps. |
| 📈 **Traffic monitoring** | Watch for traffic patterns that may indicate a DDoS attack. |
| ✉️ **SMTP alerts** | Send attack notifications to a configured email destination. |
| 🤖 **Telegram alerts** | Notify operators through a configured Telegram bot. |
| 🛡️ **Firewall basics** | Apply basic server-side firewall protection. |

## Intended flow

```mermaid
flowchart LR
    A[Server traffic] --> B[Mitigato monitoring]
    B --> C{Possible attack?}
    C -- No --> B
    C -- Yes --> D[Alert]
    D --> E[SMTP email]
    D --> F[Telegram bot]
    B --> G[Basic firewall protection]
```

## Project status

Mitigato is at the **early development** stage. This repository does not yet contain an installable release. The capabilities above describe the product direction, not shipped functionality. Installation commands and configuration examples will be added when an implementation is available.

### Roadmap

- [ ] Server installation and short setup flow
- [ ] Traffic monitoring and attack detection rules
- [ ] SMTP and Telegram alert delivery
- [ ] Basic firewall protection
- [ ] Installation, configuration, and operation guides

## Follow the project

Watch this repository for development updates. If you have a use case or a feature request, [open an issue](https://github.com/THWEDOKA/Mitigato/issues).

<div align="center">

---

**Mitigato** · Made to make server protection easier to start.

</div>
