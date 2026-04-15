# Linux Hardener - System Hardening & Security Audit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](https://www.kernel.org/)

A comprehensive Linux system hardening tool that audits systems against security best practices and CIS benchmarks. Generates a hardening score and provides remediation recommendations.

## 🚀 Features

### Security Checks (12 categories)

| Category | Checks | Points |
|----------|--------|--------|
| **System Updates** | OS version, available updates | 15 |
| **Services** | Dangerous/unnecessary services | 10 per service |
| **SSH Configuration** | Root login, password auth, protocol | 30 |
| **File Permissions** | Critical system files | 10 per file |
| **Firewall** | UFW, firewalld, iptables | 15 |
| **Audit Logging** | auditd status | 10 |
| **Failed Logins** | Brute force detection | 5 |
| **SUID Binaries** | Suspicious SUID files | up to 10 |
| **Password Policy** | Aging, quality requirements | 10 |
| **Kernel Parameters** | Security sysctl settings | 15 |
| **Core Dumps** | Restriction settings | 5 |
| **Mount Options** | Secure filesystem options | 5 |

### What Gets Checked

- ✅ OS updates (last 30 days)
- ✅ Dangerous services (telnet, FTP, rsh, etc.)
- ✅ SSH configuration (root login, password auth, protocol)
- ✅ File permissions (/etc/passwd, /etc/shadow, /etc/sudoers)
- ✅ Firewall status (ufw, firewalld, iptables)
- ✅ Audit logging (auditd)
- ✅ Failed login attempts
- ✅ SUID binaries (suspicious)
- ✅ Password policy (aging, quality)
- ✅ Kernel parameters (rp_filter, tcp_syncookies, ASLR)
- ✅ Core dump restrictions
- ✅ Mount options (noexec, nosuid, nodev)

## 📋 Requirements

- **Linux** (Ubuntu, Debian, RHEL, CentOS, Fedora)
- **Python 3.6** or higher
- **Root privileges** (for full audit)

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/joshuaguda281-stack/linux-hardener.git
cd linux-hardener

# No dependencies required! Python 3.6+ only


📁 Report Format
The tool generates a JSON report:

{
    "timestamp": "2024-01-15T14:30:00",
    "score": 85,
    "rating": "GOOD",
    "passed": [
        "OS: Ubuntu/Debian detected",
        "System is up to date",
        "No dangerous services detected"
    ],
    "warnings": [
        "/etc/sudoers has unusual permissions: 644 (expected 440)",
        "Audit logging not enabled"
    ],
    "failed": [],
    "remediations": [
        "Fix permissions: sudo chmod 440 /etc/sudoers",
        "Install auditd: sudo apt install auditd -y && sudo systemctl enable --now auditd"
    ]
}



🎯 Use Cases
New Server Deployment - Harden fresh Linux installations

Compliance Auditing - Verify security configurations (CIS benchmarks)

Incident Response - Identify and remediate security gaps

Regular Maintenance - Monthly security posture checks

Security Baseline - Establish and maintain security standards

📋 CIS Benchmark Mapping
Check	CIS Control
SSH Configuration	5.2 - SSH Server Configuration
File Permissions	6.1 - System File Permissions
Firewall	3.5 - Firewall Configuration
Audit Logging	4.1 - Configure System Accounting
Password Policy	5.3 - Password Policy
Kernel Parameters	3.3 - Network Parameters
SUID Binaries	6.1.9 - SUID/SGID Binaries
🔧 Troubleshooting
Issue	Solution
Permission denied	Run with sudo
Command not found	Some checks require specific packages (e.g., ufw, auditd)
Python version error	Ensure Python 3.6+ is installed
📝 License
MIT License - See LICENSE file for details.

👤 Author
Joshua Guda

GitHub: @joshuaguda281-stack

LinkedIn: Joshua Guda

🙏 Acknowledgments
CIS (Center for Internet Security) for benchmarks

Ubuntu/Debian security team

OpenSCAP project

⭐ Support
If this tool helps you secure Linux systems, please star the repository!
