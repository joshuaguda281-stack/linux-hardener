#!/usr/bin/env python3
"""
Linux Hardener - System Hardening and Security Audit Tool
==========================================================

Audits Linux systems against security best practices and CIS benchmarks.
Generates a hardening score and provides remediation recommendations.


Author: [Joshua Guda]
GitHub: [https://github.com/joshuaguda281-stack]
Created: 2024
License: MIT

Features:
- OS version and update check
- Unnecessary services detection
- SSH configuration audit
- File permission checks
- Firewall status verification
- Audit logging verification
- Failed login monitoring
- SUID binary detection
- Password policy enforcement
- Kernel parameter checks
- Mount option verification
- Core dump restrictions

Usage:
    sudo python3 linux_hardener.py              # Run full audit
    sudo python3 linux_hardener.py --fix        # Apply fixes (where possible)
    sudo python3 linux_hardener.py --output report.json
    sudo python3 linux_hardener.py --verbose
"""

import os
import subprocess
import sys
import json
import re
import grp
import pwd
from pathlib import Path
from datetime import datetime
import argparse

class LinuxHardener:
    def __init__(self, apply_fixes=False, verbose=False):
        self.apply_fixes = apply_fixes
        self.verbose = verbose
        self.checks = []
        self.results = {
            'passed': [],
            'failed': [],
            'warnings': []
        }
        self.remediations = []
        self.score = 100  # Start at 100, subtract for failures
        
        # Color codes for output
        self.colors = {
            'green': '\033[92m',
            'red': '\033[91m',
            'yellow': '\033[93m',
            'cyan': '\033[96m',
            'magenta': '\033[95m',
            'reset': '\033[0m'
        }
    
    def print_color(self, text, color):
        """Print colored text"""
        if self.verbose:
            print(f"{self.colors.get(color, '')}{text}{self.colors['reset']}")
        else:
            print(text)
    
    def run_command(self, cmd):
        """Run command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", 1
        except Exception:
            return "", 1
    
    def file_exists(self, filepath):
        """Check if file exists"""
        return os.path.exists(filepath)
    
    def check_os_updates(self):
        """Check OS version and available updates"""
        print(f"{self.colors['cyan']}[*] Checking OS updates...{self.colors['reset']}")
        
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'Ubuntu' in content or 'Debian' in content:
                    self.results['passed'].append("OS: Ubuntu/Debian detected")
                    if self.verbose:
                        print(f"  {self.colors['green']}[+] OS: Ubuntu/Debian detected{self.colors['reset']}")
                elif 'CentOS' in content or 'RHEL' in content or 'Fedora' in content:
                    self.results['passed'].append("OS: RHEL/CentOS/Fedora detected")
                    if self.verbose:
                        print(f"  {self.colors['green']}[+] OS: RHEL/CentOS/Fedora detected{self.colors['reset']}")
                else:
                    self.results['warnings'].append(f"OS: Unknown distribution")
            
            # Check for available updates
            stdout, code = self.run_command("apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0")
            updates = int(stdout) if stdout.isdigit() else 0
            
            if updates > 0:
                self.results['failed'].append(f"System updates available: {updates} packages")
                self.score -= min(updates // 5, 15)
                self.remediations.append(f"Run: sudo apt update && sudo apt upgrade -y ({updates} updates)")
                print(f"  {self.colors['red']}[!] {updates} updates available{self.colors['reset']}")
            else:
                self.results['passed'].append("System is up to date")
                print(f"  {self.colors['green']}[+] System is up to date{self.colors['reset']}")
                
        except FileNotFoundError:
            self.results['warnings'].append("Cannot check OS version - /etc/os-release not found")
    
    def check_unnecessary_services(self):
        """Check for running unnecessary services"""
        print(f"{self.colors['cyan']}[*] Checking unnecessary services...{self.colors['reset']}")
        
        # Services to check (insecure or unnecessary)
        dangerous_services = [
            'telnet', 'ftp', 'rsh', 'rexec', 'rlogin',
            'finger', 'tftp', 'nfs-server', 'nfs-kernel-server',
            'cups', 'avahi-daemon', 'bluetooth', 'whoopsie'
        ]
        
        running = []
        for service in dangerous_services:
            stdout, code = self.run_command(f"systemctl is-active {service} 2>/dev/null")
            if stdout and 'active' in stdout:
                running.append(service)
        
        if running:
            self.results['failed'].append(f"Dangerous services running: {', '.join(running)}")
            self.score -= 10 * len(running)
            for service in running:
                self.remediations.append(f"Disable {service}: sudo systemctl disable --now {service}")
            print(f"  {self.colors['red']}[!] Dangerous services: {', '.join(running)}{self.colors['reset']}")
        else:
            self.results['passed'].append("No dangerous services detected")
            print(f"  {self.colors['green']}[+] No dangerous services detected{self.colors['reset']}")
    
    def check_ssh_config(self):
        """Check SSH configuration security"""
        print(f"{self.colors['cyan']}[*] Checking SSH configuration...{self.colors['reset']}")
        
        ssh_config_path = '/etc/ssh/sshd_config'
        if not self.file_exists(ssh_config_path):
            self.results['warnings'].append("SSH not installed or config not found")
            return
        
        issues = []
        with open(ssh_config_path, 'r') as f:
            config = f.read()
        
        # Check for insecure settings
        if re.search(r'^PermitRootLogin yes', config, re.MULTILINE):
            issues.append("Root login allowed")
            self.score -= 10
            self.remediations.append("Disable root login: Set 'PermitRootLogin no' in /etc/ssh/sshd_config")
            print(f"  {self.colors['red']}[!] Root login allowed{self.colors['reset']}")
        
        if re.search(r'^PasswordAuthentication yes', config, re.MULTILINE):
            issues.append("Password authentication enabled (use SSH keys)")
            self.score -= 5
            self.remediations.append("Use key-based auth: Set 'PasswordAuthentication no' in /etc/ssh/sshd_config")
            print(f"  {self.colors['yellow']}[!] Password authentication enabled{self.colors['reset']}")
        
        if re.search(r'^Protocol 1', config, re.MULTILINE):
            issues.append("SSH Protocol 1 enabled (insecure)")
            self.score -= 15
            self.remediations.append("Disable SSHv1: Set 'Protocol 2' in /etc/ssh/sshd_config")
            print(f"  {self.colors['red']}[!] SSH Protocol 1 enabled (insecure){self.colors['reset']}")
        
        # Check for secure settings
        if re.search(r'^PermitRootLogin no', config, re.MULTILINE) or '#PermitRootLogin' in config:
            self.results['passed'].append("SSH root login disabled")
            if self.verbose:
                print(f"  {self.colors['green']}[+] SSH root login disabled{self.colors['reset']}")
        
        if re.search(r'^PubkeyAuthentication yes', config, re.MULTILINE):
            self.results['passed'].append("SSH key authentication enabled")
            if self.verbose:
                print(f"  {self.colors['green']}[+] SSH key authentication enabled{self.colors['reset']}")
        
        if re.search(r'^MaxAuthTries', config, re.MULTILINE):
            self.results['passed'].append("SSH max auth tries configured")
        
        if not issues:
            self.results['passed'].append("SSH securely configured")
            print(f"  {self.colors['green']}[+] SSH securely configured{self.colors['reset']}")
    
    def check_file_permissions(self):
        """Check for weak file permissions on critical files"""
        print(f"{self.colors['cyan']}[*] Checking file permissions...{self.colors['reset']}")
        
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/ssh/ssh_config',
            '/etc/crontab', '/etc/hosts', '/etc/resolv.conf'
        ]
        
        expected_perms = {
            '/etc/passwd': '644',
            '/etc/shadow': '640',
            '/etc/sudoers': '440',
            '/etc/ssh/sshd_config': '644',
            '/etc/ssh/ssh_config': '644',
            '/etc/crontab': '644',
            '/etc/hosts': '644',
            '/etc/resolv.conf': '644'
        }
        
        for file in critical_files:
            if self.file_exists(file):
                stat_info = os.stat(file)
                permissions = oct(stat_info.st_mode)[-3:]
                expected = expected_perms.get(file, '644')
                
                # Check for world-writable
                if permissions[-1] in ['6', '7']:
                    self.results['failed'].append(f"{file} is world-writable ({permissions})")
                    self.score -= 10
                    self.remediations.append(f"Fix permissions: sudo chmod {expected} {file}")
                    print(f"  {self.colors['red']}[!] {file} world-writable!{self.colors['reset']}")
                elif permissions != expected:
                    self.results['warnings'].append(f"{file} has unusual permissions ({permissions})")
                    print(f"  {self.colors['yellow']}[!] {file} has unusual permissions: {permissions} (expected {expected}){self.colors['reset']}")
                else:
                    self.results['passed'].append(f"{file} permissions OK ({permissions})")
                    if self.verbose:
                        print(f"  {self.colors['green']}[+] {file} permissions OK{self.colors['reset']}")
            else:
                self.results['warnings'].append(f"{file} not found")
    
    def check_firewall(self):
        """Check if firewall is active and has rules"""
        print(f"{self.colors['cyan']}[*] Checking firewall status...{self.colors['reset']}")
        
        # Check for ufw (Ubuntu/Debian)
        stdout, code = self.run_command("ufw status 2>/dev/null | grep -c 'Status: active'")
        if stdout and int(stdout) > 0:
            self.results['passed'].append("Firewall (ufw) active")
            print(f"  {self.colors['green']}[+] Firewall (ufw) active{self.colors['reset']}")
            return
        
        # Check for firewalld (RHEL/CentOS/Fedora)
        stdout, code = self.run_command("firewall-cmd --state 2>/dev/null")
        if stdout and 'running' in stdout:
            self.results['passed'].append("Firewall (firewalld) active")
            print(f"  {self.colors['green']}[+] Firewall (firewalld) active{self.colors['reset']}")
            return
        
        # Check for iptables
        stdout, code = self.run_command("sudo iptables -L -n 2>/dev/null | grep -c 'ACCEPT\\|DROP\\|REJECT'")
        if stdout and int(stdout) > 5:
            self.results['passed'].append("Firewall (iptables) active with rules")
            print(f"  {self.colors['green']}[+] Firewall (iptables) active with rules{self.colors['reset']}")
            return
        
        # No firewall detected
        self.results['failed'].append("No active firewall detected")
        self.score -= 15
        self.remediations.append("Enable firewall: sudo ufw enable && sudo ufw default deny incoming")
        print(f"  {self.colors['red']}[!] No firewall active!{self.colors['reset']}")
    
    def check_audit_logging(self):
        """Check if auditd is running"""
        print(f"{self.colors['cyan']}[*] Checking audit logging...{self.colors['reset']}")
        
        stdout, code = self.run_command("systemctl is-active auditd 2>/dev/null")
        if stdout and 'active' in stdout:
            self.results['passed'].append("Audit logging (auditd) is running")
            print(f"  {self.colors['green']}[+] Audit logging active{self.colors['reset']}")
        else:
            self.results['warnings'].append("Audit logging not enabled")
            self.score -= 10
            self.remediations.append("Install auditd: sudo apt install auditd -y && sudo systemctl enable --now auditd")
            print(f"  {self.colors['yellow']}[!] Audit logging not enabled{self.colors['reset']}")
    
    def check_failed_logins(self):
        """Check for recent failed login attempts"""
        print(f"{self.colors['cyan']}[*] Checking failed login attempts...{self.colors['reset']}")
        
        stdout, code = self.run_command("lastb 2>/dev/null | wc -l")
        failed = int(stdout) if stdout.isdigit() else 0
        
        if failed > 10:
            self.results['warnings'].append(f"Recent failed logins: {failed}")
            self.score -= 5
            print(f"  {self.colors['yellow']}[!] {failed} failed login attempts in logs{self.colors['reset']}")
        else:
            self.results['passed'].append(f"Only {failed} failed logins recorded")
            print(f"  {self.colors['green']}[+] Only {failed} failed logins{self.colors['reset']}")
    
    def check_suid_binaries(self):
        """Check for unusual SUID binaries"""
        print(f"{self.colors['cyan']}[*] Checking SUID binaries...{self.colors['reset']}")
        
        stdout, code = self.run_command("find / -perm -4000 -type f 2>/dev/null")
        suid_binaries = stdout.split('\n') if stdout else []
        
        # Common legitimate SUID binaries
        legitimate = [
            '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/su',
            '/usr/bin/gpasswd', '/usr/bin/chfn', '/usr/bin/chsh',
            '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/pkexec',
            '/usr/bin/crontab', '/usr/bin/at', '/usr/bin/fusermount'
        ]
        
        suspicious = [b for b in suid_binaries if b not in legitimate and b and '/snap/' not in b]
        
        if suspicious:
            self.results['warnings'].append(f"Suspicious SUID binaries: {len(suspicious)}")
            self.score -= min(len(suspicious), 10)
            print(f"  {self.colors['yellow']}[!] Found {len(suspicious)} unusual SUID binaries{self.colors['reset']}")
            for bin_path in suspicious[:5]:
                print(f"      - {bin_path}")
                self.remediations.append(f"Review SUID binary: {bin_path} (remove if not needed)")
        else:
            self.results['passed'].append("No suspicious SUID binaries found")
            print(f"  {self.colors['green']}[+] No suspicious SUID binaries found{self.colors['reset']}")
    
    def check_password_policy(self):
        """Check password policy settings"""
        print(f"{self.colors['cyan']}[*] Checking password policy...{self.colors['reset']}")
        
        # Check for password aging
        stdout, code = self.run_command("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
        if stdout:
            max_days_match = re.search(r'(\d+)', stdout)
            if max_days_match:
                max_days = int(max_days_match.group(1))
                if max_days <= 90:
                    self.results['passed'].append(f"Password max age: {max_days} days (good)")
                    print(f"  {self.colors['green']}[+] Password max age: {max_days} days{self.colors['reset']}")
                else:
                    self.results['warnings'].append(f"Password max age too high: {max_days} days")
                    self.score -= 5
                    self.remediations.append("Set password max age: edit /etc/login.defs (PASS_MAX_DAYS 90)")
                    print(f"  {self.colors['yellow']}[!] Password max age too high: {max_days}{self.colors['reset']}")
        else:
            self.results['warnings'].append("Password aging not configured")
            self.score -= 5
            self.remediations.append("Configure password aging in /etc/login.defs")
            print(f"  {self.colors['yellow']}[!] Password aging not configured{self.colors['reset']}")
        
        # Check for password quality requirements
        stdout, code = self.run_command("grep 'pam_pwquality.so' /etc/pam.d/common-password 2>/dev/null")
        if stdout:
            self.results['passed'].append("Password quality requirements configured")
            if self.verbose:
                print(f"  {self.colors['green']}[+] Password quality requirements configured{self.colors['reset']}")
        else:
            self.results['warnings'].append("Password quality requirements not configured")
            self.score -= 5
            self.remediations.append("Install libpam-pwquality and configure password strength requirements")
            print(f"  {self.colors['yellow']}[!] Password quality requirements not configured{self.colors['reset']}")
    
    def check_kernel_parameters(self):
        """Check kernel security parameters"""
        print(f"{self.colors['cyan']}[*] Checking kernel parameters...{self.colors['reset']}")
        
        kernel_params = {
            'net.ipv4.conf.all.rp_filter': '1',
            'net.ipv4.conf.default.rp_filter': '1',
            'net.ipv4.tcp_syncookies': '1',
            'net.ipv4.ip_forward': '0',
            'net.ipv4.conf.all.accept_redirects': '0',
            'net.ipv6.conf.all.accept_redirects': '0',
            'kernel.randomize_va_space': '2'
        }
        
        for param, expected in kernel_params.items():
            stdout, code = self.run_command(f"sysctl -n {param} 2>/dev/null")
            if stdout and stdout.strip() == expected:
                self.results['passed'].append(f"Kernel param {param} = {expected}")
                if self.verbose:
                    print(f"  {self.colors['green']}[+] {param} = {expected}{self.colors['reset']}")
            else:
                actual = stdout.strip() if stdout else 'not set'
                self.results['warnings'].append(f"Kernel param {param} = {actual} (expected {expected})")
                self.score -= 2
                self.remediations.append(f"Set {param}={expected} in /etc/sysctl.conf")
                print(f"  {self.colors['yellow']}[!] {param} = {actual} (expected {expected}){self.colors['reset']}")
    
    def check_core_dumps(self):
        """Check core dump restrictions"""
        print(f"{self.colors['cyan']}[*] Checking core dump restrictions...{self.colors['reset']}")
        
        # Check limits.conf
        stdout, code = self.run_command("grep -c 'hard core 0' /etc/security/limits.conf 2>/dev/null")
        if stdout and int(stdout) > 0:
            self.results['passed'].append("Core dumps restricted in limits.conf")
            if self.verbose:
                print(f"  {self.colors['green']}[+] Core dumps restricted{self.colors['reset']}")
        else:
            self.results['warnings'].append("Core dumps not restricted")
            self.score -= 5
            self.remediations.append("Add '* hard core 0' to /etc/security/limits.conf")
            print(f"  {self.colors['yellow']}[!] Core dumps not restricted{self.colors['reset']}")
    
    def check_mount_options(self):
        """Check filesystem mount options"""
        print(f"{self.colors['cyan']}[*] Checking mount options...{self.colors['reset']}")
        
        with open('/etc/fstab', 'r') as f:
            fstab = f.read()
        
        secure_options = ['noexec', 'nosuid', 'nodev']
        issues = []
        
        for option in secure_options:
            if option not in fstab and '/tmp' in fstab:
                issues.append(f"/tmp missing {option} option")
        
        if issues:
            self.results['warnings'].extend(issues)
            self.score -= 5
            for issue in issues:
                print(f"  {self.colors['yellow']}[!] {issue}{self.colors['reset']}")
                self.remediations.append(f"Add {issue.split(' ')[-1]} to /etc/fstab for /tmp")
        else:
            self.results['passed'].append("Secure mount options configured")
            print(f"  {self.colors['green']}[+] Secure mount options configured{self.colors['reset']}")
    
    def apply_remediations(self):
        """Apply automatic fixes where possible"""
        if not self.apply_fixes:
            return
        
        print(f"\n{self.colors['magenta']}[*] Applying fixes...{self.colors['reset']}")
        
        for remediation in self.remediations:
            if remediation.startswith("Run:"):
                cmd = remediation.replace("Run:", "").strip()
                print(f"  {self.colors['cyan']}Running: {cmd}{self.colors['reset']}")
                stdout, code = self.run_command(cmd)
                if code == 0:
                    print(f"    {self.colors['green']}✓ Success{self.colors['reset']}")
                else:
                    print(f"    {self.colors['red']}✗ Failed{self.colors['reset']}")
            elif remediation.startswith("Disable"):
                print(f"  {self.colors['yellow']}Manual action required: {remediation}{self.colors['reset']}")
            elif remediation.startswith("Fix permissions"):
                print(f"  {self.colors['yellow']}Manual action required: {remediation}{self.colors['reset']}")
            else:
                print(f"  {self.colors['yellow']}Manual action required: {remediation}{self.colors['reset']}")
    
    def generate_report(self):
        """Generate hardening report"""
        print(f"\n{self.colors['magenta']}{'='*70}{self.colors['reset']}")
        print(f"{self.colors['cyan']}LINUX HARDENING REPORT{self.colors['reset']}")
        print(f"{self.colors['magenta']}{'='*70}{self.colors['reset']}")
        print(f"HARDENING SCORE: {self.score}/100")
        
        if self.score >= 90:
            rating = "EXCELLENT - System well hardened"
            rating_color = 'green'
        elif self.score >= 75:
            rating = "GOOD - Some improvements needed"
            rating_color = 'green'
        elif self.score >= 60:
            rating = "FAIR - Significant hardening required"
            rating_color = 'yellow'
        else:
            rating = "POOR - System at high risk"
            rating_color = 'red'
        
        print(f"RATING: {self.colors[rating_color]}{rating}{self.colors['reset']}")
        
        print(f"\n{self.colors['magenta']}{'-'*70}{self.colors['reset']}")
        print(f"{self.colors['green']}PASSED CHECKS: {len(self.results['passed'])}{self.colors['reset']}")
        for item in self.results['passed'][:20]:
            print(f"  ✓ {item}")
        
        if self.results['warnings']:
            print(f"\n{self.colors['magenta']}{'-'*70}{self.colors['reset']}")
            print(f"{self.colors['yellow']}WARNINGS: {len(self.results['warnings'])}{self.colors['reset']}")
            for item in self.results['warnings'][:10]:
                print(f"  ⚠ {item}")
        
        if self.results['failed']:
            print(f"\n{self.colors['magenta']}{'-'*70}{self.colors['reset']}")
            print(f"{self.colors['red']}FAILED CHECKS (ACTION REQUIRED): {len(self.results['failed'])}{self.colors['reset']}")
            for item in self.results['failed']:
                print(f"  ✗ {item}")
        
        if self.remediations:
            print(f"\n{self.colors['magenta']}{'-'*70}{self.colors['reset']}")
            print(f"{self.colors['cyan']}REMEDIATIONS:{self.colors['reset']}")
            for i, remediation in enumerate(self.remediations[:10], 1):
                print(f"  {i}. {remediation}")
        
        print(f"{self.colors['magenta']}{'='*70}{self.colors['reset']}")
        
        return {
            'score': self.score,
            'rating': rating,
            'passed': self.results['passed'],
            'warnings': self.results['warnings'],
            'failed': self.results['failed'],
            'remediations': self.remediations
        }
    
    def save_report(self, output_file):
        """Save report to JSON file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'score': self.score,
            'rating': 'EXCELLENT' if self.score >= 90 else 'GOOD' if self.score >= 75 else 'FAIR' if self.score >= 60 else 'POOR',
            'passed': self.results['passed'],
            'warnings': self.results['warnings'],
            'failed': self.results['failed'],
            'remediations': self.remediations
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n{self.colors['green']}[+] Full report saved to {output_file}{self.colors['reset']}")
    
    def run_hardening(self, output_file=None):
        """Run all hardening checks"""
        print(f"\n{self.colors['magenta']}{'='*70}{self.colors['reset']}")
        print(f"{self.colors['cyan']}LINUX SYSTEM HARDENING TOOL{self.colors['reset']}")
        print(f"{self.colors['magenta']}{'='*70}{self.colors['reset']}")
        print("This tool will check your system against security best practices")
        print(f"{self.colors['magenta']}{'='*70}{self.colors['reset']}\n")
        
        checks = [
            self.check_os_updates,
            self.check_unnecessary_services,
            self.check_ssh_config,
            self.check_file_permissions,
            self.check_firewall,
            self.check_audit_logging,
            self.check_failed_logins,
            self.check_suid_binaries,
            self.check_password_policy,
            self.check_kernel_parameters,
            self.check_core_dumps,
            self.check_mount_options
        ]
        
        for check in checks:
            check()
            print()
        
        if self.apply_fixes:
            self.apply_remediations()
        
        report = self.generate_report()
        
        if output_file:
            self.save_report(output_file)
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Linux System Hardening Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo python3 linux_hardener.py                    # Run audit only
  sudo python3 linux_hardener.py --fix              # Run audit and apply fixes
  sudo python3 linux_hardener.py --output report.json
  sudo python3 linux_hardener.py --verbose
        '''
    )
    
    parser.add_argument('--fix', action='store_true',
                       help='Apply automatic fixes where possible')
    parser.add_argument('--output', '-o', default=None,
                       help='Output report file (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print(f"{colors['red']}[-] This tool requires root privileges for full checks{colors['reset']}")
        print("    Run: sudo python3 linux_hardener.py")
        sys.exit(1)
    
    hardener = LinuxHardener(apply_fixes=args.fix, verbose=args.verbose)
    hardener.run_hardening(output_file=args.output)


if __name__ == "__main__":
    main()
