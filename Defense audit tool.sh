#!/bin/bash
# ============================================================
#  "First Line of Defense" Security Audit Tool
#  Author : Security Lab Project
#  Version: 1.0
#  Purpose: Audit a Linux system for common security issues
#           and generate a human-readable report.
# ============================================================

# ── Output file ──────────────────────────────────────────────
REPORT="security_report.txt"
DUMMY_MALWARE="/tmp/totally_not_malware.sh"

# ── Colour codes (terminal only, stripped in report) ─────────
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'   # no colour

# ── Helper: print to both terminal and report file ───────────
log()  { echo -e "$1" | tee -a "$REPORT"; }
rule() { log "$(printf '%.0s─' {1..60})"; }

# ── Helper: coloured status tags (terminal) + plain (report) ─
pass() { echo -e "  ${GRN}[PASS]${NC} $1"; echo "  [PASS] $1" >> "$REPORT"; }
warn() { echo -e "  ${YEL}[WARN]${NC} $1"; echo "  [WARN] $1" >> "$REPORT"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; echo "  [FAIL] $1" >> "$REPORT"; }
info() { echo -e "  ${BLU}[INFO]${NC} $1"; echo "  [INFO] $1" >> "$REPORT"; }

# ── Initialise / wipe previous report ────────────────────────
> "$REPORT"

# ============================================================
# BANNER
# ============================================================
log ""
log "╔══════════════════════════════════════════════════════════╗"
log "║        FIRST LINE OF DEFENSE – SECURITY AUDIT           ║"
log "║              $(date '+%Y-%m-%d  %H:%M:%S %Z')                   ║"
log "╚══════════════════════════════════════════════════════════╝"
log ""

# ============================================================
# PHASE 1 – SYSTEM INFORMATION & STANDARDS  (Topics 01 & 03)
# ============================================================
rule
log "PHASE 1 │ SYSTEM INFORMATION & PATCH STATUS"
rule

# 1-A  OS identification
log ""
log "[ 1-A ] Operating System"
OS_NAME=$(grep '^PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)
ARCH=$(uname -m)
info "OS      : ${OS_NAME:-Unknown}"
info "Kernel  : $KERNEL"
info "Arch    : $ARCH"
info "Hostname: $(hostname)"

# 1-B  Current user & privilege level
log ""
log "[ 1-B ] Current Session"
CURRENT_USER=$(whoami)
info "Running as : $CURRENT_USER"
if [[ "$CURRENT_USER" == "root" ]]; then
    warn "Script is running as ROOT – principle of least privilege may be violated."
else
    pass "Script is NOT running as root (good practice)."
fi

# 1-C  System update check (simulation-safe)
log ""
log "[ 1-C ] Patch / Update Status"
if command -v apt &>/dev/null; then
    info "Package manager: apt (Debian/Ubuntu)"
    # Run update index silently; capture upgradable count
    apt-get update -qq 2>/dev/null
    UPGRADABLE=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    if [[ "$UPGRADABLE" -eq 0 ]]; then
        pass "System appears up-to-date (0 upgradable packages)."
    else
        warn "$UPGRADABLE package(s) have available updates – apply with 'sudo apt upgrade'."
    fi
elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    info "Package manager: yum/dnf (RHEL/CentOS/Fedora)"
    PKG_MGR=$(command -v dnf || command -v yum)
    UPDATES=$("$PKG_MGR" check-update -q 2>/dev/null | grep -c '^[a-zA-Z]')
    if [[ "$UPDATES" -eq 0 ]]; then
        pass "System appears up-to-date."
    else
        warn "$UPDATES package update(s) available."
    fi
else
    warn "Could not determine package manager – manual patch verification required."
fi

log ""

# ============================================================
# PHASE 2 – THREAT DETECTION SIMULATION  (Topic 02)
# ============================================================
rule
log "PHASE 2 │ THREAT DETECTION SIMULATION"
rule

# 2-A  Suspicious files in /tmp
log ""
log "[ 2-A ] Suspicious Files in /tmp"
SUSPICIOUS_EXT=("*.exe" "*.bat" "*.vbs" "*.ps1")
SUSPICIOUS_COUNT=0

for EXT in "${SUSPICIOUS_EXT[@]}"; do
    while IFS= read -r -d '' FILE; do
        warn "Suspicious extension found: $FILE"
        ((SUSPICIOUS_COUNT++))
    done < <(find /tmp -maxdepth 3 -name "$EXT" -print0 2>/dev/null)
done

# Shell scripts with 777 permissions in /tmp
while IFS= read -r -d '' FILE; do
    warn "World-writable .sh script found: $FILE  (perms: $(stat -c '%a' "$FILE"))"
    ((SUSPICIOUS_COUNT++))
done < <(find /tmp -maxdepth 3 -name "*.sh" -perm 777 -print0 2>/dev/null)

if [[ "$SUSPICIOUS_COUNT" -eq 0 ]]; then
    pass "No suspicious files detected in /tmp."
else
    fail "$SUSPICIOUS_COUNT suspicious file(s) found in /tmp – investigate immediately."
fi

# 2-B  Dummy malware check
log ""
log "[ 2-B ] Dummy Malware File Check"
info "Looking for known lab indicator: $DUMMY_MALWARE"
if [[ -f "$DUMMY_MALWARE" ]]; then
    fail "MALWARE INDICATOR DETECTED: $DUMMY_MALWARE exists on disk!"
    info "  SHA256: $(sha256sum "$DUMMY_MALWARE" 2>/dev/null | awk '{print $1}')"
    info "  Size  : $(stat -c '%s bytes' "$DUMMY_MALWARE" 2>/dev/null)"
    info "  Owned : $(stat -c '%U:%G' "$DUMMY_MALWARE" 2>/dev/null)"
else
    pass "Dummy malware file not present – system clear of this indicator."
fi

# 2-C  World-writable files outside /tmp (quick spot-check)
log ""
log "[ 2-C ] World-Writable Files Spot-Check (/etc)"
WW_COUNT=$(find /etc -maxdepth 2 -perm -o+w -not -type l 2>/dev/null | wc -l)
if [[ "$WW_COUNT" -eq 0 ]]; then
    pass "No world-writable files found in /etc (shallow scan)."
else
    warn "$WW_COUNT world-writable file(s) found in /etc – review recommended."
    find /etc -maxdepth 2 -perm -o+w -not -type l 2>/dev/null | while read -r F; do
        info "  $F"
    done
fi

log ""

# ============================================================
# PHASE 3 – LINUX HARDENING  (Topic 04)
# ============================================================
rule
log "PHASE 3 │ LINUX HARDENING CHECKS"
rule

# 3-A  Firewall (ufw) status
log ""
log "[ 3-A ] Firewall Status (ufw)"
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    info "ufw reports: $UFW_STATUS"
    if echo "$UFW_STATUS" | grep -qi "active"; then
        pass "Firewall (ufw) is ACTIVE."
    else
        fail "Firewall (ufw) is INACTIVE – enable with 'sudo ufw enable'."
    fi
else
    warn "ufw not found. Check for alternative firewall (firewalld / iptables)."
    if command -v firewall-cmd &>/dev/null; then
        FW_STATE=$(firewall-cmd --state 2>/dev/null)
        info "firewalld state: $FW_STATE"
        [[ "$FW_STATE" == "running" ]] && pass "firewalld is running." || fail "firewalld is NOT running."
    elif iptables -L &>/dev/null 2>&1; then
        RULES=$(iptables -L 2>/dev/null | grep -cv '^#')
        info "iptables has $RULES rule lines (manual review recommended)."
    fi
fi

# 3-B  SSH hardening basics
log ""
log "[ 3-B ] SSH Configuration Snapshot"
SSHD_CFG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CFG" ]]; then
    ROOT_LOGIN=$(grep -i "^PermitRootLogin" "$SSHD_CFG" | awk '{print $2}')
    PASS_AUTH=$(grep -i "^PasswordAuthentication" "$SSHD_CFG" | awk '{print $2}')
    info "PermitRootLogin      : ${ROOT_LOGIN:-not set (default may allow)}"
    info "PasswordAuthentication: ${PASS_AUTH:-not set (default enabled)}"
    [[ "${ROOT_LOGIN,,}" == "no" ]]       && pass "Root login over SSH is disabled." \
                                          || warn "Root SSH login may be permitted – set 'PermitRootLogin no'."
    [[ "${PASS_AUTH,,}" == "no" ]]        && pass "Password authentication disabled (key-only)." \
                                          || warn "Password authentication is enabled – prefer key-based auth."
else
    info "sshd_config not found (SSH may not be installed)."
fi

# 3-C  Sudo / admin users
log ""
log "[ 3-C ] Users with Sudo Privileges"
info "Members of 'sudo' group:"
if getent group sudo &>/dev/null; then
    SUDO_USERS=$(getent group sudo | cut -d: -f4)
    if [[ -z "$SUDO_USERS" ]]; then
        info "  (no users listed in sudo group)"
    else
        for U in ${SUDO_USERS//,/ }; do
            warn "Sudo user: $U  – verify this account is authorised."
        done
    fi
else
    info "  'sudo' group not found (may use 'wheel' on this distro)."
fi

# Also check /etc/sudoers for ALL entries (non-comment)
info "Sudoers entries (non-comment, excluding defaults):"
grep -v '^#\|^$\|^Defaults' /etc/sudoers 2>/dev/null | while read -r LINE; do
    info "  $LINE"
done

# 3-D  Password policy basics
log ""
log "[ 3-D ] Password Policy Indicators"
if [[ -f /etc/login.defs ]]; then
    PASS_MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    PASS_MIN=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    PASS_WARN=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
    info "PASS_MAX_DAYS  : ${PASS_MAX:-unset}"
    info "PASS_MIN_DAYS  : ${PASS_MIN:-unset}"
    info "PASS_WARN_AGE  : ${PASS_WARN:-unset}"
    [[ -n "$PASS_MAX" && "$PASS_MAX" -le 90 ]] && pass "Password max age ≤ 90 days." \
                                                || warn "Password max age not configured or > 90 days."
else
    warn "/etc/login.defs not found – cannot check password policy."
fi

log ""

# ============================================================
# SUMMARY
# ============================================================
rule
log "AUDIT SUMMARY"
rule
log ""
PASS_COUNT=$(grep -c '\[PASS\]' "$REPORT")
WARN_COUNT=$(grep -c '\[WARN\]' "$REPORT")
FAIL_COUNT=$(grep -c '\[FAIL\]' "$REPORT")

log "  Total checks passed  : $PASS_COUNT"
log "  Warnings issued      : $WARN_COUNT"
log "  Critical failures    : $FAIL_COUNT"
log ""

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    log "  ⚠  RESULT: ACTION REQUIRED – $FAIL_COUNT critical issue(s) detected."
elif [[ "$WARN_COUNT" -gt 0 ]]; then
    log "  ⚡  RESULT: REVIEW RECOMMENDED – no critical failures, but $WARN_COUNT warning(s) found."
else
    log "  ✔  RESULT: ALL CHECKS PASSED – system appears well-hardened."
fi

log ""
log "  Full report saved to: $(realpath "$REPORT")"
log "  Audit completed at  : $(date '+%Y-%m-%d %H:%M:%S %Z')"
log ""
rule
log ""

# ── Exit with non-zero code if critical failures exist ───────
exit "$FAIL_COUNT"
