#!/usr/bin/env bash
#===============================================================================
# cis_hardening.sh - Escaneo y hardening CIS Benchmark (Ubuntu 20.04 LTS)
#
# Basado en: CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0
#
# MODOS:
#   audit   -> SOLO genera informe (no aplica ninguna regla)
#   apply   -> aplica las reglas y genera informe POSTERIOR
#   full    -> informe inicial (pre) + aplica reglas + informe posterior (post)
#
# USO:
#   sudo ./cis_hardening.sh audit
#   sudo ./cis_hardening.sh apply
#   sudo ./cis_hardening.sh full
#
# MODO MULTI-EQUIPO (escanear toda la red desde el Linux node):
#   HOSTS="10.8.63.4 10.8.63.5" sudo -E ./cis_hardening.sh audit
#   HOSTS="10.8.63.4 10.8.63.1" sudo -E ./cis_hardening.sh full
#   (requiere acceso SSH con clave publica a cada host)
#
# Salidas: ./reports/cis_<modo>_<host>_<fecha>.txt
#===============================================================================
set -u
export LC_ALL=C

MODE="${1:-help}"
REPORT_DIR="./reports"
TS="$(date +%Y%m%d_%H%M%S)"
HOSTNAME_NOW="$(hostname -s 2>/dev/null || echo local)"
PASS=0; FAIL=0; REMED=0
BACKUP_EXT="cisbak.$TS"
RESULTS=()

#--- Helpers -------------------------------------------------------------------
add_result() { # id, titulo, estado(PASS|FAIL|REM), detalle
    local id="$1" title="$2" state="$3" detail="$4"
    RESULTS+=("[$state] $id | $title | $detail")
    case "$state" in
        PASS) PASS=$((PASS+1)) ;;
        FAIL) FAIL=$((FAIL+1)) ;;
        REM)  REMED=$((REMED+1)) ;;
    esac
}

backup_file() { # copia de seguridad antes de modificar
    local f="$1"
    [ -f "$f" ] && cp -p "$f" "$f.$BACKUP_EXT" 2>/dev/null
}

set_sshd_param() { # activa/desactiva y ajusta parametro en sshd_config
    local key="$1" val="$2"
    local f="/etc/ssh/sshd_config"
    if grep -Eqi "^\s*#?\s*${key}\s+" "$f"; then
        sed -ri "s|^\s*#?\s*(${key})\s+.*|\1 ${val}|I" "$f"
    else
        printf '%s %s\n' "$key" "$val" >> "$f"
    fi
}

#--- Chequeos (id alineados al CIS Ubuntu 20.04 Benchmark) ---------------------

chk_ssh_root_login() { # 5.2.8 - Ensure SSH root login is disabled
    local v="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')"
    [ "$v" = "no" ] && add_result 5.2.8 "SSH PermitRootLogin" PASS "permitrootlogin=no" \
        || add_result 5.2.8 "SSH PermitRootLogin" FAIL "permitrootlogin=${v:-desconocido}"
}

chk_ssh_maxauth() { # 5.2.4 - Ensure SSH MaxAuthTries is set to 4 or less
    local v="$(sshd -T 2>/dev/null | awk '/^maxauthtries/{print $2}')"
    [ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null \
        && add_result 5.2.4 "SSH MaxAuthTries<=4" PASS "maxauthtries=$v" \
        || add_result 5.2.4 "SSH MaxAuthTries<=4" FAIL "maxauthtries=${v:-desconocido}"
}

chk_ssh_x11() { # 5.2.11 - Ensure SSH X11 forwarding is disabled
    local v="$(sshd -T 2>/dev/null | awk '/^x11forwarding/{print $2}')"
    [ "$v" = "no" ] && add_result 5.2.11 "SSH X11Forwarding" PASS "no" \
        || add_result 5.2.11 "SSH X11Forwarding" FAIL "x11forwarding=${v:-desconocido}"
}

chk_ssh_idle() { # 5.2.12/5.2.13 - SSH idle timeout
    local i c
    i="$(sshd -T 2>/dev/null | awk '/^clientaliveinterval/{print $2}')"
    c="$(sshd -T 2>/dev/null | awk '/^clientalivecountmax/{print $2}')"
    [ -n "$i" ] && [ "$i" -ge 1 ] 2>/dev/null && [ "$i" -le 900 ] 2>/dev/null && [ "$c" -le 3 ] 2>/dev/null \
        && add_result 5.2.12 "SSH idle timeout" PASS "interval=$i count=$c" \
        || add_result 5.2.12 "SSH idle timeout" FAIL "interval=${i:-0} count=${c:-0}"
}

chk_cron() { # 5.1.2/5.1.3 - cron restringido
    if [ -f /etc/cron.deny ]; then add_result 5.1.2 "cron.deny ausente" FAIL "existe /etc/cron.deny";
    else add_result 5.1.2 "cron.deny ausente" PASS "no existe"; fi
    if [ -f /etc/cron.allow ] && [ "$(stat -c %a /etc/cron.allow)" = "640" ]; then
        add_result 5.1.3 "cron.allow 640" PASS "$(stat -c %a /etc/cron.allow)";
    else add_result 5.1.3 "cron.allow 640" FAIL "no existe o permisos incorrectos"; fi
}

chk_passwd_perms() { # 6.1.2 - /etc/passwd 644
    local p="$(stat -c %a /etc/passwd 2>/dev/null)"
    [ "$p" = "644" ] && add_result 6.1.2 "Permisos /etc/passwd" PASS "644" \
        || add_result 6.1.2 "Permisos /etc/passwd" FAIL "$p"
}

chk_shadow_perms() { # 6.1.3 - /etc/shadow 640 o 000
    local p="$(stat -c %a /etc/shadow 2>/dev/null)"
    [ "$p" = "640" ] || [ "$p" = "000" ] || [ "$p" = "600" ] \
        && add_result 6.1.3 "Permisos /etc/shadow" PASS "$p" \
        || add_result 6.1.3 "Permisos /etc/shadow" FAIL "$p"
}

chk_pwquality() { # 5.3.1/5.3.2 - password complexity
    local len="$(grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf 2>/dev/null | head -1 | tr -dc '0-9')"
    [ -n "$len" ] && [ "$len" -ge 14 ] 2>/dev/null \
        && add_result 5.3.2 "pwquality minlen>=14" PASS "minlen=$len" \
        || add_result 5.3.2 "pwquality minlen>=14" FAIL "minlen=${len:-no definido}"
}

chk_pass_max_days() { # 5.4.1.1 - PASS_MAX_DAYS <= 365
    local d="$(grep -E '^\s*PASS_MAX_DAYS\s' /etc/login.defs 2>/dev/null | awk '{print $2}' | head -1)"
    [ -n "$d" ] && [ "$d" -le 365 ] 2>/dev/null \
        && add_result 5.4.1.1 "PASS_MAX_DAYS<=365" PASS "$d" \
        || add_result 5.4.1.1 "PASS_MAX_DAYS<=365" FAIL "${d:-no definido}"
}

chk_lockout() { # 5.3.3 - lockout por intentos fallidos (pam_tally2 en 20.04)
    if grep -q "pam_tally2" /etc/pam.d/common-auth 2>/dev/null; then
        add_result 5.3.3 "Lockout intentos fallidos" PASS "pam_tally2 en common-auth"
    else
        add_result 5.3.3 "Lockout intentos fallidos" FAIL "pam_tally2 no configurado"
    fi
}

chk_umask() { # 5.4.4 - default umask 027
    local u="$(grep -E '^\s*UMASK\s' /etc/login.defs 2>/dev/null | awk '{print $2}' | head -1)"
    [ "$u" = "027" ] && add_result 5.4.4 "UMASK 027" PASS "027" \
        || add_result 5.4.4 "UMASK 027" FAIL "${u:-no definido}"
}

chk_auditd() { # 4.1.1.1/4.1.1.2 - auditd instalado y habilitado
    if dpkg -s auditd >/dev/null 2>&1 && systemctl is-enabled auditd >/dev/null 2>&1; then
        add_result 4.1.1.1 "auditd activo" PASS "instalado+habilitado"
    else
        add_result 4.1.1.1 "auditd activo" FAIL "no instalado o no habilitado"
    fi
}

chk_unused_services() { # 2.2.7/2.2.15 - avahi-daemon / cups
    for svc in avahi-daemon cups; do
        if systemctl is-enabled "$svc" >/dev/null 2>&1 || systemctl is-active "$svc" >/dev/null 2>&1; then
            add_result 2.2.x "Servicio innecesario: $svc" FAIL "activo/habilitado"
        else
            add_result 2.2.x "Servicio innecesario: $svc" PASS "deshabilitado"
        fi
    done
}

run_checks() {
    chk_ssh_root_login; chk_ssh_maxauth; chk_ssh_x11; chk_ssh_idle
    chk_cron; chk_passwd_perms; chk_shadow_perms
    chk_pwquality; chk_pass_max_days; chk_lockout; chk_umask
    chk_auditd; chk_unused_services
}

#--- Remediacion (APPLY) -------------------------------------------------------

rem_ssh() { # 5.2.8 / 5.2.4 / 5.2.11 / 5.2.12
    local f="/etc/ssh/sshd_config"
    backup_file "$f"
    set_sshd_param PermitRootLogin no
    set_sshd_param MaxAuthTries 4
    set_sshd_param X11Forwarding no
    set_sshd_param ClientAliveInterval 300
    set_sshd_param ClientAliveCountMax 2
    sshd -t 2>/dev/null && systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null
}

rem_cron() { # 5.1.2 / 5.1.3
    rm -f /etc/cron.deny
    touch /etc/cron.allow
    chown root:root /etc/cron.allow
    chmod 640 /etc/cron.allow
}

rem_perms() { # 6.1.2 / 6.1.3
    chmod 644 /etc/passwd 2>/dev/null; chown root:root /etc/passwd 2>/dev/null
    chmod 640 /etc/shadow 2>/dev/null; chown root:shadow /etc/shadow 2>/dev/null
}

rem_pwquality() { # 5.3.1 / 5.3.2
    local f=/etc/security/pwquality.conf
    backup_file "$f"
    sed -ri 's|^\s*#?\s*minlen\s*=.*|minlen = 14|I' "$f"
    grep -qE '^\s*minlen\s*=' "$f" || echo "minlen = 14" >> "$f"
    sed -ri 's|^\s*#?\s*retry\s*=.*|retry = 3|I' "$f"
    grep -qE '^\s*retry\s*=' "$f" || echo "retry = 3" >> "$f"
}

rem_login_defs() { # 5.4.1.1 / 5.4.4
    local f=/etc/login.defs
    backup_file "$f"
    sed -ri 's|^\s*PASS_MAX_DAYS\s+.*|PASS_MAX_DAYS   365|' "$f"
    grep -qE '^\s*PASS_MAX_DAYS\s' "$f" || echo "PASS_MAX_DAYS   365" >> "$f"
    sed -ri 's|^\s*UMASK\s+.*|UMASK           027|' "$f"
    grep -qE '^\s*UMASK\s' "$f" || echo "UMASK           027" >> "$f"
}

rem_lockout() { # 5.3.3 (Ubuntu 20.04 usa pam_tally2)
    local f=/etc/pam.d/common-auth
    backup_file "$f"
    if ! grep -q pam_tally2 "$f"; then
        sed -i '1i auth required pam_tally2.so onerr=fail deny=5 unlock_time=900 root_unlock_time=300' "$f"
    fi
}

rem_auditd() { # 4.1.1.1 / 4.1.1.2
    apt-get install -y auditd >/dev/null 2>&1
    systemctl enable --now auditd >/dev/null 2>&1
}

rem_services() { # 2.2.7 / 2.2.15
    for svc in avahi-daemon cups; do
        systemctl disable --now "$svc" >/dev/null 2>&1
    done
}

apply_rules() {
    echo "[*] Aplicando reglas CIS (backups con extension .$BACKUP_EXT)..."
    rem_ssh
    rem_cron
    rem_perms
    rem_pwquality
    rem_login_defs
    rem_lockout
    rem_auditd
    rem_services
}

#--- Reporte -------------------------------------------------------------------

write_report() { # $1 = etiqueta (pre/post)
    local tag="$1"
    local file="${REPORT_DIR}/cis_${tag}_${HOSTNAME_NOW}_${TS}.txt"
    mkdir -p "$REPORT_DIR"
    {
        echo "=============================================================="
        echo " Informe CIS Benchmark - Ubuntu 20.04 | equipo: $HOSTNAME_NOW"
        echo " Modo: $MODE | informe: $tag | fecha: $(date)"
        echo " Referencia: CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0"
        echo "=============================================================="
        echo
        for r in "${RESULTS[@]}"; do echo "  $r"; done
        echo
        echo "--------------------------------------------------------------"
        printf '  Resumen %s: PASS=%d  FAIL=%d  REMEDIADO=%d\n' "$tag" "$PASS" "$FAIL" "$REMED"
        echo "--------------------------------------------------------------"
    } > "$file"
    echo "[+] Informe generado: $file"
}

print_screen() {
    local tag="$1"
    echo; echo "===== RESULTADOS ($tag) ====="
    for r in "${RESULTS[@]}"; do echo "  $r"; done
    echo "  Resumen $tag: PASS=$PASS FAIL=$FAIL REMEDIADO=$REMED"
}

#--- Ejecucion remota ----------------------------------------------------------

remote_run() {
    for h in $HOSTS; do
        echo "[*] Ejecutando en host remoto: $h"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$h" \
            "bash -s $MODE" < "$0"
    done
    exit 0
}

#--- Main ----------------------------------------------------------------------

case "$MODE" in
    audit)
        [ -n "${HOSTS:-}" ] && remote_run
        run_checks
        write_report "pre"
        print_screen "pre"
        ;;
    apply)
        [ -n "${HOSTS:-}" ] && remote_run
        apply_rules
        RESULTS=(); PASS=0; FAIL=0; REMED=0
        run_checks
        write_report "post"
        print_screen "post"
        ;;
    full)
        [ -n "${HOSTS:-}" ] && remote_run
        run_checks
        write_report "pre"
        print_screen "pre"
        echo; echo "[*] Aplicando reglas..."
        apply_rules
        RESULTS=(); PASS=0; FAIL=0; REMED=0
        run_checks
        write_report "post"
        print_screen "post"
        ;;
    *)
        sed -n '2,30p' "$0"
        ;;
esac
