#!/bin/bash

# ================= CONFIGURACIÓN DE TUS EQUIPOS =================
ROUTER_IP="10.8.63.1"
ROUTER_USER="Ezequiel"
ROUTER_PASS="Cisco123"

SWITCH_IP="10.8.63.5"
SWITCH_USER="Jimenez"
SWITCH_PASS="Cisco123"

FORTI_IP="172.8.63.2
FORTI_USER="admin"
FORTI_PASS="admin"

# Contraseña de 'enable' en equipos Cisco (si no hay, se deja igual)
ENABLE_PASS="Jimenez"

REPORTE="informe_cis_$(date +%Y%m%d_%H%M%S).txt"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

# ================= FUNCIONES DE ESCANEO (AUDITORÍA) =================
escanear_cisco() {
    NOMBRE=$1; IP=$2; USER=$3; PASS=$4
    echo ">>> Escaneando $NOMBRE ($IP)..." | tee -a "$REPORTE"

    # Los Cisco entran en modo usuario (>). Sin 'enable' = sin show run-config.
    CONFIG=$(sshpass -p "$PASS" ssh -t $SSH_OPTS "$USER@$IP" <<EOF
enable
$ENABLE_PASS
terminal length 0
show running-config
exit
exit
EOF
)

    if echo "$CONFIG" | grep -qiE "permission denied|invalid input|password required"; then
        echo "  [ERROR] No se pudo entrar a modo privilegiado en $NOMBRE ($IP)" | tee -a "$REPORTE"
        echo "          -> revisa ENABLE_PASS" | tee -a "$REPORTE"
        return
    fi

    # Regla CIS 1: service password-encryption
    echo "$CONFIG" | grep -q "service password-encryption" && \
        echo "  [CUMPLE] CIS 1.1: Encriptación de contraseñas activa" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS 1.1: Falta 'service password-encryption'" | tee -a "$REPORTE"

    # Regla CIS 2: no ip http server (deshabilitar HTTP inseguro)
    echo "$CONFIG" | grep -q "^no ip http server" && \
        echo "  [CUMPLE] CIS 2.1: Servidor HTTP inseguro deshabilitado" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS 2.1: Servidor HTTP activo" | tee -a "$REPORTE"

    # Regla CIS 3: banner de advertencia legal
    echo "$CONFIG" | grep -q "^banner " && \
        echo "  [CUMPLE] CIS 3.1: Banner de advertencia configurado" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS 3.1: Falta banner de advertencia legal" | tee -a "$REPORTE"

    # Regla CIS 4: exec-timeout en líneas VTY
    echo "$CONFIG" | grep -q "exec-timeout" && \
        echo "  [CUMPLE] CIS 4.1: Timeout de sesión inactiva configurado" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS 4.1: Falta 'exec-timeout' en líneas VTY" | tee -a "$REPORTE"
}

escanear_fortigate() {
    echo ">>> Escaneando FortiGate ($FORTI_IP)..." | tee -a "$REPORTE"

    CONFIG=$(sshpass -p "$FORTI_PASS" ssh $SSH_OPTS "$FORTI_USER@$FORTI_IP" "show system global" 2>/dev/null)

    if [ -z "$CONFIG" ]; then
        echo "  [ERROR] No se pudo conectar por SSH a FortiGate ($FORTI_IP)" | tee -a "$REPORTE"
        return
    fi

    # Regla CIS FortiGate 1: admin-timeout (en FGT 7.x lleva guion)
    echo "$CONFIG" | grep -q "set admin-timeout" && \
        echo "  [CUMPLE] CIS FGT-1: Tiempo de expiración de sesión configurado" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS FGT-1: admin-timeout por defecto (inseguro)" | tee -a "$REPORTE"

    # Regla CIS FortiGate 2: pre-login-banner
    echo "$CONFIG" | grep -q "set pre-login-banner enable" && \
        echo "  [CUMPLE] CIS FGT-2: Banner previo al login habilitado" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS FGT-2: Banner previo al login deshabilitado" | tee -a "$REPORTE"

    # Regla CIS FortiGate 3: strong-crypto
    echo "$CONFIG" | grep -q "set strong-crypto enable" && \
        echo "  [CUMPLE] CIS FGT-3: Cifrado fuerte (TLS/SSH) habilitado" | tee -a "$REPORTE" || \
        echo "  [FALLA]  CIS FGT-3: Cifrado fuerte no forzado" | tee -a "$REPORTE"
}

# ================= FUNCIONES DE HARDENING (APLICAR REGLAS) =================
aplicar_cisco() {
    NOMBRE=$1; IP=$2; USER=$3; PASS=$4
    echo ">>> Aplicando reglas CIS en $NOMBRE ($IP)..."

    sshpass -p "$PASS" ssh -t $SSH_OPTS "$USER@$IP" <<EOF
enable
$ENABLE_PASS
configure terminal
service password-encryption
no ip http server
banner login ^C ACCESO RESTRINGIDO - SOLO PERSONAL AUTORIZADO ^C
line vty 0 4
exec-timeout 5 0
transport input ssh
end
write memory
exit
exit
EOF
    echo "  Reglas Cisco aplicadas en $NOMBRE"
}

aplicar_fortigate() {
    echo ">>> Aplicando reglas CIS en FortiGate ($FORTI_IP)..."

    sshpass -p "$FORTI_PASS" ssh $SSH_OPTS "$FORTI_USER@$FORTI_IP" <<EOF
config system global
set admin-timeout 5
set pre-login-banner enable
set strong-crypto enable
end
EOF
    echo "  Reglas FortiGate aplicadas"
}

# ================= MENÚ PRINCIPAL =================
clear
echo "===================================================="
echo "   AUDITORÍA Y HARDENING CIS - TOPOLOGÍA PNETLAB    "
echo "===================================================="
echo "1) Solo escanear y crear informe (Sin aplicar cambios)"
echo "2) Aplicar reglas CIS y generar informe póstumo"
echo "===================================================="
read -p "Seleccione una opción [1-2]: " OPCION

echo "REPORTE DE CUMPLIMIENTO CIS - $(date)" > "$REPORTE"
echo "====================================================" >> "$REPORTE"

case $OPCION in
    1)
        echo -e "\n[+] Iniciando escaneo de solo lectura..."
        escanear_cisco "Router Cisco C7200" "$ROUTER_IP" "$ROUTER_USER" "$ROUTER_PASS"
        escanear_cisco "Switch Cisco vIOS" "$SWITCH_IP" "$SWITCH_USER" "$SWITCH_PASS"
        escanear_fortigate
        ;;
    2)
        echo -e "\n[+] Aplicando configuraciones de seguridad (Hardening)..."
        aplicar_cisco "Router Cisco C7200" "$ROUTER_IP" "$ROUTER_USER" "$ROUTER_PASS"
        aplicar_cisco "Switch Cisco vIOS" "$SWITCH_IP" "$SWITCH_USER" "$SWITCH_PASS"
        aplicar_fortigate
        echo -e "\n[+] Esperando 3 segundos para verificación póstuma..."
        sleep 3
        echo "ESTADO PÓSTUMO TRAS APLICAR HARDENING:" >> "$REPORTE"
        escanear_cisco "Router Cisco C7200" "$ROUTER_IP" "$ROUTER_USER" "$ROUTER_PASS"
        escanear_cisco "Switch Cisco vIOS" "$SWITCH_IP" "$SWITCH_USER" "$SWITCH_PASS"
        escanear_fortigate
        ;;
    *)
        echo "Opción inválida."
        exit 1
        ;;
esac

echo -e "\n===================================================="
echo "Proceso terminado. Informe guardado en: $REPORTE"
