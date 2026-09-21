#!/usr/bin/env python3
"""
=============================================================================
TOPOLOGÍA SDN — PROYECTO DE GRADO
Universidad Católica de Colombia
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Descripción:
  10 hosts divididos en 2 VLANs sobre Mininet con Open vSwitch.
  VLAN OPS  (ID 10): hosts h1–h5  → subred 10.0.10.0/24
  VLAN ADM  (ID 20): hosts h6–h10 → subred 10.0.20.0/24

  Topología:
       [OPS h1-h5]──s1──┐
                        s3──── Controlador Ryu (127.0.0.1:6633)
       [ADM h6-h10]─s2──┘

  Controlador: Ryu con OpenFlow 1.3
  Uso:
      sudo python3 topology_project.py
  Requiere:
      Mininet, Open vSwitch, Ryu corriendo en otra terminal:
      ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633
=============================================================================
"""

import sys as _sys

def _check_mininet():
    try:
        import mininet  # noqa
    except ImportError:
        print("\n[ERROR] Mininet no está en el PYTHONPATH de este intérprete.")
        print("        Mininet debe correrse con el Python del sistema, no de un venv.")
        print("\n  Soluciones:")
        print("  1. Usar el Python del sistema directamente:")
        print("       sudo /usr/bin/python3 topology_project.py")
        print("\n  2. O instalar mininet para Python:")
        print("       pip install mininet")
        print("       (si la versión del paquete es compatible)\n")
        _sys.exit(1)

_check_mininet()

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import subprocess

# ─── PARÁMETROS DE RED ───────────────────────────────────────────────────────
CONTROLLER_IP   = '127.0.0.1'
CONTROLLER_PORT = 6633
OPENFLOW_VER    = 'OpenFlow13'

VLAN_OPS = 10       # VLAN Operaciones  — hosts h1–h5
VLAN_ADM = 20       # VLAN Administración — hosts h6–h10

SUBNET_OPS = '10.0.10'   # .1 … .5
SUBNET_ADM = '10.0.20'   # .1 … .5

LINK_BW     = 100   # Mbps
LINK_DELAY  = '1ms'
LINK_LOSS   = 0

# ─── HELPERS ─────────────────────────────────────────────────────────────────
def set_vlan_port(switch, port, vlan_id, mode='access'):
    """
    Configura un puerto OVS como access (un host) o trunk (uplink entre switches).
    mode='access' : tráfico sin tag en el host, el switch añade el tag VLAN.
    mode='trunk'  : permite pasar múltiples VLANs entre switches.
    """
    sw_name = switch.name
    if mode == 'access':
        # Asignar el puerto a la VLAN como access
        subprocess.call([
            'ovs-vsctl', 'set', 'port',
            f'{sw_name}-eth{port}',
            f'tag={vlan_id}'
        ])
        info(f'    [{sw_name}] eth{port} → VLAN {vlan_id} (access)\n')
    elif mode == 'trunk':
        # Trunk: permitir las dos VLANs
        subprocess.call([
            'ovs-vsctl', 'set', 'port',
            f'{sw_name}-eth{port}',
            f'trunks={VLAN_OPS},{VLAN_ADM}'
        ])
        info(f'    [{sw_name}] eth{port} → trunk (VLAN {VLAN_OPS},{VLAN_ADM})\n')


def assign_ip(host, ip, prefix=24, gw=None):
    """Asigna IP y gateway a un host."""
    host.cmd(f'ip addr flush dev {host.name}-eth0')
    host.cmd(f'ip addr add {ip}/{prefix} dev {host.name}-eth0')
    host.cmd(f'ip link set {host.name}-eth0 up')
    if gw:
        host.cmd(f'ip route add default via {gw}')


def configure_ovs_dpid(switch, dpid):
    """Fuerza el DPID del switch para identificación determinista en Ryu."""
    subprocess.call(['ovs-vsctl', 'set', 'bridge', switch.name,
                     f'other-config:datapath-id={dpid:016x}'])


def enable_stp(switch):
    """Habilita STP en el switch para evitar loops en la topología."""
    subprocess.call(['ovs-vsctl', 'set', 'bridge', switch.name,
                     'stp_enable=true'])


# ─── TOPOLOGÍA ───────────────────────────────────────────────────────────────
def build_topology():
    """
    Construye y levanta la red completa. Retorna el objeto Mininet.

    Diagrama lógico:
      h1 (OPS)──┐
      h2 (OPS)──┤
      h3 (OPS)──┤──[s1, DPID=0x01]──eth6──[s3, DPID=0x03]──eth1──[s1]
      h4 (OPS)──┤                           │
      h5 (OPS)──┘                    eth2──[s2, DPID=0x02]──eth1──[s2]
                                             │
      h6  (ADM)──┐                   Controlador Ryu
      h7  (ADM)──┤                   (RemoteController)
      h8  (ADM)──┤──[s2, DPID=0x02]──eth6──[s3]
      h9  (ADM)──┤
      h10 (ADM)──┘
    """
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
        waitConnected=True,
    )

    # ── Controlador remoto (Ryu) ─────────────────────────────────────────────
    info('\n*** Agregando controlador Ryu (RemoteController)\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )

    # ── Switches ─────────────────────────────────────────────────────────────
    info('*** Agregando switches OVS (OpenFlow 1.3)\n')
    sw_opts = dict(protocols=OPENFLOW_VER, failMode='secure')

    s1 = net.addSwitch('s1', dpid='0000000000000001', **sw_opts)  # Switch OPS
    s2 = net.addSwitch('s2', dpid='0000000000000002', **sw_opts)  # Switch ADM
    s3 = net.addSwitch('s3', dpid='0000000000000003', **sw_opts)  # Switch core

    # ── Hosts VLAN OPS (h1–h5) ───────────────────────────────────────────────
    info('*** Agregando hosts VLAN OPS (10.0.10.0/24)\n')
    ops_hosts = []
    for i in range(1, 6):
        h = net.addHost(
            f'h{i}',
            ip=f'{SUBNET_OPS}.{i}/24',
            defaultRoute=f'via {SUBNET_OPS}.254',
            cls=None,
        )
        ops_hosts.append(h)
        info(f'    h{i} → {SUBNET_OPS}.{i}/24  [VLAN {VLAN_OPS}]\n')

    # ── Hosts VLAN ADM (h6–h10) ──────────────────────────────────────────────
    info('*** Agregando hosts VLAN ADM (10.0.20.0/24)\n')
    adm_hosts = []
    for i in range(6, 11):
        h = net.addHost(
            f'h{i}',
            ip=f'{SUBNET_ADM}.{i-5}/24',
            defaultRoute=f'via {SUBNET_ADM}.254',
            cls=None,
        )
        adm_hosts.append(h)
        info(f'    h{i} → {SUBNET_ADM}.{i-5}/24  [VLAN {VLAN_ADM}]\n')

    # ── Enlaces host ↔ switch ─────────────────────────────────────────────────
    info('*** Creando enlaces host ↔ switch\n')
    link_params = dict(bw=LINK_BW, delay=LINK_DELAY, loss=LINK_LOSS)

    # OPS: h1-h5 → s1  (puertos 1–5 de s1)
    for h in ops_hosts:
        net.addLink(h, s1, **link_params)

    # ADM: h6-h10 → s2  (puertos 1–5 de s2)
    for h in adm_hosts:
        net.addLink(h, s2, **link_params)

    # ── Uplinks switch ↔ switch core ─────────────────────────────────────────
    info('*** Creando uplinks hacia switch core (s3)\n')
    net.addLink(s1, s3, **link_params)   # s1-eth6 ↔ s3-eth1
    net.addLink(s2, s3, **link_params)   # s2-eth6 ↔ s3-eth2

    return net, c0, s1, s2, s3, ops_hosts, adm_hosts


def configure_vlans(s1, s2, s3):
    """
    Configura los puertos OVS con tags VLAN después de que Mininet
    haya creado los interfaces.

    s1 ports:  eth1-eth5 = access VLAN 10 (OPS hosts)
               eth6      = trunk hacia s3
    s2 ports:  eth1-eth5 = access VLAN 20 (ADM hosts)
               eth6      = trunk hacia s3
    s3 ports:  eth1      = trunk desde s1
               eth2      = trunk desde s2
    """
    info('\n*** Configurando VLANs en Open vSwitch\n')

    info(f'  [s1] Puertos 1-5 → VLAN {VLAN_OPS} access (OPS)\n')
    for port in range(1, 6):
        set_vlan_port(s1, port, VLAN_OPS, mode='access')

    info(f'  [s1] Puerto 6 → trunk\n')
    set_vlan_port(s1, 6, None, mode='trunk')

    info(f'  [s2] Puertos 1-5 → VLAN {VLAN_ADM} access (ADM)\n')
    for port in range(1, 6):
        set_vlan_port(s2, port, VLAN_ADM, mode='access')

    info(f'  [s2] Puerto 6 → trunk\n')
    set_vlan_port(s2, 6, None, mode='trunk')

    info(f'  [s3] Puertos 1-2 → trunk\n')
    set_vlan_port(s3, 1, None, mode='trunk')
    set_vlan_port(s3, 2, None, mode='trunk')


def verify_connectivity(net, ops_hosts, adm_hosts):
    """
    Prueba de conectividad intra-VLAN y verifica aislamiento inter-VLAN.
    Se imprimen los resultados en la consola de Mininet.
    """
    info('\n*** Verificación de conectividad intra-VLAN OPS\n')
    # Ping de h1 a h2 (mismo segmento OPS)
    result = ops_hosts[0].cmd(f'ping -c2 -W1 {SUBNET_OPS}.2')
    if '2 received' in result or '1 received' in result:
        info('    [OK] h1 → h2 (OPS intra-VLAN): REACHABLE\n')
    else:
        info('    [WARN] h1 → h2: no responde aún (el controlador puede estar instalando flujos)\n')

    info('*** Verificación de aislamiento inter-VLAN (OPS → ADM)\n')
    result = ops_hosts[0].cmd(f'ping -c2 -W1 {SUBNET_ADM}.1')
    if '0 received' in result or 'unreachable' in result or '100%' in result:
        info('    [OK] h1 → h6 (OPS→ADM): BLOCKED (aislamiento correcto)\n')
    else:
        info('    [INFO] h1 → h6: respondió — el controlador Ryu puede estar permitiendo inter-VLAN\n')


def print_summary(ops_hosts, adm_hosts):
    """Imprime tabla resumen de la topología levantada."""
    info('\n' + '='*65 + '\n')
    info('  TOPOLOGÍA LEVANTADA — RESUMEN\n')
    info('='*65 + '\n')
    info(f'  {"Host":<8} {"IP":<18} {"VLAN":<10} {"Switch":<10} {"Propósito"}\n')
    info('-'*65 + '\n')
    for i, h in enumerate(ops_hosts, 1):
        info(f'  h{i:<7} {SUBNET_OPS}.{i:<12} VLAN {VLAN_OPS}    s1          Workstation OPS\n')
    for i, h in enumerate(adm_hosts, 1):
        info(f'  h{i+5:<7} {SUBNET_ADM}.{i:<12} VLAN {VLAN_ADM}    s2          Workstation ADM\n')
    info('-'*65 + '\n')
    info(f'  s1   → Switch OPS  (DPID: 0x0000000000000001)\n')
    info(f'  s2   → Switch ADM  (DPID: 0x0000000000000002)\n')
    info(f'  s3   → Switch Core (DPID: 0x0000000000000003)\n')
    info(f'  c0   → Controlador Ryu @ {CONTROLLER_IP}:{CONTROLLER_PORT}\n')
    info('='*65 + '\n')
    info('  Comandos útiles en la CLI de Mininet:\n')
    info('    pingall                   → prueba conectividad total\n')
    info('    h1 ping -c3 10.0.10.2    → ping intra-VLAN OPS\n')
    info('    h1 ping -c3 10.0.20.1    → ping inter-VLAN (debe fallar)\n')
    info('    h6 iperf -s &            → servidor iperf en ADM\n')
    info('    h1 iperf -c 10.0.20.1   → test ancho de banda\n')
    info('    dump                      → estado de todos los nodos\n')
    info('    links                     → estado de todos los enlaces\n')
    info('    sh ovs-vsctl show         → configuración OVS\n')
    info('    sh ovs-ofctl dump-flows s1 -O OpenFlow13  → flujos s1\n')
    info('='*65 + '\n\n')


# ─── MAIN ────────────────────────────────────────────────────────────────────
def run():
    setLogLevel('info')

    info('\n' + '='*65 + '\n')
    info('  INICIANDO TOPOLOGÍA SDN — PROYECTO DE GRADO\n')
    info('  Universidad Católica de Colombia — 2026\n')
    info('='*65 + '\n')

    # 1. Construir la topología
    net, c0, s1, s2, s3, ops_hosts, adm_hosts = build_topology()

    # 2. Levantar la red
    info('\n*** Iniciando red Mininet\n')
    net.start()
    info('*** Red iniciada\n')

    # 3. Esperar que OVS registre los interfaces antes de configurar VLANs
    info('*** Esperando estabilización de Open vSwitch (3 s)...\n')
    time.sleep(3)

    # 4. Configurar VLANs en OVS
    configure_vlans(s1, s2, s3)

    # 5. Esperar conexión de switches con el controlador Ryu
    info('\n*** Esperando conexión con el controlador Ryu (5 s)...\n')
    time.sleep(5)

    # 6. Resumen de topología
    print_summary(ops_hosts, adm_hosts)

    # 7. Verificación básica de conectividad
    verify_connectivity(net, ops_hosts, adm_hosts)

    # 8. Abrir CLI interactiva
    info('\n*** Abriendo CLI de Mininet — escribe "exit" para terminar\n\n')
    CLI(net)

    # 9. Limpiar al salir
    info('\n*** Deteniendo red y limpiando OVS\n')
    net.stop()
    subprocess.call(['mn', '--clean'])
    info('*** Limpieza completada\n')


if __name__ == '__main__':
    run()
