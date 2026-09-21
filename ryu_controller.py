#!/usr/bin/env python3
"""
=============================================================================
CONTROLADOR RYU — PROYECTO DE GRADO
Universidad Católica de Colombia
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Descripción:
  Aplicación Ryu con OpenFlow 1.3 que implementa 3 capas de operación:

  CAPA 1 — NORMAL:
    • MAC learning con aislamiento VLAN (OPS=10 / ADM=20)
    • Monitoreo silencioso de las 5 métricas OpenFlow
    • Período de gracia de 30s al arrancar

  CAPA 2 — SOSPECHOSO (1 ó 2 métricas superadas):
    • Rate-limiting en puertos críticos del host sospechoso
    • Tráfico forzado a pasar por el controlador (no se corta)
    • Log detallado del comportamiento

  CAPA 3 — CRÍTICO (≥ CRITICAL_THRESHOLD métricas simultáneas):
    • OFPFlowMod DROP prioridad 100 → host aislado de la red
    • Construcción y envío de payload JSON al agente LLM
    • El agente LLM responde con pasos a ejecutar + alertas

  Métricas implementadas:
    M1 — Tasa de nuevos flujos por host     (OFPFlowStatsRequest, polling)
    M2 — Fan-out de destinos únicos         (OFPFlowStatsRequest, polling)
    M3 — Duración corta + volumen alto SMB  (OFPFlowStatsReply)
    M4 — Tasa de Packet-In por host         (EventOFPPacketIn, tiempo real)
    M5 — Flujos east-west en puertos crit.  (monitor + umbral)

Uso:
    ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633

Dependencias:
    pip install ryu
    (urllib de stdlib — sin requests, compatible con Python 3.8)
=============================================================================
"""

import json
import re
import time
import threading
import urllib.request
import urllib.error
import logging
from collections import defaultdict
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, vlan
from ryu.lib import hub

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN — todos los parámetros ajustables están aquí
# ═══════════════════════════════════════════════════════════════════════════════

LOG_LEVEL        = logging.INFO
POLLING_INTERVAL = 5        # segundos entre ciclos de polling OFPFlowStats

# ── VLANs ─────────────────────────────────────────────────────────────────────
VLAN_OPS   = 10
VLAN_ADM   = 20
SUBNET_OPS = '10.0.10.'
SUBNET_ADM = '10.0.20.'

# ── Puertos críticos (movimiento lateral) ─────────────────────────────────────
CRITICAL_PORTS = {445, 135, 3389, 5985, 139}

# ── Umbrales de las 5 métricas ────────────────────────────────────────────────
THRESHOLD_M1_FLOWS_PER_30S = 20     # M1: nuevos flujos en 30s hacia puertos críticos
THRESHOLD_M2_UNIQUE_DSTS   = 15     # M2: destinos únicos en 30s
THRESHOLD_M3_DURATION_SEC  = 5      # M3: duración máxima del flujo SMB (segundos)
THRESHOLD_M3_BYTES         = 512000 # M3: volumen mínimo del flujo SMB (~500 KB)
THRESHOLD_M4_PACKET_IN_MIN = 200    # M4: Packet-In por minuto desde un host
THRESHOLD_M5_COUNT         = 5      # M5: flujos W2W distintos en puertos críticos

# ── Ventanas temporales ───────────────────────────────────────────────────────
WINDOW_M1_M2_SEC = 30   # ventana de análisis para M1 y M2
WINDOW_M4_SEC    = 60   # ventana deslizante para M4

# ── Lógica de escalamiento ────────────────────────────────────────────────────
# CAPA 2 (SOSPECHOSO): con 1 métrica superada → rate-limit
# CAPA 3 (CRÍTICO):    con ≥ CRITICAL_THRESHOLD métricas → DROP + LLM
CRITICAL_THRESHOLD = 3

# ── Período de gracia al arrancar ─────────────────────────────────────────────
# Evita falsos positivos por el tráfico de verificación inicial de Mininet.
# Aumentar si la red tarda más en estabilizarse.
STARTUP_GRACE_SEC = 30

# ── Destino del payload JSON (agente LLM) ─────────────────────────────────────
# Cambiar AGENT_URL cuando el agente esté disponible.
# AGENT_ENABLED = False → solo imprime el JSON en el log (modo prueba).
AGENT_URL     = 'http://localhost:8080/alert'
AGENT_TIMEOUT = 5
AGENT_ENABLED = False   # ← True cuando el agente LLM esté corriendo

# ── Rate-limit: parámetros de la Capa 2 ──────────────────────────────────────
# idle_timeout corto para que las reglas expiren solas si el host se normaliza
RATE_LIMIT_IDLE_TIMEOUT = 60   # segundos antes de que expire la regla de rate-limit
RATE_LIMIT_HARD_TIMEOUT = 120  # timeout máximo absoluto

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
logger = logging.getLogger('RyuSDN')


# ═══════════════════════════════════════════════════════════════════════════════
class SDNRansomwareDetector(app_manager.RyuApp):
    """
    Controlador SDN con detección de movimiento lateral en 3 capas.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Tabla de MACs: {dpid: {(mac, vlan_id): puerto}}
        self.mac_to_port = defaultdict(dict)

        # Datapaths registrados: {dpid: datapath}
        self.datapaths = {}

        # IPs de workstations conocidas (se rellena con cada Packet-In)
        self.workstation_ips = set()

        # Bitácora de tráfico por host para M1/M2/M4/M5
        self.host_flow_log = defaultdict(lambda: {
            'flows':          [],   # (ip_dst, timestamp, tp_dst)
            'packet_in_times': [],  # timestamps de cada Packet-In (M4)
            'east_west':      set() # pares (ip_dst, tp_dst) W2W vistos (M5)
        })

        # Estado de alerta por host
        self.host_alert_state = defaultdict(lambda: {
            'level':             'NORMAL',
            'metrics_triggered': set(),
            'last_alert':        0,
        })

        # Snapshot de valores numéricos al momento del disparo (para el JSON)
        self.metric_snapshot = defaultdict(dict)

        # Hosts con DROP instalado (para no reinstalar la regla)
        self.blocked_hosts = set()

        # Tiempo de arranque para el período de gracia
        self._start_time = time.time()

        # Iniciar hilo de polling
        self._polling_thread = hub.spawn(self._polling_loop)

        logger.info('=' * 60)
        logger.info('  Controlador SDN — 3 capas de detección activas')
        logger.info(f'  Período de gracia: {STARTUP_GRACE_SEC}s')
        logger.info(f'  Umbral CRÍTICO:    {CRITICAL_THRESHOLD} métricas simultáneas')
        logger.info(f'  Agente LLM:        {"HABILITADO" if AGENT_ENABLED else "DESHABILITADO (modo log)"}')
        logger.info('=' * 60)

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA BASE — CONEXIÓN DE SWITCHES
    # ═══════════════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Al conectarse un switch:
        1. Instala regla table-miss (todo sin match → CONTROLLER)
        2. Instala reglas de monitoreo M5 (W2W → CONTROLLER + NORMAL)
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        self.datapaths[dpid] = datapath
        logger.info(f'[SWITCH] Conectado: DPID={dpid:#018x}')

        # ── Regla table-miss (prioridad 0) ───────────────────────────────────
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        # ── Reglas de monitoreo M5 (prioridad 10) ────────────────────────────
        self._install_m5_monitor_rules(datapath)

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 1 — PROCESAMIENTO NORMAL (Packet-In)
    # ═══════════════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Procesa cada paquete que sube al controlador.
        Realiza MAC learning, aislamiento VLAN,
        y registra métricas M4 y M5 en tiempo real.
        """
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        # Parsear capas del paquete
        pkt      = packet.Packet(msg.data)
        eth_pkt  = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        # Ignorar LLDP y STP
        if eth_pkt.ethertype in (0x88cc, 0x8942):
            return

        dst_mac  = eth_pkt.dst
        src_mac  = eth_pkt.src
        vlan_pkt = pkt.get_protocol(vlan.vlan)
        vlan_id  = vlan_pkt.vid if vlan_pkt else None
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        src_ip = ip_pkt.src if ip_pkt else None
        dst_ip = ip_pkt.dst if ip_pkt else None
        tp_dst = (tcp_pkt.dst_port if tcp_pkt else
                  udp_pkt.dst_port if udp_pkt else None)

        # ── MAC learning ──────────────────────────────────────────────────────
        self.mac_to_port[dpid][(src_mac, vlan_id)] = in_port

        # ── Registrar IP de workstation ───────────────────────────────────────
        if src_ip and (src_ip.startswith(SUBNET_OPS) or
                       src_ip.startswith(SUBNET_ADM)):
            self.workstation_ips.add(src_ip)

        # ── M4: registrar Packet-In por host (tiempo real) ───────────────────
        if src_ip and src_ip not in self.blocked_hosts:
            self.host_flow_log[src_ip]['packet_in_times'].append(time.time())

        # ── M5: monitorear flujos east-west (tiempo real) ─────────────────────
        if (src_ip and dst_ip and tp_dst
                and src_ip in self.workstation_ips
                and dst_ip in self.workstation_ips
                and tp_dst in CRITICAL_PORTS
                and src_ip not in self.blocked_hosts):

            ew_log = self.host_flow_log[src_ip]['east_west']
            ew_log.add((dst_ip, tp_dst))
            ew_count = len(ew_log)

            logger.debug(f'[M5] {src_ip}→{dst_ip}:{tp_dst} '
                         f'W2W acumulados: {ew_count}/{THRESHOLD_M5_COUNT}')

            if ew_count >= THRESHOLD_M5_COUNT:
                self._trigger_metric(
                    src_ip, 'M5', datapath, in_port,
                    msg=f'M5: {ew_count} flujos W2W en puertos críticos '
                        f'≥ umbral {THRESHOLD_M5_COUNT}'
                )

        # ── Aislamiento inter-VLAN ────────────────────────────────────────────
        if src_ip and dst_ip:
            src_ops = src_ip.startswith(SUBNET_OPS)
            dst_ops = dst_ip.startswith(SUBNET_OPS)
            if src_ops != dst_ops:
                logger.debug(f'[VLAN] Bloqueado inter-VLAN: {src_ip}→{dst_ip}')
                return

        # ── Registrar flujo para M1/M2 ────────────────────────────────────────
        if src_ip and dst_ip and tp_dst:
            self.host_flow_log[src_ip]['flows'].append(
                (dst_ip, time.time(), tp_dst)
            )

        # ── Forwarding L2 ─────────────────────────────────────────────────────
        lookup_key = (dst_mac, vlan_id)
        if lookup_key in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][lookup_key]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Instalar flujo de reenvío si conocemos el puerto destino
        if (out_port != ofproto.OFPP_FLOOD
                and src_ip
                and src_ip not in self.blocked_hosts):
            match = (
                parser.OFPMatch(
                    in_port=in_port, eth_dst=dst_mac, eth_src=src_mac,
                    vlan_vid=(0x1000 | vlan_id)
                ) if vlan_id else
                parser.OFPMatch(
                    in_port=in_port, eth_dst=dst_mac, eth_src=src_mac
                )
            )
            self._add_flow(datapath, priority=1, match=match,
                           actions=actions,
                           idle_timeout=30, hard_timeout=60)

        # Enviar paquete actual
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        datapath.send_msg(out)

    # ═══════════════════════════════════════════════════════════════════════════
    # POLLING — M1, M2, M3, M4 cada POLLING_INTERVAL segundos
    # ═══════════════════════════════════════════════════════════════════════════
    def _polling_loop(self):
        """Hilo de polling: solicita estadísticas de flujos a todos los switches."""
        hub.sleep(5)
        logger.info(f'[POLLING] Iniciado cada {POLLING_INTERVAL}s')
        while True:
            for dpid, datapath in list(self.datapaths.items()):
                self._request_flow_stats(datapath)
                self._evaluate_m4(datapath)
            hub.sleep(POLLING_INTERVAL)

    def _request_flow_stats(self, datapath):
        """Envía OFPFlowStatsRequest al switch."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(
            datapath, flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0, cookie_mask=0,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Evalúa M1, M2 y M3 con los datos de la tabla de flujos del switch.
        """
        body     = ev.msg.body
        datapath = ev.msg.datapath
        now      = time.time()

        # Agrupar flujos por IP origen
        flows_by_src = defaultdict(list)
        for stat in body:
            m      = stat.match
            src_ip = m.get('ipv4_src')
            dst_ip = m.get('ipv4_dst')
            tp_dst = m.get('tcp_dst') or m.get('udp_dst')
            if src_ip and dst_ip:
                flows_by_src[src_ip].append({
                    'dst_ip':   dst_ip,
                    'tp_dst':   tp_dst,
                    'duration': stat.duration_sec,
                    'bytes':    stat.byte_count,
                })

        for src_ip, flows in flows_by_src.items():
            if src_ip in self.blocked_hosts:
                continue

            # M1: flujos recientes en ventana hacia puertos críticos
            recent = [f for f in flows
                      if f['duration'] < WINDOW_M1_M2_SEC
                      and f['tp_dst'] in CRITICAL_PORTS]
            m1_val = len(recent)

            # M2: destinos únicos de esos flujos recientes
            m2_val = len({f['dst_ip'] for f in recent})

            # M3: flujo SMB breve y voluminoso
            m3_hit = any(
                f['tp_dst'] == 445
                and f['duration'] < THRESHOLD_M3_DURATION_SEC
                and f['bytes']    > THRESHOLD_M3_BYTES
                for f in flows
            )

            if m1_val > 0:
                logger.debug(f'[STATS] {src_ip} M1={m1_val} '
                             f'M2={m2_val} M3={m3_hit}')

            if m1_val > THRESHOLD_M1_FLOWS_PER_30S:
                self._trigger_metric(
                    src_ip, 'M1', datapath, None,
                    msg=f'M1: {m1_val} flujos nuevos en {WINDOW_M1_M2_SEC}s '
                        f'> umbral {THRESHOLD_M1_FLOWS_PER_30S}'
                )
            if m2_val > THRESHOLD_M2_UNIQUE_DSTS:
                self._trigger_metric(
                    src_ip, 'M2', datapath, None,
                    msg=f'M2: {m2_val} destinos únicos en {WINDOW_M1_M2_SEC}s '
                        f'> umbral {THRESHOLD_M2_UNIQUE_DSTS}'
                )
            if m3_hit:
                self._trigger_metric(
                    src_ip, 'M3', datapath, None,
                    msg=f'M3: flujo SMB <{THRESHOLD_M3_DURATION_SEC}s '
                        f'y >{THRESHOLD_M3_BYTES}B detectado'
                )

    def _evaluate_m4(self, datapath):
        """Evalúa M4: tasa de Packet-In en ventana deslizante."""
        now    = time.time()
        cutoff = now - WINDOW_M4_SEC

        for src_ip, log in list(self.host_flow_log.items()):
            if src_ip in self.blocked_hosts:
                continue
            # Limpiar timestamps fuera de la ventana
            log['packet_in_times'] = [
                t for t in log['packet_in_times'] if t > cutoff
            ]
            rate = len(log['packet_in_times']) * (60 / WINDOW_M4_SEC)

            if rate > THRESHOLD_M4_PACKET_IN_MIN:
                self._trigger_metric(
                    src_ip, 'M4', datapath, None,
                    msg=f'M4: {rate:.0f} Packet-In/min '
                        f'> umbral {THRESHOLD_M4_PACKET_IN_MIN}'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # MOTOR DE ALERTAS — decide la capa de respuesta
    # ═══════════════════════════════════════════════════════════════════════════
    def _trigger_metric(self, src_ip, metric_id, datapath, in_port, msg=''):
        """
        Acumula métricas por host y determina la capa de respuesta:
          CAPA 1 (NORMAL):      0 métricas  → sin acción
          CAPA 2 (SOSPECHOSO):  1-2 métricas → rate-limit
          CAPA 3 (CRÍTICO):     ≥ CRITICAL_THRESHOLD → DROP + JSON al LLM
        """
        # ── Período de gracia ─────────────────────────────────────────────────
        elapsed = time.time() - self._start_time
        if elapsed < STARTUP_GRACE_SEC:
            remaining = int(STARTUP_GRACE_SEC - elapsed)
            logger.debug(f'[GRACIA] {src_ip}/{metric_id} ignorada '
                         f'({remaining}s restantes)')
            return

        state = self.host_alert_state[src_ip]
        state['metrics_triggered'].add(metric_id)
        count = len(state['metrics_triggered'])

        # Guardar valor numérico para el JSON
        nums = re.findall(r'\d+\.?\d*', msg)
        if nums:
            self.metric_snapshot[src_ip][metric_id] = float(nums[0])

        logger.warning(f'[{metric_id}] {src_ip} — {msg} '
                       f'| activas: {sorted(state["metrics_triggered"])}')

        prev_level = state['level']

        # ── CAPA 2: SOSPECHOSO ────────────────────────────────────────────────
        if count < CRITICAL_THRESHOLD:
            new_level = 'SOSPECHOSO'
            if prev_level == 'NORMAL':
                state['level'] = new_level
                logger.warning(f'[CAPA 2] {src_ip} → SOSPECHOSO '
                               f'({count} métrica(s)) — aplicando rate-limit')
                if datapath:
                    self._apply_rate_limit(datapath, src_ip)

        # ── CAPA 3: CRÍTICO ───────────────────────────────────────────────────
        else:
            new_level = 'CRITICO'
            state['level'] = new_level
            if src_ip not in self.blocked_hosts:
                logger.critical(
                    f'[CAPA 3] {src_ip} → CRÍTICO '
                    f'({count} métricas: {sorted(state["metrics_triggered"])}) '
                    f'— DROP + escalando al agente LLM'
                )
                # Buscar el datapath correcto si no viene en el argumento
                dp = datapath or next(iter(self.datapaths.values()), None)
                if dp:
                    self._block_host(dp, src_ip)
                self._send_json_alert(src_ip, state, dp)

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 2 — RATE-LIMIT
    # ═══════════════════════════════════════════════════════════════════════════
    def _apply_rate_limit(self, datapath, src_ip):
        """
        Instala reglas que fuerzan el tráfico del host sospechoso
        en puertos críticos a pasar por el controlador.
        El tráfico NO se corta — se ralentiza (cada paquete pasa por Ryu).
        Las reglas expiran en RATE_LIMIT_IDLE_TIMEOUT segundos de inactividad.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instaladas = 0
        for port in CRITICAL_PORTS:
            try:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ip_proto=6,
                    tcp_dst=port,
                )
                actions = [parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
                )]
                self._add_flow(
                    datapath, priority=20, match=match, actions=actions,
                    idle_timeout=RATE_LIMIT_IDLE_TIMEOUT,
                    hard_timeout=RATE_LIMIT_HARD_TIMEOUT,
                )
                instaladas += 1
            except Exception as e:
                logger.debug(f'[RATE-LIMIT] Error en puerto {port}: {e}')

        logger.warning(f'[CAPA 2] Rate-limit aplicado a {src_ip} '
                       f'en {instaladas} puertos críticos '
                       f'(expira en {RATE_LIMIT_IDLE_TIMEOUT}s de inactividad)')

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 3 — DROP + JSON AL AGENTE LLM
    # ═══════════════════════════════════════════════════════════════════════════
    def _block_host(self, datapath, src_ip):
        """
        Instala regla OFPFlowMod DROP permanente con prioridad 100.
        Gana sobre todas las demás reglas — el host queda sin red.
        """
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self._add_flow(
            datapath, priority=100, match=match,
            actions=[],             # lista vacía = DROP en OpenFlow 1.3
            idle_timeout=0,         # permanente
            hard_timeout=0,
        )
        self.blocked_hosts.add(src_ip)
        logger.critical(f'[CAPA 3] {src_ip} — OFPFlowMod DROP instalado '
                        f'(prioridad 100, permanente)')

    def _send_json_alert(self, src_ip, state, datapath):
        """
        Construye el payload JSON con el contexto completo del ataque
        y lo envía al agente LLM en un hilo separado.
        """
        snap     = self.metric_snapshot.get(src_ip, {})
        log      = self.host_flow_log.get(src_ip, {})
        now      = time.time()
        cutoff   = now - WINDOW_M1_M2_SEC
        triggered = sorted(state['metrics_triggered'])

        # Calcular valores actuales como respaldo al snapshot
        recent_flows = [f for f in log.get('flows', [])
                        if f[1] > cutoff and f[2] in CRITICAL_PORTS]
        m1_backup = len(recent_flows)
        m2_backup = len({f[0] for f in recent_flows})
        pkt_times = [t for t in log.get('packet_in_times', [])
                     if t > now - WINDOW_M4_SEC]
        m4_backup = round(len(pkt_times) * (60 / WINDOW_M4_SEC), 1)

        payload = {
            'timestamp':          datetime.utcnow().isoformat() + 'Z',
            'alerta_nivel':       'CRITICO',
            'host_origen':        src_ip,
            'dpid_switch':        f'{datapath.id:#018x}' if datapath else 'unknown',
            'contexto_topologico': self._get_topology_context(src_ip),
            'metricas': {
                'M1_nuevos_flujos_por_30s':   snap.get('M1', m1_backup),
                'M2_destinos_unicos_por_30s': snap.get('M2', m2_backup),
                'M3_smb_anomalo':             'M3' in triggered,
                'M4_packet_in_por_min':       snap.get('M4', m4_backup),
                'M5_flujos_east_west':        'M5' in triggered,
                'M5_count':                   snap.get('M5', len(log.get('east_west', set()))),
            },
            'umbrales_superados': triggered,
            'ioc_activados':      self._map_ioc(triggered),
            'accion_ryu_previa':  f'OFPFlowMod DROP prioridad 100 — {src_ip} aislado',
            'solicitud_al_agente': (
                'Analiza el ataque descrito. Devuelve un JSON con: '
                '"veredicto" (confirmado/falso_positivo/indeterminado), '
                '"severidad" (critica/alta/media), '
                '"acciones_ryu" (lista de acciones a ejecutar en la red), '
                '"mensaje_operador" (explicación en lenguaje natural), '
                '"alertas" (lista de canales: email/slack/sms).'
            ),
        }

        logger.info(f'[CAPA 3] Payload JSON para {src_ip}:\n'
                    f'{json.dumps(payload, indent=2, ensure_ascii=False)}')

        if AGENT_ENABLED:
            thread = threading.Thread(
                target=self._post_to_agent,
                args=(payload,),
                daemon=True,
            )
            thread.start()
        else:
            logger.info('[AGENTE] AGENT_ENABLED=False — '
                        'JSON registrado en log, no se envió al agente.')

    def _post_to_agent(self, payload):
        """
        Envía el payload JSON al agente LLM (hilo separado).
        Usa urllib de stdlib — sin dependencias externas.
        Si el agente responde con acciones, las ejecuta en la red.
        """
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req  = urllib.request.Request(
            AGENT_URL,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as resp:
                body    = resp.read().decode('utf-8')
                status  = resp.status
                logger.info(f'[AGENTE] HTTP {status} — respuesta recibida')
                try:
                    respuesta = json.loads(body)
                    self._ejecutar_respuesta_agente(
                        payload['host_origen'], respuesta
                    )
                except json.JSONDecodeError:
                    logger.warning(f'[AGENTE] Respuesta no es JSON válido: {body[:200]}')

        except urllib.error.URLError:
            logger.warning(f'[AGENTE] No disponible en {AGENT_URL} '
                           '— el JSON quedó registrado en el log')
        except Exception as e:
            logger.error(f'[AGENTE] Error inesperado: {e}')

    def _ejecutar_respuesta_agente(self, src_ip, respuesta):
        """
        Ejecuta las acciones que el agente LLM indicó en su respuesta.
        Estructura esperada del JSON del agente:
        {
          "veredicto": "confirmado" | "falso_positivo" | "indeterminado",
          "severidad": "critica" | "alta" | "media",
          "acciones_ryu": ["mantener_bloqueo", "desbloquear", "bloquear_subred"],
          "mensaje_operador": "...",
          "alertas": ["email", "slack", "sms"]
        }
        """
        veredicto = respuesta.get('veredicto', 'indeterminado')
        acciones  = respuesta.get('acciones_ryu', [])
        mensaje   = respuesta.get('mensaje_operador', '')
        alertas   = respuesta.get('alertas', [])

        logger.info(f'[AGENTE] Veredicto: {veredicto}')
        logger.info(f'[AGENTE] Mensaje:   {mensaje}')
        logger.info(f'[AGENTE] Acciones:  {acciones}')
        logger.info(f'[AGENTE] Alertas:   {alertas}')

        # Ejecutar acciones en la red
        for accion in acciones:
            if accion == 'desbloquear' and veredicto == 'falso_positivo':
                logger.info(f'[AGENTE] Desbloqueando {src_ip} (falso positivo)')
                self.blocked_hosts.discard(src_ip)
                self.host_alert_state[src_ip]['level'] = 'NORMAL'
                self.host_alert_state[src_ip]['metrics_triggered'].clear()
                # Nota: la regla DROP en OVS debe eliminarse manualmente
                # o via REST API de Ryu si está habilitada

            elif accion == 'mantener_bloqueo':
                logger.info(f'[AGENTE] Manteniendo bloqueo de {src_ip}')

            elif accion == 'bloquear_subred':
                logger.warning(f'[AGENTE] Acción bloquear_subred solicitada '
                               f'para subred de {src_ip} — '
                               f'requiere implementación manual')

            else:
                logger.warning(f'[AGENTE] Acción desconocida: {accion}')

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITOR M5 — reglas de observación east-west
    # ═══════════════════════════════════════════════════════════════════════════
    def _install_m5_monitor_rules(self, datapath):
        """
        Instala reglas de monitoreo para tráfico W2W en puertos críticos.
        Prioridad 10 — el paquete llega al controlador Y se reenvía normalmente.
        No bloquea nada — solo observa y cuenta para M5.
        El DROP solo llega si el host supera CRITICAL_THRESHOLD métricas.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid    = datapath.id
        count   = 0

        for tp_dst in CRITICAL_PORTS:
            for subred in (SUBNET_OPS, SUBNET_ADM):
                for src_s in range(1, 6):
                    for dst_s in range(1, 6):
                        if src_s == dst_s:
                            continue
                        try:
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ipv4_src=f'{subred}{src_s}',
                                ipv4_dst=f'{subred}{dst_s}',
                                ip_proto=6,
                                tcp_dst=tp_dst,
                            )
                            actions = [
                                parser.OFPActionOutput(
                                    ofproto.OFPP_CONTROLLER,
                                    ofproto.OFPCML_NO_BUFFER
                                ),
                                parser.OFPActionOutput(ofproto.OFPP_NORMAL),
                            ]
                            self._add_flow(
                                datapath, priority=10,
                                match=match, actions=actions,
                                idle_timeout=0, hard_timeout=0,
                            )
                            count += 1
                        except Exception:
                            pass

        logger.info(f'[M5] {count} reglas de monitoreo W2W instaladas '
                    f'en DPID={dpid:#018x} — DROP solo por umbral')

    # ═══════════════════════════════════════════════════════════════════════════
    # UTILIDADES
    # ═══════════════════════════════════════════════════════════════════════════
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, table_id=0):
        """Instala una regla OpenFlow en el switch."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = (
            [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            if actions else
            [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        )
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=table_id,
        )
        datapath.send_msg(mod)

    def _map_ioc(self, triggered):
        """Mapea las métricas disparadas a los IoC del catálogo."""
        t = set(triggered)
        iocs = []
        if {'M1', 'M2'}.issubset(t): iocs.append('IOC-01')
        if 'M3' in t:                iocs.append('IOC-02')
        if 'M4' in t:                iocs.append('IOC-03')
        if 'M5' in t:                iocs.append('IOC-04')
        if {'M5', 'M1'}.issubset(t): iocs.append('IOC-07')
        if len(t) >= CRITICAL_THRESHOLD: iocs.append('IOC-05')
        return sorted(set(iocs))

    def _get_topology_context(self, src_ip):
        """Infiere el segmento de red del host origen."""
        if src_ip.startswith(SUBNET_OPS):
            return f'VLAN OPS (ID={VLAN_OPS}), subred {SUBNET_OPS}0/24'
        if src_ip.startswith(SUBNET_ADM):
            return f'VLAN ADM (ID={VLAN_ADM}), subred {SUBNET_ADM}0/24'
        return 'subred desconocida'
