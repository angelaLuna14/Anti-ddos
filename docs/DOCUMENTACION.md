# Anti-DDoS Protection System v2.0 - Documentacion Completa

## Indice

1. [Resumen del Sistema](#1-resumen-del-sistema)
2. [Ejecutables](#2-ejecutables)
3. [Modulos](#3-modulos)
4. [Arquitectura](#4-arquitectura)
5. [Configuracion](#5-configuracion)
6. [Compilacion](#6-compilacion)
7. [Uso](#7-uso)

---

## 1. Resumen del Sistema

Sistema de proteccion DDoS multicapa escrito en C++17, con 12 modulos funcionales. Protege contra:

- **Ataques de volumen:** SYN flood, UDP flood, ICMP flood, DNS amplification, NTP amplification
- **Ataques de aplicacion:** HTTP flood, Slowloris, credential stuffing, API abuse
- **Bots y scrapers:** Deteccion de comportamiento automatizado via analisis conductual
- **Trafico VPN/Tor:** Identificacion y bloqueo de VPN, Tor, proxies
- **Amenazas geograficas:** Bloqueo por pais, ASN, datacenter, proxy
- **Amenazas avanzadas:** ML-based anomaly detection, honeypots, respuesta automatizada

**Caracteristicas:**
- Multiplataforma: Linux + Windows
- Proteccion en kernel: eBPF/XDP (solo Linux)
- Proteccion en userspace: DPI, rate limiting, analisis conductual
- Distribuido: Cluster multi-nodo con sincronizacion de amenazas
- API REST para integracion
- CLI interactivo con 23 comandos

---

## 2. Ejecutables

### 2.1 `antiddos-cli.exe` - Consola Interactiva

**Plataforma:** Linux + Windows
**Ejecutable:** 132 KB
**Proporcion:** Interfaz de usuario principal para controlar el sistema.

**Modos de ejecucion:**
```
antiddos-cli              # Modo interactivo (REPL con prompt "antiddos> ")
antiddos-cli <comando>    # Modo batch (ejecuta un comando y sale)
```

**Todos los comandos disponibles (23 comandos):**

| Comando | Aliases | Descripcion | Uso |
|---------|---------|-------------|-----|
| `start` | `run`, `on` | Iniciar el daemon de proteccion | `start` |
| `stop` | `halt`, `off` | Detener el daemon | `stop` |
| `status` | `info`, `st` | Mostrar estado del daemon (activo/inactivo, uptime) | `status` |
| `stats` | `statistics` | Mostrar estadisticas de trafico | `stats` |
| `block` | `ban`, `blacklist` | Bloquear IP en firewall del SO | `block <ip> [duracion_seg]` |
| `unblock` | `unban`, `whitelist` | Desbloquear IP | `unblock <ip>` |
| `list-blocked` | `blocked`, `lb` | Listar IPs bloqueadas | `list-blocked` |
| `config` | `cfg`, `conf` | Mostrar configuracion actual | `config` |
| `set-threshold` | `threshold`, `st` | Establecer limite de requests/segundo | `set-threshold <valor>` |
| `set-sensitivity` | `sensitivity`, `ss` | Ajustar sensibilidad de deteccion (0.0-1.0) | `set-sensitivity <0.0-1.0>` |
| `geo-block` | `gb` | Bloquear todo el trafico de un pais | `geo-block <codigo_pais>` |
| `geo-allow` | `ga` | Permitir trafico de un pais bloqueado | `geo-allow <codigo_pais>` |
| `geo-list` | `gl` | Listar reglas de geo-bloqueo | `geo-list` |
| `whitelist-add` | `wa` | Agregar IP a whitelist | `whitelist-add <ip>` |
| `whitelist-remove` | `wr` | Eliminar IP de whitelist | `whitelist-remove <ip>` |
| `whitelist-list` | `wl` | Listar IPs en whitelist | `whitelist-list` |
| `blacklist-add` | `ba` | Agregar IP a blacklist | `blacklist-add <ip>` |
| `blacklist-remove` | `br` | Eliminar IP de blacklist | `blacklist-remove <ip>` |
| `blacklist-list` | `bl` | Listar IPs en blacklist | `blacklist-list` |
| `scan` | `detect` | Escanear trafico en busca de amenazas | `scan` |
| `monitor` | `watch`, `live` | Monitoreo de trafico en tiempo real | `monitor` |
| `logs` | `log` | Mostrar logs recientes del sistema | `logs` |
| `update` | `upgrade` | Actualizar bases de datos de inteligencia | `update` |
| `export` | `save` | Exportar configuracion/datos a JSON | `export [archivo]` |
| `import` | `load` | Importar configuracion/datos desde archivo | `import <archivo>` |
| `help` | `?` | Mostrar ayuda | `help` |
| `version` | `ver`, `-v` | Mostrar version e info de compilacion | `version` |
| `quit` | `exit`, `q` | Salir del programa | `quit` |

**Modulos internos que utiliza:** `RateLimiter`, `BehavioralAnalyzer`, `GeoBlocker`

---

### 2.2 `antiddos-daemon.exe` - Servicio/Daemon

**Plataforma:** Linux + Windows
**Ejecutable:** 85 KB
**Proporcion:** Proceso de fondo que ejecuta la proteccion continua del sistema.

**Opciones de linea de comandos:**
```
antiddos-daemon                    # Ejecutar como servicio del SO
antiddos-daemon --console          # (Windows) Ejecutar en modo consola
antiddos-daemon --daemon           # (Linux) Daemonizar con fork
```

**Funcionamiento:**
- Lee configuracion de `config/config.ini`
- Inicializa `RateLimiter`, `BehavioralAnalyzer`, `GeoBlocker`, `VPNDetector`
- Loop interno cada 100ms:
  - Cada 5 minutos: limpia IPs bloqueadas expiradas
  - Cada 1 minuto: imprime estadisticas (requests totales, permitidos, bloqueados, bots detectados, atacantes detectados)
- Callbacks activos:
  - **Rate limiter:** Cuando bloquea una IP, la bloquea a nivel del firewall del SO via `platform::NetworkUtils::block_ip()`
  - **Behavioral analyzer:** Loggea tipo de comportamiento detectado (BOT, SCRAPER, SCANNER, DDOS, HTTP_FLOOD) con nivel de confianza

**Integracion con servicios del SO:**
- **Windows:** Se registra como Windows Service ("AntiDDoS") usando `SERVICE_TABLE_ENTRY` / `StartServiceCtrlDispatcher`
- **Linux:** Se daemoniza con `fork()`/`setsid()`/`umask(0)`
- **Senales:** SIGINT, SIGTERM (ambas plataformas), SIGQUIT (Linux)

---

### 2.3 `antiddos-api.exe` - API REST Gateway

**Plataforma:** Linux + Windows
**Ejecutable:** 77 KB
**Proporcion:** Servidor HTTP REST para integracion programatica con el sistema.

**Opciones:**
```
antiddos-api                             # Iniciar en puerto 8080
antiddos-api --port 9090                 # Puerto personalizado
antiddos-api --bind 127.0.0.1            # Solo localhost
antiddos-api --api-key "mi-clave"        # Autenticacion por API key
antiddos-api --no-auth                   # Sin autenticacion
antiddos-api --cors                      # Habilitar CORS
antiddos-api --help                      # Ayuda
```

**Endpoints REST disponibles:**

| Metodo | Endpoint | Descripcion |
|--------|----------|-------------|
| GET | `/api/v1/status` | Estado del sistema y version |
| GET | `/api/v1/stats` | Estadisticas de requests y amenazas |
| GET | `/api/v1/blocked` | Lista de IPs bloqueadas |
| POST | `/api/v1/block` | Bloquear una IP |
| POST | `/api/v1/unblock` | Desbloquear una IP |
| GET | `/api/v1/incidents` | Listar incidentes activos |
| GET | `/api/v1/config` | Obtener configuracion actual |

**Caracteristicas:**
- Generacion/validacion de tokens JWT
- Rate limiting por cliente
- Gestion de origenes CORS
- Pipeline de middleware
- Autenticacion por ruta

---

### 2.4 `antiddos-cluster.exe` - Gestor de Cluster

**Plataforma:** Linux + Windows
**Ejecutable:** 49 KB
**Proporcion:** Coordinacion multi-nodo para proteccion DDoS distribuida.

**Opciones:**
```
antiddos-cluster                                        # Iniciar nodo
antiddos-cluster --cluster-id "mi-cluster"              # ID del cluster
antiddos-cluster --join 192.168.1.100:7000              # Unirse a cluster existente
antiddos-cluster --port 7000                            # Puerto de escucha
antiddos-cluster --discover                             # Auto-descubrimiento (multicast)
antiddos-cluster --heartbeat 1000                       # Intervalo heartbeat (ms)
antiddos-cluster --help                                 # Ayuda
```

**Funcionamiento interno:**
- Nodos se comunican via protocolo de sincronizacion
- Eleccion de lider estilo Raft con term tracking
- Deteccion de nodos activos/inactivos/fallidos via heartbeat
- Sincronizacion de datos de amenazas entre nodos
- Auto-descubrimiento via multicast

**Roles de nodo:** LEADER, FOLLOWER, CANDIDATE, OBSERVER
**Estados de nodo:** ACTIVE, INACTIVE, SUSPECTED, FAILED, JOINING, LEAVING

---

### 2.5 `antiddos-intel.exe` - Inteligencia de Amenazas

**Plataforma:** Linux + Windows
**Ejecutable:** 64 KB
**Proporcion:** Gestion de feeds de inteligencia de amenazas y reputacion de IPs/dominios.

**Opciones:**
```
antiddos-intel                                            # Modo interactivo
antiddos-intel --database /path/to/db                     # Archivo de base de datos
antiddos-intel --add-feed https://example.com/feed.txt    # Agregar feed de amenazas
antiddos-intel --block-ip 10.0.0.1                        # Bloquear IP especifica
antiddos-intel --whitelist-ip 192.168.1.1                 # Whitelist IP
antiddos-intel --list                                     # Listar IPs bloqueadas
antiddos-intel --stats                                    # Estadisticas de inteligencia
antiddos-intel --export /path/to/export.json              # Exportar datos a JSON
antiddos-intel --import /path/to/import.json              # Importar datos desde JSON
antiddos-intel --help                                     # Ayuda
```

**Estadisticas que muestra:**
- Total Queries, Malicious Detections, Whitelist Hits
- Active Feeds, IP Entries, Domain Entries, Indicators

**Tipos de feeds soportados:**
IP_BLACKLIST, IP_WHITELIST, DOMAIN_BLACKLIST, URL_BLACKLIST, HASH_MALWARE, CIDR_BLOCKLIST, ASN_BLOCKLIST, VULNERABILITY, ATTACK_PATTERN, CUSTOM

---

### 2.6 `xdp-cli.exe` - CLI de Filtro eBPF/XDP (Solo Linux)

**Plataforma:** Solo Linux
**Proporcion:** Control interactivo del filtro eBPF en kernel para proteccion en tiempo real.

**Modos de ejecucion:**
```
xdp-cli                    # Modo interactivo (REPL con prompt "xdp> ")
xdp-cli <comando>          # Modo batch
```

**Comandos disponibles (17 comandos):**

| Comando | Aliases | Descripcion | Uso |
|---------|---------|-------------|-----|
| `load` | `attach` | Cargar programa XDP/eBPF en interfaz de red | `load [obj_path] [interfaz]` |
| `unload` | `detach` | Descargar programa XDP | `unload` |
| `status` | | Mostrar estado del filtro XDP | `status` |
| `stats` | | Mostrar estadisticas de paquetes XDP | `stats` |
| `blacklist-add` | `ba` | Agregar IP a blacklist en kernel | `blacklist-add <ip> [duracion] [razon]` |
| `blacklist-remove` | `br` | Eliminar IP de blacklist kernel | `blacklist-remove <ip>` |
| `blacklist-list` | `bl` | Listar IPs en blacklist kernel | `blacklist-list` |
| `port-block` | `pb` | Bloquear puerto en kernel | `port-block <puerto> [tcp/udp]` |
| `port-allow` | `pa` | Desbloquear puerto en kernel | `port-allow <puerto>` |
| `port-list` | `pl` | Listar filtros de puerto | `port-list` |
| `rate-limit` | `rl` | Establecer rate limit por IP en kernel | `rate-limit <ip> <pps>` |
| `rate-remove` | `rr` | Eliminar rate limit kernel | `rate-remove <ip>` |
| `rate-list` | | Listar rate limits kernel | `rate-list` |
| `config` | | Mostrar configuracion XDP | `config` |
| `monitor` | `watch` | Monitoreo en tiempo real de paquetes XDP | `monitor` |
| `interfaces` | `if` | Listar interfaces de red disponibles | `interfaces` |
| `help` | `?` | Mostrar ayuda | `help` |

**Requisitos:** Linux 4.18+, soporte eBPF en kernel, permisos root

---

### 2.7 `xdp-loader.exe` - Cargador eBPF/XDP (Solo Linux)

**Plataforma:** Solo Linux
**Proporcion:** Cargador no interactivo que adjunta el filtro XDP a una interfaz de red.

**Opciones:**
```
xdp-loader --interface eth0                              # Interfaz objetivo
xdp-loader --file /usr/lib/antiddos/xdp_filter_kern.o  # Archivo .o del filtro
xdp-loader --detach                                      # Desadjuntar programa XDP
xdp-loader --stats                                       # Cargar y mostrar estadisticas
xdp-loader --help                                        # Ayuda
```

**Funcionamiento:**
- Carga el programa eBPF en la interfaz de red especificada
- Ejecuta hasta que se presiona Ctrl+C
- Descarga gracefulmente el programa al salir
- Ideal para despliegue simple sin CLI interactivo

---

### 2.8 `antiddos_tests.exe` - Suite de Tests Unitarios

**Plataforma:** Linux + Windows
**Ejecutable:** 118 KB
**Proporcion:** Ejecuta 8 tests de verificacion de cada modulo del sistema.

| Test | Modulo que verifica |
|------|---------------------|
| `test_packet_engine()` | Instanciacion, configuracion de umbrales |
| `test_rate_limiter()` | Configuracion, primera request retorna ALLOW |
| `test_vpn_detector()` | Analisis de conexion con payload OpenVPN |
| `test_behavioral_analyzer()` | Toggle modo learning, analisis de request |
| `test_ml_detector()` | Configuracion de umbral, prediccion |
| `test_honeypot()` | Creacion de honeypot HTTP |
| `test_auto_responder()` | Creacion de reglas, procesamiento de amenazas, bloqueo de IPs |
| `test_threat_intel()` | Operaciones blacklist/whitelist, deteccion de IPs maliciosas |

**Ejecucion:**
```
.\bin\Release\antiddos_tests.exe
```

**Salida esperada:**
```
=============================================
  Anti-DDoS System - Unit Tests
=============================================

Testing Packet Engine...
  Packet Engine: OK
Testing Rate Limiter...
  Rate Limiter: OK
Testing VPN Detector...
  VPN Detector: OK
Testing Behavioral Analyzer...
  Behavioral Analyzer: OK
Testing ML Detector...
  ML Detector: OK
Testing Honeypot System...
  Honeypot System: OK
Testing Auto Responder...
  Auto Responder: OK
Testing Threat Intelligence...
  Threat Intelligence: OK

=============================================
  All tests passed!
=============================================
```

---

## 3. Modulos

### 3.1 Packet Engine (`packet-engine/`)

**Clase principal:** `antiddos::PacketEngine`
**Proposito:** Motor central de inspeccion profunda de paquetes (DPI).

**Que detecta:**
- SYN floods, UDP floods, ICMP floods, HTTP floods
- DNS amplification, NTP amplification, SSDP amplification
- Trafico VPN (OpenVPN, WireGuard, IPSec, Shadowsocks, V2ray)

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `start_capture(interface)` | Iniciar captura de paquetes |
| `stop_capture()` | Detener captura |
| `process_packet(packet)` | Analizar un paquete |
| `set_threshold(syn, packet, byte)` | Configurar umbrales de deteccion |
| `block_ip(ip, duration)` | Bloquear IP por duracion |
| `get_blocked_ips()` | Listar IPs bloqueadas |

**Tipos internos:**
- `PacketInfo` - Paquete capturado (IPs, puertos, protocolo, payload, timestamp)
- `ThreatLevel` - NONE, LOW, MEDIUM, HIGH, CRITICAL
- `ConnectionStats` - Metricas por conexion (packets, bytes, SYN/ACK/FIN/RST counts, scores)

---

### 3.2 VPN Detector (`packet-engine/`)

**Clase principal:** `antiddos::VPNDetector`
**Proposito:** Identificacion de trafico VPN/proxy/Tor via inspeccion profunda de paquetes.

**Que detecta:** OpenVPN, WireGuard, IPSec, L2TP, PPTP, SSTP, Shadowsocks, V2Ray, Trojan

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `analyze_connection(...)` | Analisis completo de conexion VPN |
| `is_known_vpn_provider(ip)` | Verificar si IP es de proveedor VPN conocido |
| `is_tor_exit_node(ip)` | Verificar si IP es nodo de salida Tor |
| `is_datacenter_ip(ip)` | Verificar si IP es de datacenter |
| `block_asn(asn)` | Bloquear un ASN completo |

---

### 3.3 Rate Limiter (`rate-limiting/`)

**Clase principal:** `antiddos::RateLimiter`
**Proposito:** Rate limiting multi-algoritmo con fingerprinting de conexion.

**Algoritmos implementados:**
- Token Bucket (burst handling)
- Sliding Window (rate tracking)
- Connection Fingerprint Anomaly Scoring

**Acciones posibles:** ALLOW, DROP, THROTTLE, CAPTCHA, REDIRECT, BLOCK_TEMPORARY, BLOCK_PERMANENT

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `check_request(src_ip)` | Evaluar request y retornar accion |
| `add_whitelist(ip)` / `add_blacklist(ip)` | Gestion de listas |
| `set_endpoint_limit(endpoint, max_rps)` | Rate limit por endpoint |
| `update_fingerprint(ip, fp)` | Actualizar fingerprint de navegador |
| `set_sensitivity(s)` | Ajustar sensibilidad |

---

### 3.4 Behavioral Analyzer (`advanced-mitigation/`)

**Clase principal:** `antiddos::BehavioralAnalyzer`
**Proposito:** Analisis conductual ML-inspirado para deteccion de bots y atacantes.

**Que detecta:** BOT, SCRAPER, SCANNER, DDOS, CREDENTIAL_STUFFING, API_ABUSE, SLOWLORIS, HTTP_FLOOD

**Analisis interno:**
- Patrones de temporizacion (regularidad de requests)
- Entropia de payload
- Consistencia de headers
- Patrones de traversal de endpoints
- Score de regularidad

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `analyze_request(src_ip, pattern)` | Alimentar request al analizador |
| `get_profile(ip)` | Obtener perfil de comportamiento |
| `detect_bots(min_confidence)` | Listar IPs de bots detectados |
| `set_learning_mode(enable)` | Toggle modo aprendizaje |

---

### 3.5 Geo Blocker (`advanced-mitigation/`)

**Clase principal:** `antiddos::GeoBlocker`
**Proposito:** Bloqueo geografico de IPs por pais, ASN, y tipo de trafico.

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `lookup(ip)` | Obtener ubicacion geografica |
| `is_blocked(ip)` | Verificar si IP esta bloqueada |
| `add_rule(rule)` | Agregar regla de geo-bloqueo |
| `add_blocked_country(rule, code)` | Bloquear pais |
| `set_block_datacenters(rule, bool)` | Bloquear IPs de datacenter |

---

### 3.6 ML Detector (`ml-detection/`)

**Clase principal:** `antiddos::ml::MLDetector`
**Proposito:** Deteccion de anomalias via aprendizaje automatico.

**Modelos soportados:** Isolation Forest, Random Forest, Neural Network, Autoencoder, SVM, Decision Tree

**Vector de features (16 dimensiones):** packets_per_second, bytes_per_second, syn/ack/fin/rst ratios, avg/std packet size, unique_ports, unique_ips, connection_duration, payload_entropy, header_consistency, timing_regularity, geo_dispersion, protocol_distribution

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `predict(features)` | Clasificar un vector de features |
| `train(samples)` | Entrenar modelo con muestras etiquetadas |
| `load_model(path)` / `save_model(path)` | Persistir modelos |

---

### 3.7 Honeypot System (`honeypot/`)

**Clase principal:** `antiddos::honeypot::HoneypotManager`
**Proposito:** Despliegue de honeypots multi-protocolo y rastreo de atacantes.

**Protocolos simulados:** HTTP, HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Memcached, DNS, Telnet, RDP

**Tracking de atacantes:**
- IPs, puertos, tiempos de conexion
- Comandos intentados, usernames/passwords probados
- Payloads capturados
- Fase del ataque (MITRE ATT&CK Kill Chain)
- Score de amenaza

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `create_honeypot(name, config)` | Crear honeypot |
| `start_honeypot(name)` | Iniciar honeypot |
| `get_sessions(honeypot)` | Obtener sesiones de atacantes |
| `export_sessions_json()` | Exportar datos de atacantes |

---

### 3.8 Auto Responder (`auto-response/`)

**Clase principal:** `antiddos::response::AutoResponder`
**Proposito:** Motor de respuesta automatizada basado en reglas.

**Acciones de respuesta:** LOG_ONLY, RATE_LIMIT, CAPTCHA, BLOCK_IP, BLOCK_PORT, REDIRECT, CHALLENGE, DROP_TRAFFIC, BLACKLIST, WHITELIST, NOTIFY_ADMIN, TRIGGER_HONEYPOT, GEO_BLOCK, THROTTLE

**API principal:**
| Metodo | Descripcion |
|--------|-------------|
| `process_threat(ip, attack_type, severity, confidence)` | Procesar amenaza y ejecutar acciones |
| `add_rule(rule)` | Agregar regla de respuesta |
| `get_active_incidents()` | Obtener incidentes activos |
| `export_incidents_json()` | Exportar incidentes |

---

### 3.9 API Gateway (`api-dashboard/`)

**Clase principal:** `antiddos::api::APIGateway`
**Proposito:** Servidor HTTP REST con autenticacion y middleware.

**Caracteristicas:** JWT, rate limiting por cliente, CORS, middleware pipeline, autenticacion por ruta.

---

### 3.10 Cluster Manager (`distributed/`)

**Clase principal:** `antiddos::distributed::ClusterManager`
**Proposito:** Coordinacion multi-nodo con eleccion de lider estilo Raft.

**Funciones:** Heartbeat, auto-descubrimiento multicast, sincronizacion de amenazas, reporte de metricas por nodo.

---

### 3.11 Threat Intelligence (`threat-intel/`)

**Clase principal:** `antiddos::intel::ThreatIntelManager`
**Proposito:** Agregacion de feeds de inteligencia y gestion de reputacion.

**Tipos de datos:**
- `IPReputation` - Nivel de reputacion, threat score, confianza, tags, pais, ASN, ISP
- `DomainReputation` - Reputacion de dominios (phishing, malware, C2)
- `AttackPattern` - Patrones de ataque con MITRE ATT&CK ID
- `ThreatIndicator` - IOCs genericos (tipo, valor, nivel, confianza, fuente)

---

## 4. Arquitectura

### Capas del Sistema

```
CAPA 3: GESTION (~10-50ms)
+------------------------------------------------------------------+
|  antiddos-cli     |  antiddos-api      |  antiddos-cluster        |
|  antiddos-daemon  |  antiddos-intel    |  xdp-cli (Linux)        |
+------------------------------------------------------------------+
        |                  |                     |
        v                  v                     v
CAPA 2: USERSPACE (~1-5ms)
+------------------------------------------------------------------+
|  PacketEngine <-> VPNDetector       (packet-engine/)             |
|  RateLimiter                        (rate-limiting/)             |
|  BehavioralAnalyzer <-> GeoBlocker  (advanced-mitigation/)       |
|  MLDetector                         (ml-detection/)              |
|  HoneypotManager                    (honeypot/)                  |
|  AutoResponder                      (auto-response/)             |
|  ThreatIntelManager                 (threat-intel/)              |
|  APIGateway                         (api-dashboard/)             |
|  ClusterManager                     (distributed/)               |
+------------------------------------------------------------------+
        |
        v
CAPA 1: KERNEL (<0.1ms)
+------------------------------------------------------------------+
|  eBPF/XDP: SYN flood | UDP flood | Rate limit | IP blacklist     |
|  (xdp_filter_kern.o adjunto a NIC via XDPLoader)                 |
+------------------------------------------------------------------+
```

### Flujo de Datos de un Paquete

1. **Capa 1 (Kernel):** Filtro XDP/eBPF corre a nivel de driver de NIC, descarta SYN floods, UDP floods, IPs en blacklist y rate-limited antes de que el paquete llegue al stack de red del kernel.

2. **Capa 2 (Userspace):** `PacketEngine` realiza DPI. `VPNDetector` verifica trafico VPN/proxy/tor. `RateLimiter` aplica token bucket + sliding window. `BehavioralAnalyzer` construye perfiles por IP y clasifica comportamiento. `GeoBlocker` verifica reglas de pais/ASN. `MLDetector` ejecuta deteccion de anomalias. `AutoResponder` ejecuta acciones automatizadas. `HoneypotManager` atrae atacantes a servicios decoy. `ThreatIntelManager` provee reputacion de IPs/dominios desde feeds externos.

3. **Capa 3 (Gestion):** `antiddos-cli` provee control humano. `antiddos-api` provee acceso REST. `antiddos-cluster` sincroniza datos de amenazas entre nodos. `antiddos-intel` agrega feeds de inteligencia. `antiddos-daemon` integra todo como proceso de fondo persistente.

---

## 5. Configuracion

Archivo: `config/config.ini`

```ini
[general]
daemon_mode = true
log_file = /var/log/antiddos/antiddos.log
log_level = INFO
pid_file = /var/run/antiddos.pid

[rate_limiting]
max_requests_per_second = 100
max_requests_per_minute = 1000
max_requests_per_hour = 10000
burst_size = 50
window_size_seconds = 60
block_duration_seconds = 300
enable_adaptive = true
sensitivity = 0.5

[behavioral_analysis]
learning_mode = false
min_samples = 1000
bot_threshold = 0.7
attack_threshold = 0.8
rate_limit_per_second = 100
rate_limit_per_minute = 1000

[geo_blocking]
enabled = false
database_path = /var/lib/antiddos/geoip.csv
block_datacenters = false
block_proxies = false
block_tor = false
block_vpn = false

[vpn_detection]
enabled = true
block_vpn = false
block_tor = true
custom_ports = 1194,51820,500,4500

[firewall]
auto_block = true
block_duration = 300
max_blocks_per_hour = 100
whitelist_private_ips = true

[notifications]
enabled = true
email = admin@example.com
webhook_url =
alert_threshold = HIGH

[performance]
max_connections = 10000
connection_timeout = 30
cleanup_interval = 300
stats_interval = 60

[network]
interface = auto
capture_mode = promiscuous
buffer_size = 4096
max_packets_per_second = 100000
```

---

## 6. Compilacion

### Requisitos

**Windows:**
- Visual Studio 2022 (v17.14+)
- CMake 3.15+
- Windows SDK 10.0.26100.0

**Linux:**
- GCC 9+ o Clang 10+
- CMake 3.15+
- libpcap-dev
- Linux 4.18+ (para eBPF/XDP)

### Pasos

```bash
# Crear directorio de build
mkdir build && cd build

# Configurar con CMake (Windows)
cmake .. -G "Visual Studio 17 2022" -A x64

# Configurar con CMake (Linux)
cmake .. -DCMAKE_BUILD_TYPE=Release

# Compilar
cmake --build . --config Release

# Ejecutar tests
.\bin\Release\antiddos_tests.exe       # Windows
./bin/antiddos_tests                   # Linux
```

### Estructura de salida

```
bin/Release/
  antiddos-cli.exe          # Consola interactiva
  antiddos-daemon.exe       # Servicio/daemon
  antiddos-api.exe          # API REST
  antiddos-cluster.exe      # Gestor de cluster
  antiddos-intel.exe        # Inteligencia de amenazas
  antiddos_tests.exe        # Tests unitarios
  antiddos_core.lib         # Libreria estatica core
  antiddos_extended.lib     # Libreria estatica extendida
```

---

## 7. Uso

### Ejemplo 1: Iniciar proteccion basica

```bash
# Iniciar daemon en modo consola
antiddos-daemon --console

# En otra terminal, verificar estado
antiddos-cli status
antiddos-cli stats
```

### Ejemplo 2: Bloquear IP manualmente

```bash
antiddos-cli block 10.0.0.1 3600       # Bloquear por 1 hora
antiddos-cli list-blocked               # Ver IPs bloqueadas
antiddos-cli unblock 10.0.0.1           # Desbloquear
```

### Ejemplo 3: Configurar geo-bloqueo

```bash
antiddos-cli geo-block CN               # Bloquear trafico de China
antiddos-cli geo-block RU               # Bloquear trafico de Rusia
antiddos-cli geo-list                   # Ver reglas activas
```

### Ejemplo 4: Monitoreo en tiempo real

```bash
antiddos-cli monitor                    # Vista en tiempo real
```

### Ejemplo 5: API REST

```bash
# Iniciar API
antiddos-api --port 8080 --api-key "mi-clave-secreta"

# Consultar status
curl -H "X-API-Key: mi-clave-secreta" http://localhost:8080/api/v1/status

# Bloquear IP via API
curl -X POST -H "X-API-Key: mi-clave-secreta" \
     -H "Content-Type: application/json" \
     -d '{"ip":"10.0.0.1","duration":3600}' \
     http://localhost:8080/api/v1/block
```

### Ejemplo 6: Cluster distribuido

```bash
# Nodo maestro
antiddos-cluster --cluster-id "prod-cluster" --port 7000

# Nodo esclavo
antiddos-cluster --cluster-id "prod-cluster" --join 192.168.1.100:7000
```

### Ejemplo 7: eBPF/XDP (Linux)

```bash
# Cargar filtro en interfaz
xdp-cli load /usr/lib/antiddos/xdp_filter_kern.o eth0

# Ver estado
xdp-cli status
xdp-cli stats

# Bloquear IP en kernel
xdp-cli blacklist-add 10.0.0.1 3600 "ataque SYN flood"

# Monitorear paquetes
xdp-cli monitor
```

### Ejemplo 8: Threat Intelligence

```bash
antiddos-intel --add-feed https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
antiddos-intel --block-ip 10.0.0.1
antiddos-intel --stats
antiddos-intel --list
```
