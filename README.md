# Anti-DDoS Protection System v2.0

Sistema de proteccion DDoS multicapa en C++17 para Linux y Windows.

## Caracteristicas

### Capa 1: Proteccion en Kernel (eBPF/XDP) - Solo Linux
- Bloqueo SYN flood a nivel de driver de NIC
- Bloqueo UDP flood en kernel
- Rate limiting por IP en kernel
- Bloqueo CIDR/subred en kernel
- Blacklist de IPs en kernel
- Filtrado de puertos en kernel
- Estadisticas en tiempo real

### Capa 2: Proteccion en Userspace
- **Packet Engine**: Inspeccion profunda de paquetes (DPI)
- **VPN Detector**: Deteccion de OpenVPN, WireGuard, IPSec, Shadowsocks
- **Rate Limiter**: Token Bucket + Sliding Window + Fingerprinting
- **Behavioral Analyzer**: Deteccion de bots, scrapers, scanners
- **Geo Blocker**: Bloqueo por pais, ASN, datacenter
- **ML Detector**: Deteccion de anomalias via Isolation Forest
- **Honeypot**: Trampas multi-protocolo (HTTP, SSH, FTP, MySQL)

### Capa 3: Respuesta Automatica
- **Auto Responder**: Reglas de respuesta automatizada
- Escalacion progresiva (IP → CIDR → ASN → pais)
- Bloqueo automatico de atacantes
- Notificaciones de amenazas

### Capa 4: Inteligencia de Amenazas
- **Threat Intel**: Feeds de IPs maliciosas
- **ASN Database**: Base de datos de 15+ VPN providers
- Bloqueo automatico de proveedores VPN
- Bloqueo de datacenters

### Capa 5: Proteccion de Juegos (Half-Life/Source)
- Deteccion de query flood (A2S_INFO, A2S_PLAYER, A2S_RULES)
- Deteccion de connection flood
- Proteccion de servidores CS 1.6, CS:GO, CS2, Sven Co-op, Half-Life, Garry's Mod
- Rate limiting adaptado a juegos
- Auto-bloqueo de atacantes

### Capa 6: Gestion
- **CLI Interactivo**: 23+ comandos
- **API REST**: 7 endpoints para integracion
- **Daemon**: Servicio en background (Windows Service / Linux daemon)
- **Cluster**: Multi-nodo con sincronizacion de amenazas

## Juegos Soportados

| Juego | Puerto | Proteccion |
|-------|--------|------------|
| Half-Life | 27005-27015 | Query flood, Connection flood |
| Sven Co-op | 27011 | Query flood, Connection flood |
| Counter-Strike 1.6 | 27012-27015 | Query flood, Connection flood |
| Counter-Strike: Source | 27015 | Query flood, Connection flood |
| Counter-Strike: GO | 27015-27030 | Query flood, Connection flood |
| Counter-Strike 2 | 27015-27030 | Query flood, Connection flood |
| Garry's Mod | 27015 | Query flood, Connection flood |
| Day of Defeat | 27013 | Query flood, Connection flood |

## VPN Providers Bloqueados

NordVPN, ExpressVPN, Surfshark, Mullvad, ProtonVPN, CyberGhost, PIA, Hotspot Shield, Windscribe, IVPN, HideMyAss, PureVPN, IPVanish, StrongVPN, TunnelBear

## Requisitos

### Linux
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake libpcap-devel

# Para eBPF/XDP (opcional)
sudo apt-get install -y linux-headers-$(uname -r) libbpf-dev
```

### Windows
- Visual Studio 2022 (v17.14+)
- CMake 3.15+
- Windows SDK 10.0.26100.0
- WinPcap (opcional, para captura de paquetes)

## Instalacion

### Linux
```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/anti-ddos-project.git
cd anti-ddos-project

# Compilar
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Instalar
sudo make install

# O instalar manualmente
sudo cp ../bin/antiddos-cli /usr/local/bin/
sudo cp ../bin/antiddos-daemon /usr/local/bin/
sudo cp ../bin/antiddos-api /usr/local/bin/
sudo cp ../bin/antiddos-cluster /usr/local/bin/
sudo cp ../bin/antiddos-intel /usr/local/bin/
sudo mkdir -p /etc/antiddos
sudo cp ../config/config.ini /etc/antiddos/
```

### Windows
```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/anti-ddos-project.git
cd anti-ddos-project

# Compilar con Visual Studio
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Los ejecutables estan en bin/Release/
```

## Uso

### 1. Iniciar Proteccion Basica
```bash
# Linux - Iniciar daemon
sudo antiddos-daemon --daemon

# Windows - Iniciar como servicio
antiddos-daemon.exe

# Windows - Modo consola (para pruebas)
antiddos-daemon.exe --console
```

### 2. Controlar con CLI
```bash
# Ver estado
antiddos-cli status

# Ver estadisticas
antiddos-cli stats

# Monitoreo en tiempo real
antiddos-cli monitor
```

### 3. Bloquear IPs
```bash
# Bloquear IP individual
antiddos-cli block 10.0.0.1 3600

# Bloquear rango CIDR (todo un proveedor VPN)
antiddos-cli block 185.100.87.0/24 86400

# Ver IPs bloqueadas
antiddos-cli list-blocked

# Desbloquear
antiddos-cli unblock 10.0.0.1
```

### 4. Configurar Proteccion de Juegos
```bash
# Ejemplo: Proteger servidor CS 1.6 en puerto 27015
# El sistema detecta automaticamente el protocolo Half-Life/Source

# Configurar rate limiting para juegos
antiddos-cli set-threshold 50

# Bloquear proveedores VPN
antiddos-cli config
# Editar config.ini: block_vpn_providers=true
```

### 5. Bloquear Proveedores VPN
```bash
# Bloquear todos los proveedores VPN conocidos
# Editar /etc/antiddos/config.ini:
# [vpn_detection]
# block_vpn_providers = true

# O usar el CLI:
antiddos-cli config
```

### 6. Configurar API REST
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

### 7. Cluster Distribuido
```bash
# Nodo maestro
antiddos-cluster --cluster-id "prod" --port 7000

# Nodo esclavo
antiddos-cluster --cluster-id "prod" --join 192.168.1.100:7000
```

### 8. eBPF/XDP (Solo Linux)
```bash
# Cargar filtro en interfaz de red
sudo xdp-cli load /usr/lib/antiddos/xdp_filter_kern.o eth0

# Ver estado
sudo xdp-cli status

# Bloquear IP en kernel
sudo xdp-cli blacklist-add 10.0.0.1 3600 "ataque"

# Monitorear paquetes
sudo xdp-cli monitor
```

## Configuracion

Archivo: `/etc/antiddos/config.ini` (Linux) o `config/config.ini` (Windows)

```ini
[general]
daemon_mode = true
log_file = /var/log/antiddos/antiddos.log
log_level = INFO

[rate_limiting]
max_requests_per_second = 100
max_requests_per_minute = 1000
burst_size = 50
block_duration_seconds = 300
enable_adaptive = true
sensitivity = 0.5

[vpn_detection]
enabled = true
block_vpn_providers = true
block_datacenters = false
block_tor = true

[geo_blocking]
enabled = false
block_datacenters = false
block_proxies = false
block_tor = false

[game_protection]
enabled = true
max_queries_per_second = 50
max_connections_per_second = 10
auto_block_duration_seconds = 300

[firewall]
auto_block = true
block_duration = 300
whitelist_private_ips = true

[notifications]
enabled = true
email = admin@example.com
webhook_url =
alert_threshold = HIGH
```

## Estructura del Proyecto

```
anti-ddos-project/
├── packet-engine/          # Motor de paquetes + VPN Detector
├── rate-limiting/          # Rate limiter multi-algoritmo
├── advanced-mitigation/    # Behavioral analyzer + Geo blocker
├── game-protection/        # Proteccion Half-Life/CS/Sven Co-op
├── asn-database/           # Base de datos ASN + VPN providers
├── ml-detection/           # Detector de anomalias ML
├── honeypot/               # Sistema de trampas
├── auto-response/          # Respuesta automatizada
├── api-dashboard/          # API REST gateway
├── distributed/            # Cluster manager
├── threat-intel/           # Inteligencia de amenazas
├── ebpf-xdp/               # Filtro kernel eBPF/XDP (Linux)
├── orchestration/          # CLI + Daemon
├── shared/                 # Utilidades compartidas
├── tests/                  # Tests unitarios
├── config/                 # Archivos de configuracion
├── docs/                   # Documentacion
└── bin/                    # Ejecutables compilados
```

## Comandos CLI

| Comando | Descripcion |
|---------|-------------|
| `start` | Iniciar proteccion |
| `stop` | Detener proteccion |
| `status` | Ver estado del sistema |
| `stats` | Ver estadisticas de trafico |
| `block <ip> [seg]` | Bloquear una IP |
| `unblock <ip>` | Desbloquear una IP |
| `list-blocked` | Ver IPs bloqueadas |
| `config` | Ver configuracion |
| `set-threshold <valor>` | Cambiar limite de requests/seg |
| `set-sensitivity <0-1>` | Ajustar sensibilidad |
| `geo-block <pais>` | Bloquear un pais |
| `geo-allow <pais>` | Permitir un pais |
| `whitelist-add <ip>` | Agregar a whitelist |
| `blacklist-add <ip>` | Agregar a blacklist |
| `scan` | Escanear amenazas |
| `monitor` | Monitoreo en tiempo real |
| `logs` | Ver logs |
| `export` | Exportar config a JSON |
| `import` | Importar config desde JSON |
| `help` | Ver ayuda |
| `version` | Ver version |
| `quit` | Salir |

## API REST

| Metodo | Endpoint | Descripcion |
|--------|----------|-------------|
| GET | `/api/v1/status` | Estado del sistema |
| GET | `/api/v1/stats` | Estadisticas |
| GET | `/api/v1/blocked` | IPs bloqueadas |
| POST | `/api/v1/block` | Bloquear IP |
| POST | `/api/v1/unblock` | Desbloquear IP |
| GET | `/api/v1/incidents` | Incidentes activos |
| GET | `/api/v1/config` | Configuracion actual |

## Tests

```bash
# Ejecutar todos los tests
./bin/antiddos_tests

# Salida esperada:
# =============================================
#   Anti-DDoS System - Unit Tests
# =============================================
# Testing Packet Engine... OK
# Testing Rate Limiter... OK
# Testing VPN Detector... OK
# Testing Behavioral Analyzer... OK
# Testing ML Detector... OK
# Testing Honeypot System... OK
# Testing Auto Responder... OK
# Testing Threat Intelligence... OK
# Testing CIDR/Subnet Blocking... OK
# Testing Game Protector... OK
# Testing ASN Database... OK
# =============================================
#   All tests passed!
# =============================================
```

## Licencia

MIT License

## Contribuir

1. Fork el proyecto
2. Crear branch (`git checkout -b feature/nueva-funcionalidad`)
3. Commit (`git commit -m 'Agregar nueva funcionalidad'`)
4. Push (`git push origin feature/nueva-funcionalidad`)
5. Abrir Pull Request
