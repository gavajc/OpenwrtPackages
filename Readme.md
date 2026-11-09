# Network & System Diagnostic Daemons (`OpenWrt packages`)

Paquetes para dispositivos **OpenWrt** para ejecutar un demonio de telemetría y diagnóstico desarrollados en **C++17** y **Python 3**.


## 🚀 Características Clave (C++)

*   **Rendimiento Fulminante:** Recolección de métricas del sistema en microsegundos mediante llamadas directas a la memoria del kernel (`sysinfo`, `getifaddrs`).
*   **Asincronía de Alto Nivel:** Manejo de señales del sistema operativo (`SIGINT`/`SIGTERM`) mediante el subsistema asíncrono **`boost::asio::signal_set`** respaldado por el mecanismo nativo `signalfd` y `epoll` de Linux. El hilo principal se mantiene libre para la lógica de negocio.
*   **Espera Eficiente:** Dormido profundo con costo cero de CPU a través de **`std::condition_variable`**. Despierta instantáneamente ante señales del sistema operativo para un apagado limpio (RAII).
*   **Protección de Almacenamiento Flash:** Filtro estricto en RAM para actualizaciones del intervalo. El demonio **solo escribe en la Flash ROM vía UCI si el intervalo de tiempo cambia**, protegiendo las celdas de memoria del router contra la degradación física.
*   **Trazabilidad Industrial:** Integración directa con el demonio de logs nativo de OpenWrt (`logread`) mediante la API estándar de **`<syslog.h>`**, clasificando eventos críticos, advertencias y notas de red.

## 🚀 Características Clave (Python)

*   **Telemetria:** Recolección de métricas del sistema.
*   **Asincronía de Alto Nivel:** Manejo de señales del sistema operativo (`SIGINT`/`SIGTERM`).
*   **Espera Eficiente:** Dormido profundo con costo cero de CPU a través de **`std::condition_variable`** y **`epoll`**. Despierta instantáneamente ante señales del sistema operativo para un apagado limpio.
*   **Protección de Almacenamiento Flash:** Filtro estricto en RAM para actualizaciones del intervalo. El demonio **solo escribe en la Flash ROM vía UCI si el intervalo de tiempo cambia**, protegiendo las celdas de memoria del router contra la degradación física.
*   **Trazabilidad Industrial:** Integración directa con el demonio de logs nativo de OpenWrt (`logread`) mediante la API estándar de Python para consumir **`<syslog.h>`**.

---

## 🏗️ Arquitectura del Software (C++)

Revisar el repositorio del codigo C++ en:

	https://github.com/gavajc/diagnostic

Donde se detalla la arquitectura y los modulos del demonio.

---

---

## 🏗️ Arquitectura del Software (Python)

El proyecto sigue una estructura atómica y desacoplada basada en el **Principio de Responsabilidad Única (SRP)**:

1.  **`diagnostic_collector.py` (Utilidades del Sistema):** Biblioteca encargada de interrogar a ubus para optencion de telemetria (uptime, carga, interfaces de red, túneles VPN, servicios y pruebas síncronas de latencia/DNS).
2.  **`sysdiagnostic_main.py` (Orquestador Central):** Motor principal que gobierna el ciclo de vida del demonio: vacía la cola local, ejecuta la recolección, administra el almacenamiento temporal en la RAM-disk (`/tmp/sysdiagnostic/`) con un límite estricto de `N` reportes, y atiende las señales de red.

---

## 📦 Estructura del Archivo de Configuración (`/etc/config/*diagnostic`)

El demonio es completamente dinámico y obedece en caliente a las directrices dictadas por el archivo de configuración UCI de OpenWrt ambos demonios comparte las mismas configuraciones excepto por la seccion system, que solo la ocupa el demonio de C++.

Al ser el demonio de C++ un binario compilado, se debe tener un mecanismo para poder elegir que interfaz utilizar sin recompilar, por tal motivo dicha sección es utilizada por el demonio de C++. El archivo de configuración para el demonio en C++ es /etc/config/diagnostic mientras que para Python es /etc/config/sysdiagnostic

```ini

config sysdiagnostic 'system'
	option mac_interface 'br-lan'

config sysdiagnostic 'dns_test'
	option host 'openwrt.org'

config sysdiagnostic 'latency_test'
	option host 'openwrt.org'
	option port '443'

config sysdiagnostic 'api'
	option url 'http://tu-servidor-api.local'
	option token 'tu_bearer_token_secreto_aqui'

config sysdiagnostic 'schedule'
	option check_interval '60'
	option max_queued_reports '10'
```

---

## 🔄 Mecanismo de Almacenamiento Local (Cola Desconectada)

Si el enlace hacia la API REST se cae, o si no hay ninguna API configurada en UCI, el demonio activa de forma automática su modo offline:
*   Almacena los reportes en la RAM-disk local: C++ `/tmp/diagnostic/report_<timestamp>.json` y Python `/tmp/sysdiagnostic/report_<timestamp>.json`.
*   Monitorea la cantidad de archivos existentes basándose en la opción `max_queued_reports`.
*   Si se alcanza el límite máximo `N`, el sistema ordena los archivos cronológicamente, **elimina el reporte más antiguo de la memoria Flash/RAM** e inserta el nuevo, blindando al router contra desbordamientos de almacenamiento.
*   En cuanto el enlace de red se recupera, el demonio vacía secuencialmente (del más viejo al más nuevo) toda la cola pendiente antes de enviar la telemetría actual.

---

## 🛠️ Requisitos de Compilación (Toolchain de OpenWrt solo C++) 

El proyecto requiere enlazarse contra las librerías nativas del core del sistema operativo y las primitivas de hilos de C++17:

*   **Bandera de Estándar:** `-std=c++17`
*   **Banderas de Enlace:** `-luci -lubox -lcrypto -lssl -pthread`

El ejecutable final se genera bajo el nombre de **`diagnostic`** listo para ser administrado por el supervisor de servicios `procd`.


Para Python el proyecto no requiere compilacion pues son scripts de Python pero si requiere dependencias de Python como el core, ubus, uci y codecs (+python3-light +python3-uci +python3-ubus +python3-codecs).

El script ejecutable final se genera bajo el nombre de **`sysdiagnostic`** listo para ser administrado por el supervisor de servicios `procd`.

A diferencia del demonio en C++ este requiere tener al menos de 12MB a 14MB de espacio libre en ROM para poder funcionar, frente a los misero 437Kb utilizados por el demonio de C++
En cuanto a consumo de RAM se requiere entre 15 MB y 30 MB de memoria RAM. El simple hecho de levantar la máquina virtual de Python (python3-light) para que pueda interpretar código máquina en el router ya le cuesta al sistema un piso mínimo de unos 8 MB a 10 MB de RAM (el footprint base del proceso).
En cuanto el script ejecuta un import json, import os y módulos de red como urllib, Python carga pesados árboles de objetos, diccionarios de tipado dinámico y recolectores de basura en la memoria del router, disparando el consumo otros 10 MB a 15 MB.


## 📦 Instalacion y Uso

Para utilizarse, solo se debe agregar este repositorio al folder de paquetes de OpenWrt en la seccion que se desee (en nuestro ejercicio se utilizo: openwrt/packages/utils/) y generar el paquete ipk o apk segun la version que se utilice.
Tambien se puede integrar en una imagen completa para flashear algun dispositivo. Para desinstalar depende del gestor de paqutes utilizado. En este proyecto se uso OpenWrt 24.10 que aun utiliza el viejo opkg.

	opkg install diagnostic_1.0.0-r1_x86_64.ipk
	opkg remove diagnostic

Al Instalarse se ejecutara el demonio y comenzara a enviar la informacion a la API REST configurada en el archvio de configuracion.
Si se esta conectado por SSH, serial, etc se puede invocar a logread para ver el trace que deja el demonio:
	
	logread -f -e diagnostic

Se mostrara que esta en ejecucion, el envio del reporte al API REST, si hay respuesta de re calibracion del intervalo, lo indicara tambien en el log con el nuevo intervalo establecido.
Y no se requiere reiniciar pues acepta los cambios de manera automatica. También se indica en el log, los posibles fallos que se pudieran presentar como errores de transmision por caida d ela interfaz o negacion de servicio del API REST entre otros.

También se puede verificar su funcionamiento revisando el sitio de webhook.site configurado para la recepcion de los reportes, agregar o cambiar en la respuesta la configuracion del intervalo de funcionamiento del demonio.
En el momento que se creo este repositorio la URL de webhook es: https://webhook.site/50149264-2741-487a-be88-e973ff3f3a69

El mecanismo de health implementado es el siguiente:

	CRITICO: Cuando el load average es superior al 4.0 o la memoria RAM < 5%
	DEGRADED: Cuando algun test de conectividad fallo o no esta en ejecución alguno de los servicios monitoreados (dnsmasq, dropbear, firewall).
	OK: No se presento ninguno de los 2 anteriores.

Esto mismo aplica para el demonio hecho en C++ con al diferencia que el demonio de C++ se llama solo "diagnostic" y la URL de webhook es: https://webhook.site/7d30c803-89fc-4696-8214-1a82d615c0d7 
