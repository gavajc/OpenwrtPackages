import datetime
import os
import socket
import time
import ubus

class Result:
    """Contenedor de respuesta unificado al estilo C-Struct / std::expected"""

    def __init__(self, success, error_code=0, error_msg="", data=None):
        self.success = success  # bool: True si la operación fue exitosa
        self.error_code = error_code  # int: Código numérico de error (tipo errno)
        self.error_msg = error_msg  # str: Mensaje descriptivo del problema
        self.data = data  # El payload real retornado si success es True

class SysDiagnosticCollector:

    def __init__(self):
        self.agent_version = "1.0.0"
        self.total_memory_kb = -1

        # C++ Style: Deliver a fully valid object or atomic failure
        # If ubusd is not ready, we throw an unhandled exception to signal procd
        if not ubus.connect():
            raise RuntimeError("Critical: Could not connect to ubusd socket.")

    def get_free_storage_kb(self, path):
        try:
            st = os.statvfs(path)
            space_kb = int((st.f_bavail * st.f_frsize) / 1024)
            return Result(success=True, data=space_kb)
        except OSError as e:
            return Result(
                success=False,
                error_code=e.errno,
                error_msg=f"Kernel statvfs failed: {e.strerror}",
            )

    def get_system_load_avg(self):
        try:
            res = ubus.call("system", "info", {})
            if res and isinstance(res, list) and len(res) > 0:
                info_dict = res[0]  # <--- CORRECCIÓN CLAVE: Indexación de lista
                load_array = info_dict.get("load")
                if load_array and isinstance(load_array, list) and len(load_array) > 0:
                    integer_average = sum(load_array) / len(load_array)
                    load_decimal = round(integer_average / 65536.0, 2)
                    return Result(success=True, data=load_decimal)

                return Result(success=False, error_code=1002, error_msg="Key 'load' missing or invalid in system info dict")
            return Result(success=False, error_code=1003, error_msg="Empty or unexpected structure from ubus call")
        except Exception as e:
            return Result(success=False, error_code=1000, error_msg=f"Ubus call exception: {str(e)}")

    def get_system_uptime(self):
        try:
            res = ubus.call("system", "info", {})
            # Extraemos de forma estricta el primer diccionario de la lista res[0]
            if res and isinstance(res, list) and len(res) > 0:
                info_dict = res[0]  # <--- CORRECCIÓN CLAVE: Indexación de lista
                uptime_val = info_dict.get("uptime")
                if uptime_val is not None:
                    return Result(success=True, data=int(uptime_val))

                return Result(success=False, error_code=1004, error_msg="Key 'uptime' missing in system info dict")
            return Result(success=False, error_code=1003, error_msg="Empty or unexpected structure from ubus call")
        except Exception as e:
            return Result(success=False, error_code=1000, error_msg=f"Ubus call exception: {str(e)}")
            
    def get_services_status(self, service_list):
        status_report = {}
        try:
            for srv in service_list:
                res = ubus.call("service", "list", {"name": srv})
                if res and isinstance(res, list) and len(res) > 0:
                    payload = res[0]  # <--- CORRECCIÓN CLAVE: El list de service también usa indexación [0]
                    if srv in payload:
                        service_data = payload.get(srv, {})
                        instances = service_data.get("instances", {})
                        if instances and any(inst.get("running") for inst in instances.values()):
                            status_report[srv] = "OK"
                            continue
                        if srv == "firewall":
                            # Punto 2, del review: En sistemas modernos, el firewall no es un demonio activo que este en ejecución
                            # por lo que no tiene un estado en ubus ni en /proc. Ubus regresa un objeto vacio por lo que para poder 
                            # medir si esta activo el firewall verificamos que exista el archivo de tablas del kernel tal cual hice en C++.
                            tablesPath = "/proc/net/ip_tables_names"

                            if os.path.isfile(tablesPath):
                                status_report[srv] = "OK"
                                continue
                status_report[srv] = "fail"
            return Result(success=True, data=status_report)
        except Exception as e:
            return Result(success=False, error_code=1000, error_msg=f"Ubus service call failed: {str(e)}")

    def get_network_interfaces(self, only_active=True):
        # Synchronously extracts network profiles returning a unified Result container
        interfaces_list = []
        network_dump = {}

        try:
            res = ubus.call("network.interface", "dump", {})
            if res and isinstance(res, list) and len(res) > 0:
                network_dump = res[0]
                
                for iface in network_dump.get("interface", []):
                    v4_list = iface.get("ipv4-address", [])
                    v6_list = iface.get("ipv6-address", [])

                    if not only_active or (v4_list or v6_list):
                        dns_list = iface.get("dns-server", [])
                        route_list = iface.get("route", [])

                        v4_data = v4_list[0] if (isinstance(v4_list, list) and len(v4_list) > 0) else {}
                        v6_data = v6_list[0] if (isinstance(v6_list, list) and len(v6_list) > 0) else {}
                        route_data = route_list[0] if (isinstance(route_list, list) and len(route_list) > 0) else {}

                        ipv4_str = f"{v4_data.get('address')}/{v4_data.get('mask')}" if v4_data.get('address') else None
                        ipv6_str = f"{v6_data.get('address')}/{v6_data.get('assignment')}" if v6_data.get('address') else None
                        gateway_str = route_data.get("nexthop", "0.0.0.0")

                        interfaces_list.append({
                            "interface": iface.get("interface"),
                            "status": "OK" if iface.get("up") else "fail",
                            "protocol": iface.get("proto"),
                            "ipv4": ipv4_str,
                            "ipv6": ipv6_str,
                            "dns_server": dns_list if dns_list else None,
                            "gateway": gateway_str
                        })
            return Result(success=True, data=(interfaces_list, network_dump))
        except Exception as e:
            return Result(success=False, error_code=1000, error_msg=f"Ubus network dump exception: {str(e)}")

    def get_active_vpns(self, network_dump):
        # Inspects active system devices exposed by the Linux Kernel to match virtual VPN layers
        vpns = []
        if not network_dump:
            return Result(success=True, data=None)

        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()

            for line in lines:
                if ":" not in line:
                    continue
                iface_name = line.split(":")[0].strip()

                vpn_type = None
                if iface_name.startswith("tun"):
                    vpn_type = "openvpn"
                elif iface_name.startswith("wg"):
                    vpn_type = "wireguard"

                if vpn_type:
                    ip_address = None
                    for interface in network_dump.get("interface", []):
                        if interface.get("device") == iface_name:
                            v4_addrs = interface.get("ipv4-address", [])
                            if v4_addrs and isinstance(v4_addrs, list) and len(v4_addrs) > 0:
                                ip_address = v4_addrs[0].get("address")
                            else:
                                v6_addrs = interface.get("ipv6-address", [])
                                if v6_addrs and isinstance(v6_addrs, list) and len(v6_addrs) > 0:
                                    ip_address = v6_addrs[0].get("address")
                            break

                    vpns.append({
                        "interface": iface_name,
                        "type": vpn_type,
                        "ip": ip_address
                    })
            return Result(success=True, data=vpns if vpns else None)
        except OSError as e:
            return Result(success=False, error_code=e.errno, error_msg=f"Kernel netdev read failed: {e.strerror}")

    def run_dns_test(self, host):
        if not host:
            return Result(success=True, data={"status": "skipped", "host": None, "resolved_ip": None})

        try:
            resolved_ip = socket.gethostbyname(host)
            return Result(success=True, data={"status": "success", "host": host, "resolved_ip": resolved_ip})
        except socket.gaierror as e:
            return Result(success=False, data={"status": "failed", "host": host, "resolved_ip": None})

    def run_latency_test(self, host, port):
        # Estimates network latency utilizing strict TCP errno inspection and Result patterns
        if not host:
            return Result(success=True, data={"status": "skipped", "host": None, "latency_ms": -1})

        import errno
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)

        start_time = time.perf_counter()
        try:
            sock.connect((host, port))
            latency = (time.perf_counter() - start_time) * 1000
            sock.close()
            return Result(success=True, data={
                "status": "success",
                "host": host,
                "latency_ms": round(latency, 2)
            })
        except OSError as e:
            latency = (time.perf_counter() - start_time) * 1000
            try:
                sock.close()
            except OSError:
                pass

            # C-Style Errno Audit: ECONNREFUSED or ECONNRESET means the remote host is alive!
            if e.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                return Result(success=True, data={
                    "status": "success",
                    "host": host,
                    "latency_ms": round(latency, 2)
                })
            
            # True network drop fault (ENETUNREACH, EHOSTUNREACH, ETIMEDOUT, or socket timeout)
            # We strictly enforce success=False accompanied by the exact OS kernel errno
            err_code = e.errno if e.errno else 110 # 110 is ETIMEDOUT fallback
            return Result(
                success=False, 
                error_code=err_code, 
                error_msg=os.strerror(err_code) if e.errno else "Socket connection timeout expired",
                data={"status": "failed", "host": host, "latency_ms": -1}
            )

    def generate_diagnostic(self, config_data):
        # Initial scaffold for the telemetry report tree
        report = {
            "agent_version": self.agent_version,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "system": {},
            "resources": {},
            "network_interfaces": [],
            "services": {},
            "vpns": None,
            "diagnostics": {},
            "health": {"status": "OK", "reasons": []}
        }

        reasons = []
        # Flag structural tracker to audit critical execution path failures
        orchestration_success = True
        fatal_msg = ""

        # 1. Base board details via direct síncrono ubus call
        try:
            board_res = ubus.call("system", "board", {})
            if board_res and isinstance(board_res, list) and len(board_res) > 0:
                board_data = board_res[0]  # <--- CORRECCIÓN: Extraer el diccionario de la lista
                report["system"]["hostname"] = board_data.get("hostname")
                report["system"]["model"] = board_data.get("model")
                report["system"]["board"] = board_data.get("board_name")
                release = board_data.get("release", {})
                report["system"]["version"] = f"{release.get('distribution', 'OpenWrt')} {release.get('version', '')}"
            else:
                reasons.append("ubus_board_structure_invalid")
                orchestration_success = False
                fatal_msg += "[Board Structure Invalid] "
        except Exception as e:
            reasons.append("ubus_board_call_failed")
            orchestration_success = False
            fatal_msg += f"[Board Call Exception: {str(e)}] "

        # 2. Extract metrics verifying the strict internal Result status
        uptime_res = self.get_system_uptime()
        if uptime_res.success:
            report["system"]["uptime_seconds"] = uptime_res.data
        else:
            report["system"]["uptime_seconds"] = -1
            reasons.append("uptime_fetch_failed")
            orchestration_success = False
            fatal_msg += f"[Uptime: {uptime_res.error_msg}] "

        load_res = self.get_system_load_avg()
        if load_res.success:
            report["system"]["load_average_summary"] = load_res.data
        else:
            report["system"]["load_average_summary"] = -1.0
            reasons.append("load_avg_fetch_failed")
            orchestration_success = False
            fatal_msg += f"[LoadAvg: {load_res.error_msg}] "

        # 3. Synchronously grab memory bounds data
        try:
            info_res = ubus.call("system", "info", {})
            if info_res and isinstance(info_res, list) and len(info_res) > 0:
                memory = info_res[0].get("memory", {})  # <--- CORRECCIÓN: Extraer de info_res[0]
                self.total_memory_kb = int(memory.get("total", 0) / 1024)
                report["resources"]["free_memory_kb"] = int(memory.get("free", 0) / 1024)
            else:
                reasons.append("ubus_memory_structure_invalid")
                orchestration_success = False
                fatal_msg += "[Memory Structure Invalid] "
        except Exception as e:
            reasons.append("ubus_memory_call_failed")
            orchestration_success = False
            fatal_msg += f"[Memory Call Exception: {str(e)}] "

        # 4. Extract Primary bridge MAC address directly from Linux sysfs standard (C-style)
        try:
            with open("/sys/class/net/br-lan/address", "r") as f:
                report["system"]["mac_principal"] = f.read().strip()
        except OSError as e:
            report["system"]["mac_principal"] = "00:00:00:00:00:00"
            reasons.append("sysfs_mac_read_failed")
            orchestration_success = False
            fatal_msg += f"[Sysfs MAC Error: {e.strerror}] "

        # 5. Populate Storage maps via verified Result returns
        overlay_res = self.get_free_storage_kb("/overlay")
        report["resources"]["free_overlay_kb"] = overlay_res.data if overlay_res.success else -1
        if not overlay_res.success:
            reasons.append("overlay_storage_fetch_failed")
            orchestration_success = False
            fatal_msg += f"[Overlay storage: {overlay_res.error_msg}] "

        tmp_res = self.get_free_storage_kb("/tmp")
        report["resources"]["free_tmp_kb"] = tmp_res.data if tmp_res.success else -1
        if not tmp_res.success:
            reasons.append("tmp_storage_fetch_failed")
            orchestration_success = False
            fatal_msg += f"[Tmp storage: {tmp_res.error_msg}] "

        # 6. Gather network configurations extracting the payload from Result
        net_res = self.get_network_interfaces(only_active=True)
        interfaces_list, network_dump = net_res.data if net_res.success else ([], {})
        report["network_interfaces"] = interfaces_list
        if not net_res.success:
            reasons.append("network_interfaces_fetch_failed")
            orchestration_success = False
            fatal_msg += f"[Network Dump: {net_res.error_msg}] "

        # 7. Extract dynamic VPN links crossing data with the unmapped kernel devices list
        vpn_res = self.get_active_vpns(network_dump)
        report["vpns"] = vpn_res.data if vpn_res.success else None
        if not vpn_res.success:
            reasons.append("vpn_kernel_scan_failed")
            orchestration_success = False
            fatal_msg += f"[VPN Kernel Scan: {vpn_res.error_msg}] "

        # 8. Check essential procd infrastructure service nodes
        srv_res = self.get_services_status(["dnsmasq", "dropbear", "firewall"])
        report["services"] = srv_res.data if srv_res.success else {"dnsmasq": "fail", "dropbear": "fail", "firewall": "fail"}
        if not srv_res.success:
            reasons.append("services_procd_fetch_failed")
            orchestration_success = False
            fatal_msg += f"[Procd Services: {srv_res.error_msg}] "

        # 9. Trigger network diagnostic socket testing hooks (Internal error handles success=True)
        dns_target = config_data.get("dns_host")
        lat_target = config_data.get("latency_host")
        lat_port = config_data.get("latency_port", 443)

        dns_test_res = self.run_dns_test(dns_target)
        report["diagnostics"]["dns_test"] = dns_test_res.data

        lat_test_res = self.run_latency_test(lat_target, lat_port)
        report["diagnostics"]["latency_test"] = lat_test_res.data

        # 10. Process threshold resource analytical checks
        free_mem = report["resources"].get("free_memory_kb", -1)
        load_summary = report["system"].get("load_average_summary", -1.0)

        if ((self.total_memory_kb > 0 and free_mem >= 0 and (free_mem / self.total_memory_kb) < 0.05)
            or (load_summary > 4.0)
            or (not dns_test_res.success and not lat_test_res.success)
        ):
            report["health"]["status"] = "critical"
            if load_summary > 4.0:
                reasons.append("high_cpu_load")
            if self.total_memory_kb > 0 and free_mem >= 0 and (free_mem / self.total_memory_kb) < 0.05:
                reasons.append("out_of_memory")
            if not dns_test_res.success:
                reasons.append("dns_test_failed")
            if not lat_test_res.success:
                reasons.append("latency_test_failed")

        # Degraded or infrastructure failure condition evaluations
        if report["health"]["status"] != "critical":
            if report["diagnostics"]["dns_test"]["status"] == "failed":
                reasons.append("dns_test_failed")
            if report["diagnostics"]["latency_test"]["status"] == "failed":
                reasons.append("latency_test_failed")
            for srv_name, srv_status in report["services"].items():
                if srv_status == "fail":
                    reasons.append(f"{srv_name}_service_down")

            if reasons:
                report["health"]["status"] = "degraded"

        report["health"]["reasons"] = reasons
        
        # === UNIFIED PATTERN RESULT RETURN BOUNDARY ===
        if orchestration_success:
            return Result(success=True, data=report)
        else:
            # We return success=False but STILL deliver the partial payload structure inside data
            return Result(success=False, error_code=1005, error_msg=fatal_msg, data=report)

