#!/usr/bin/env python3
import json
import sys
import sysdiagnostic_collector

def run_unit_tests():
    print("=== STARTING SYS_DIAGNOSTIC_COLLECTOR UNIT TESTS (PATTERN RESULT) ===")
    
    # Flag global para rastrear si ocurre alguna falla en el circuito
    all_tests_passed = True
    
    # 1. Instanciación protegida por el constructor atómico
    try:
        collector = sysdiagnostic_collector.SysDiagnosticCollector()
    except RuntimeError as e:
        print(f"\n[CRITICAL FATAL] Constructor failed: {e}")
        print("\n**************************************************")
        print("  VERDICT: TESTS FAILED (Initialization Crash)")
        print("**************************************************")
        sys.exit(1)

    # 2. Test get_system_uptime
    print("\n[TEST 1] Testing System Uptime Extraction:")
    uptime_res = collector.get_system_uptime()
    if uptime_res.success:
        print(f"  -> SUCCESS: {uptime_res.data} seconds")
    else:
        print(f"  -> FAILED [{uptime_res.error_code}]: {uptime_res.error_msg}")
        all_tests_passed = False

    # 3. Test get_system_load_avg
    print("\n[TEST 2] Testing System Load Average Summary:")
    load_res = collector.get_system_load_avg()
    if load_res.success:
        print(f"  -> SUCCESS: {load_res.data}")
    else:
        print(f"  -> FAILED [{load_res.error_code}]: {load_res.error_msg}")
        all_tests_passed = False

    # 4. Test get_free_storage_kb
    print("\n[TEST 3] Testing Virtual Storage Free Space Calculations:")
    overlay_res = collector.get_free_storage_kb("/overlay")
    tmp_res = collector.get_free_storage_kb("/tmp")
    
    if overlay_res.success and tmp_res.success:
        print(f"  -> SUCCESS: /overlay={overlay_res.data} KB, /tmp={tmp_res.data} KB")
    else:
        if not overlay_res.success:
            print(f"  -> /overlay FAILED [{overlay_res.error_code}]: {overlay_res.error_msg}")
        if not tmp_res.success:
            print(f"  -> /tmp FAILED [{tmp_res.error_code}]: {tmp_res.error_msg}")
        all_tests_passed = False

    # 5. Test get_services_status
    print("\n[TEST 4] Testing Procd Services Isolation Status:")
    services_to_probe = ["dnsmasq", "dropbear", "firewall", "non_existent_srv"]
    srv_res = collector.get_services_status(services_to_probe)
    
    if srv_res.success:
        print(f"  -> SUCCESS Map: {json.dumps(srv_res.data, indent=2)}")
        # Nota: Que 'non_existent_srv' dé "fail" dentro del mapa es correcto y esperado,
        # lo importante es que el método se ejecutó con éxito (success=True)
    else:
        print(f"  -> FAILED [{srv_res.error_code}]: {srv_res.error_msg}")
        all_tests_passed = False

    # 6. Test get_network_interfaces
    print("\n[TEST 5] Testing Network Interface Profiles:")
    net_res = collector.get_network_interfaces(only_active=True)
    if net_res.success:
        interfaces_list, raw_dump = net_res.data  # Unpack the tuple payload
        print(f"  -> SUCCESS: Detected {len(interfaces_list)} active interface profiles.")
    else:
        print(f"  -> FAILED [{net_res.error_code}]: {net_res.error_msg}")
        all_tests_passed = False
        raw_dump = {}  # Fallback for next test

    # 7. Test get_active_vpns (Uso del método público renombrado sin guion bajo)
    print("\n[TEST 5b] Testing VPN Kernel Interface Scanner via sysfs:")
    vpn_res = collector.get_active_vpns(raw_dump)
    if vpn_res.success:
        if vpn_res.data is None:
            print("  -> SUCCESS: No active virtual VPN layers detected in Kernel (Expected).")
        else:
            print(f"  -> SUCCESS Map: {json.dumps(vpn_res.data, indent=2)}")
    else:
        print(f"  -> FAILED [{vpn_res.error_code}]: {vpn_res.error_msg}")
        all_tests_passed = False

    # 8. Test standalone network boundary hooks
    print("\n[TEST 6] Testing Isolated Sockets Diagnostics (DNS and TCP Latency):")
    dns_res = collector.run_dns_test("nxtview.com")
    # Apuntamos a localhost puerto 80 para garantizar que no muera por el firewall de la VM
    latency_res = collector.run_latency_test("nxtview.com", 443)
    
    if dns_res.success and latency_res.success:
        print(f"  -> DNS Outcome: {json.dumps(dns_res.data)}")
        print(f"  -> TCP Latency Outcome: {json.dumps(latency_res.data)}")
    else:
        if not dns_res.success:
            print(f"  -> DNS Test FAILED [{dns_res.error_code}]: {dns_res.error_msg}")
        if not latency_res.success:
            print(f"  -> Latency Test FAILED [{latency_res.error_code}]: {latency_res.error_msg}")
        all_tests_passed = False

    # 9. Test global generate_diagnostic orchestrator
    print("\n[TEST 7] Testing Global Orchestrator (Full Report JSON Mapping):")
    mock_config = {"dns_host": "openwrt.org", "latency_host": "nxtview.com", "latency_port": 443}
    
    diagnostic_res = collector.generate_diagnostic(mock_config)
    if diagnostic_res.success:
        print("  -> SUCCESS: Full diagnostic payload orchestrated correctly.")
        print(json.dumps(diagnostic_res.data, indent=2))
    else:
        print(f"  -> DEGRADED/FAILED ORCHESTRATION [{diagnostic_res.error_code}]: {diagnostic_res.error_msg}")
        print("  -> Partial Data Captured:")
        print(json.dumps(diagnostic_res.data, indent=2))
        all_tests_passed = False # Levanta la bandera global si el reporte falló internamente

    # === EVALUACIÓN DE VEREDICTO FINAL ===
    print("\n==================================================")
    if all_tests_passed:
        print("  VERDICT: TESTS PASSED")
        print("==================================================")
        sys.exit(0)
    else:
        print("  VERDICT: TESTS FAILED")
        print("==================================================")
        sys.exit(1)

if __name__ == "__main__":
    run_unit_tests()

