#!/usr/bin/env python3
import json
import os
import select
import signal
import sys
import syslog
import time
import urllib.error
import urllib.request

# C++ Style: Include the private directory into Python's search path arrays
sys.path.append("/usr/share/sysdiagnostic")

import sysdiagnostic_collector # Now we can import the collector namespace smoothly regardless of Python's system version

# Initialize the system logread context to identify this daemon instance natively
syslog.openlog(ident="sysdiagnostic", logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

# Global execution control flag
keep_running = True

# Thread-safe global system dictionary configuration containing robust defaults
config = {
    "dns_host": "openwrt.org",
    "latency_host": "openwrt.org",
    "latency_port": 443,
    "api_url": None,
    "api_token": None,
    "check_interval": 60,
    "max_queued_reports": 10
}

# Define the local volatile RAM location path to stack pending diagnostics offline
QUEUE_DIR = "/tmp/sysdiagnostic"

# 1. Establish the POSIX anonymous pipe file descriptors (read_fd, write_fd)
pipe_read_fd, pipe_write_fd = os.pipe()

# 2. Instantiate and optimize the native poll object outside the main loop execution
poll_obj = select.poll()
poll_obj.register(pipe_read_fd, select.POLLIN)

def signal_handler(signum, frame):
    # Dynamic signal handler to catch incoming SIGTERM or SIGINT from procd
    global keep_running
    syslog.syslog(syslog.LOG_INFO, f"Service received signal ({signum}). Initiating graceful teardown sequence.")
    keep_running = False
    
    # The Self-Pipe Trick: Write an atomic NOP byte to unblock the kernel poll immediately
    try:
        os.write(pipe_write_fd, b"\x00")
    except OSError as e:
        syslog.syslog(syslog.LOG_ERR, f"Exception writing pipe (errno {e.errno}): {e.strerror}")

# Bind the standard POSIX system signals to our optimized handler
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def load_uci_configuration():
    # Extracts target operational parameters from OpenWrt /etc/config/sysdiagnostic structures
    import uci
    
    try:
        # C++ Style: Create the instance directly from the Uci class constructor
        ctx = uci.Uci()
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"Failed to instantiate UCI interface context: {str(e)}")
        return
    
    try:
        # Parse DNS test section attributes
        dns_h = ctx.get("sysdiagnostic", "dns_test", "host")
        if dns_h: config["dns_host"] = dns_h
        
        # Parse Latency test section attributes
        lat_h = ctx.get("sysdiagnostic", "latency_test", "host")
        if lat_h: config["latency_host"] = lat_h
        
        lat_p = ctx.get("sysdiagnostic", "latency_test", "port")
        if lat_p: config["latency_port"] = int(lat_p)
        
        # Parse REST upstream API parameters
        api_u = ctx.get("sysdiagnostic", "api", "url")
        if api_u: config["api_url"] = api_u
        
        api_t = ctx.get("sysdiagnostic", "api", "token")
        if api_t: config["api_token"] = api_t
        
        # Parse timing schedules and queue limits
        interval = ctx.get("sysdiagnostic", "schedule", "check_interval")
        if interval: config["check_interval"] = int(interval)
        
        max_q = ctx.get("sysdiagnostic", "schedule", "max_queued_reports")
        if max_q: config["max_queued_reports"] = int(max_q)
        
    except uci.UciException:
        # Maintain defaults if the configuration file is missing or contains errors
        syslog.syslog(syslog.LOG_WARNING, "UCI file missing or invalid. Operating with safe default properties.")
    except ValueError:
        syslog.syslog(syslog.LOG_ERR, "Type casting failed on numeric option parsing. Check interval or port values.")

def update_schedule_configuration(option_name, value_str):
    # Updates a specific option inside the 'schedule' section via UCI.
    import uci
    
    try:
        # 1. Instantiate the native OpenWrt UCI context
        ctx = uci.Uci()
        
        # 2. Modify the target property within volatile process cache layout
        ctx.set("sysdiagnostic", "schedule", option_name, value_str)
        
        # 3. Trigger a synchronous atomic commit down to the physical Flash ROM disk layout
        ctx.commit("sysdiagnostic")
        
        return True, f"Option '{option_name}' successfully committed to disk storage layout."
    except Exception as e:
        # Intercept and return the storage fault details to be printed into logread
        return False, f"UCI transaction failure on option '{option_name}': {str(e)}"

def check_api_response(response):
    """Parses and validates the upstream HTTP connection payload response.
    
    Processes dynamic command actions like 'set_interval' and updates both
    active running memory configuration and permanent physical storage.
    Returns a tuple (success_bool, status_reason_str).
    """
    # 1. Edge boundary check: Validate HTTP response code ranges
    if not (200 <= response.status < 300):
        return False, f"HTTP Server Error: {response.status}"
        
    try:
        # 2. Extract and decode the raw streaming bytes from network socket
        response_body = response.read().decode("utf-8").strip()
        
        # Scenario check: If the API response body is empty, skip and assume OK
        if not response_body:
            return True, f"HTTP {response.status} (Empty payload body response)"
            
    except Exception as e:
        # Network streaming read or decoding crash boundary
        syslog.syslog(syslog.LOG_ERR, f"(Failed to read socket stream: {str(e)})")
        return True, f"HTTP {response.status} (Failed to read socket stream: {str(e)})"

    # 3. Defensive programming: Attempt to safely parse JSON context
    try:
        api_json = json.loads(response_body)
    except ValueError as e:
        # JSON validation fault: Write to syslog but return True to clear local flash queue
        syslog.syslog(
            syslog.LOG_ERR, 
            f"Failed to parse incoming API JSON payload response: {str(e)}. Raw frame: {response_body}"
        )
        return True, f"HTTP {response.status} (Malformed JSON payload skipped)"

    # 4. Target actions extraction (C2 Command and Control check)
    if isinstance(api_json, dict) and "actions" in api_json:
        actions = api_json.get("actions", [])
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, dict) and action.get("type") == "set_interval":
                    try:
                        new_interval = int(action.get("value", 0))
                        
                        if new_interval > 0:
                            # Optimization boundary: Verify if the interval value is different
                            if new_interval != config["check_interval"]:
                                syslog.syslog(
                                    syslog.LOG_INFO, 
                                    f"Dynamic update frame caught. Recalibrating interval from {config['check_interval']}s to {new_interval}s"
                               )
                                
                                # First step: Update the operational variable in volatile memory RAM
                                config["check_interval"] = new_interval
                                
                                # Second step: Commit configuration into permanent storage layout using our general method
                                storage_ok, storage_msg = update_schedule_configuration("check_interval", str(new_interval))
                                
                                if not storage_ok:
                                    # Flash ROM write failed, log evidence but keep True execution flow
                                    syslog.syslog(syslog.LOG_ERR, f"Storage write error trace: {storage_msg}")
                            else:
                                # Values match, omit writing transactions to prevent flash layout wear
                                pass
                                
                    except (ValueError, TypeError):
                        syslog.syslog(syslog.LOG_ERR, "Command execution payload action 'set_interval' contained a corrupt non-numeric value frame.")

    return True, f"HTTP {response.status}"

def send_to_api(report_data):
    # Transmits the diagnostic data payload via HTTP/HTTPS POST using the native urllib module
    if not config["api_url"]:
        return False, "API URL not configured"

    # Convert the Python dictionary structure into raw encoded JSON bytes
    payload = json.dumps(report_data).encode("utf-8")
    
    # Establish standard headers for transaction authorization and tracking
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"SysDiagnosticAgent/{report_data['agent_version']}"
    }
    if config["api_token"]:
        headers["Authorization"] = f"Bearer {config['api_token']}"

    # Build the native HTTP request wrapper descriptor
    req = urllib.request.Request(config["api_url"], data=payload, headers=headers, method="POST")
    
    try:
        # Open network socket with a strict 5.0 seconds connection boundary
        with urllib.request.urlopen(req, timeout=5.0) as response:
            return check_api_response(response)
    except urllib.error.HTTPError as e:
        return False, f"HTTP Error Code {e.code}"
    except urllib.error.URLError as e:
        return False, f"Network Connection Failed: {e.reason}"
    except Exception as e:
        return False, f"Unexpected Socket Error: {str(e)}"

def save_to_queue(report_data):
    # Buffers telemetry payloads down to volatile storage when upstream targets are unreachable
    if not os.path.exists(QUEUE_DIR):
        try:
            os.makedirs(QUEUE_DIR)
        except OSError as e:
            syslog.syslog(syslog.LOG_ERR, f"Critical: Unable to create buffer space path at {QUEUE_DIR} (errno {e.errno}): {e.strerror}")
            return

    try:
        # 1. Enforce physical queue capacity boundaries to protect memory space ceilings
        files = [os.path.join(QUEUE_DIR, f) for f in os.listdir(QUEUE_DIR) if f.endswith(".json")]
        if len(files) >= config["max_queued_reports"]:
            # Sort system items using standard modification timestamps
            files.sort(key=os.path.getmtime)
            # Remove the oldest trace on the timeline to maintain balance
            oldest_file = files[0]
            os.remove(oldest_file)
            syslog.syslog(syslog.LOG_WARNING, f"Queue ceiling reached. Purged oldest historical report item: {os.path.basename(oldest_file)}")

        # 2. Persist JSON data directly to local disk arrays
        filename = f"report_{report_data['generated_at'].replace(':', '')}.json"
        filepath = os.path.join(QUEUE_DIR, filename)
        
        with open(filepath, "w") as f:
            json.dump(report_data, f)
        syslog.syslog(syslog.LOG_INFO, f"Report successfully buffered locally to offline queue space: {filename}")
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"Failed to execute volatile storage transaction: {str(e)}")

def process_pending_queue():
    # Flushes historical entries sequentially to preserve timeline analytics upstream
    if not config["api_url"] or not os.path.exists(QUEUE_DIR):
        return

    try:
        files = [os.path.join(QUEUE_DIR, f) for f in os.listdir(QUEUE_DIR) if f.endswith(".json")]
        if not files:
            return

        # Sort the directory array from oldest trace up to the newest record
        files.sort(key=os.path.getmtime)
        syslog.syslog(syslog.LOG_INFO, f"Detected {len(files)} unsent diagnostic items in queue. Initiating upstream sync.")

        for filepath in files:
            filename = os.path.basename(filepath)
            try:
                with open(filepath, "r") as f:
                    stored_report = json.load(f)
                
                # Attempt to offload cached state payload
                success, reason = send_to_api(stored_report)
                if success:
                    os.remove(filepath)
                    syslog.syslog(syslog.LOG_INFO, f"trying to send file {filename} with result OK")
                else:
                    # Freeze queue transmission to preserve chronology during network failure states
                    syslog.syslog(syslog.LOG_WARNING, f"trying to send file {filename} with result FAIL : {reason}. Halting queue processing.")
                    break
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR, f"Error processing queued item {filename}: {str(e)}")
                break
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"Error traversing queue filesystem directory: {str(e)}")

if __name__ == "__main__":
    # Main Daemon Execution Block
    syslog.syslog(syslog.LOG_INFO, "Initializing system diagnostic daemon service.")
    
    # Process configuration profile inputs
    load_uci_configuration()
    
    # Class instantiation mapped through explicit module tracking namespace
    collector = sysdiagnostic_collector.SysDiagnosticCollector()
    
    # Kernel driven operational event loop boundary
    while keep_running:
        syslog.syslog(syslog.LOG_INFO, "Executing diagnostic daemon")
        
        # 1. Sync step: try to flush queued history files first
        process_pending_queue()
        
        # 2. Capture metrics using the strict unifed Pattern Result
        diagnostic_res = collector.generate_diagnostic(config)
        
        # Extract the telemetry payload structure (handles partial maps on False)
        current_report = diagnostic_res.data
        
        # If orchestration failed internally, write down a high-visibility permanent syslog trace
        if not diagnostic_res.success:
            syslog.syslog(
                syslog.LOG_ERR, 
                f"Critical Error during report orchestration [{diagnostic_res.error_code}]: {diagnostic_res.error_msg}"
            )
        
        # 3. Stream semantic operational summary down into local syslog infrastructure
        health_status = current_report["health"]["status"]
        syslog.syslog(syslog.LOG_INFO, f"Estado del router: {health_status}")
        
        # 4. Process routing logic into upstream endpoints or down to local storage buckets
        if config["api_url"]:
            api_success, api_reason = send_to_api(current_report)
            syslog.syslog(syslog.LOG_INFO, f"Resultado del envío API: {api_reason}")
            if not api_success:
                save_to_queue(current_report)
        else:
            save_to_queue(current_report)
            
        # 5. Core Optimized Lock: Yield process control back to the Kernel using the global poll tracker
        if keep_running:
            timeout_ms = config["check_interval"] * 1000
            events = poll_obj.poll(timeout_ms)
            if events:
                try:
                    os.read(pipe_read_fd, 1)
                except OSError as e:
                    syslog.syslog(syslog.LOG_ERR, f"Exception reading pipe (errno {e.errno}): {e.strerror}")

    # 6. Safe System Resource Release Sequence on clean daemon exit
    try:
        os.close(pipe_read_fd)
        os.close(pipe_write_fd)
    except OSError as e:
        syslog.syslog(syslog.LOG_ERR, f"Exception closing pipe (errno {e.errno}): {e.strerror}")

    syslog.syslog(syslog.LOG_INFO, "Service daemon shutdown complete. Exiting process safely.")
    sys.exit(0)
