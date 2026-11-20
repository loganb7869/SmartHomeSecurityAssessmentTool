# server.py - the only file you need to run. It:
#     - shows the dashboard web page (dashboard.html)
#     - runs scanner.py in the background when you press "Scan network"
#     - saves every scan + a plain-English report to Documents/Device Scanner
#     - listens for device names in the background (DHCP.py)
#
# How to run it:
#     python3 server.py            Mac/Linux (it asks for your password because scanning needs admin)
#     python server.py             Windows (open the terminal as Administrator first)
#     python3 server.py 8080       same thing but on a different port
#
# Then open the address it prints, usually http://127.0.0.1:8000
#
# The web page talks to us with these "API" calls. Every /api call has to include
# the header "X-Scanner: 1" (explained in api_ok() below):
#     GET  /api/health                is the server running? are we admin? what network are we on?
#     POST /api/scan/start {cidr}     start a scan (cidr can be a network OR a single IP)
#     GET  /api/scan/status           how far along the scan is, and the results when it's done
#     POST /api/scan/cancel           stop the scan
#     POST /api/scan/save {id|scan}   "Save a copy": save a scan into our two folders
#     GET  /api/history               list of every saved scan
#     GET  /api/history/<id>          one saved scan
#     GET  /api/names                 the names you gave your devices
#     POST /api/names {key, name}     rename a device (empty name = remove the name)
#     GET  /report/<id>               the plain-English report for a scan

# reading/writing JSON
import json
# environment variables, permissions, killing processes
import os
# checking scan ids look right
import re
# moving old files, finding sudo
import shutil
# for stopping the scanner with SIGTERM
import signal
# to run scanner.py as its own process
import subprocess
# printing, exiting, command line arguments
import sys
# the scan runs in the background while the page keeps working
import threading
# timing the scan
import time
# Python's built-in web server
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
# nicer file paths
from pathlib import Path
# splits a URL into its parts
from urllib.parse import urlparse

# the folder this file is in
HERE = Path(__file__).resolve().parent
# so we can import our other files from this folder
sys.path.insert(0, str(HERE))
# noqa: E402            # makes the safety score and findings
import security
# noqa: E402              # saves scans and writes the plain-English report
import report
# noqa: E402             # we only use its network check here, the real scan runs as its own process
import scanner
# noqa: E402           # to find this computer's IP (for the default network)
import discovery

# the file we run to do a scan
SCANNER = HERE / "scanner.py"
# older versions saved scans here, we move them on start-up
OLD_HISTORY_DIR = HERE / "scans"
# the names you give devices on the dashboard
NAMES_FILE = HERE / "names.json"
# 127.0.0.1 means only this computer can open the page, not others on the Wi-Fi
HOST, PORT = "127.0.0.1", 8000
# stop a scan after 15 minutes (900 seconds) no matter what
SCAN_TIMEOUT = 900
# scanner.py starts its progress lines with this (has to match scanner.py)
PROGRESS_TAG = "@@PROGRESS "
SERVED_FILES = {"/dashboard.html", "/styles.css", "/labels.js", "/render.js", "/dashboard.js",
                # the ONLY files the browser is allowed to get (so it can't download our code or scans)
                "/favicon.ico"}
# what a scan id has to look like, e.g. scan-20261118-154841
HISTORY_ID = re.compile(r"^scan-\d{8}-\d{6}$")
# normal requests are tiny, so we refuse anything bigger than 10 KB...
MAX_BODY = 10_000
# ...except "Save a copy" of an opened file, which sends the whole scan (5 MB max)
MAX_SAVE_BODY = 5_000_000


#
# Function: is_admin - True if we're running with sudo (Mac/Linux) or as Administrator (Windows).
# Input argument: none
# Output argument: none
# Return: True if we're running as admin
# Dependencies: ctypes; os - geteuid
#
def is_admin():
    try:
        # Mac/Linux
        if hasattr(os, "geteuid"):
            # 0 = root
            return os.geteuid() == 0
        # Windows
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Small file helpers (names.json and the saved scans)
# ---------------------------------------------------------------------------

#
# Function: write_json - Save data as JSON safely (temp file then swap, so a crash can't leave half a file).
# Input argument: path - the file to write
#                 data - what to save
# Output argument: none
# Return: none
# Dependencies: json - dump; os - replace; pathlib - Path; report.py - give_to_user
#
def write_json(path, data):
    path = Path(path)
    # make the folder if needed
    path.parent.mkdir(parents=True, exist_ok=True)
    # make sure the real user owns it, not root
    report.give_to_user(path.parent)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    report.give_to_user(path)


#
# Function: read_json - Load a JSON file, or give back `default` if it's missing or broken.
# Input argument: path - the file to read
#                 default - what to give back if it isn't a number
# Output argument: none
# Return: what was in the file, or `default`
# Dependencies: json - JSONDecodeError, load
#
def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


#
# Function: load_names - The names the user gave their devices, as {device id: name}.
# Input argument: none
# Output argument: none
# Return: {device id: name}
# Dependencies: read_json
#
def load_names():
    data = read_json(NAMES_FILE, {})
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


#
# Function: history_dir - Where the saved scans are (Documents/Device Scanner/scans).
# Input argument: none
# Output argument: none
# Return: the scans folder (a Path)
# Dependencies: report.py - scans_dir
#
def history_dir():
    return report.scans_dir()


#
# Function: history_list - A short summary of every saved scan, newest first, for the dashboard's dropdown.
# Input argument: none
# Output argument: none
# Return: a list of {id, scanned_at, network, devices, score, report_file}, newest first
# Dependencies: history_dir, read_json
#
def history_list():
    items = []
    # file names sort by date, reverse = newest first
    for f in sorted(history_dir().glob("scan-*.json"), reverse=True):
        data = read_json(f)
        # skip broken files
        if not isinstance(data, dict):
            continue
        rep_ = data.get("report") or {}
        # file name without .json
        items.append({"id": f.stem,
                      "scanned_at": data.get("scanned_at"),
                      "network": data.get("network"),
                      "devices": len(data.get("devices") or []),
                      "score": rep_.get("score"),
                      "report_file": data.get("report_file")})
    return items


#
# Function: latest_scan_of - The most recent saved scan of this network (to compare with), or None.
# Input argument: network - the network to scan, e.g. 192.168.1.0/24
# Output argument: none
# Return: the last scan of this network, or None
# Dependencies: history_dir, history_list, read_json
#
def latest_scan_of(network):
    # already newest first
    for item in history_list():
        if item["network"] == network:
            return read_json(history_dir() / f"{item['id']}.json")
    return None


#
# Function: move_old_history - Older versions saved scans next to the code. Move them into Documents/Device Scanner.
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: report.py - give_to_user, make_dirs; shutil - move; history_dir
#
def move_old_history():
    # nothing to move
    if not OLD_HISTORY_DIR.is_dir():
        return
    try:
        report.make_dirs()
        for f in OLD_HISTORY_DIR.glob("scan-*.json"):
            target = history_dir() / f.name
            # don't overwrite anything
            if not target.exists():
                shutil.move(str(f), target)
                report.give_to_user(target)
        # delete the old folder if it's empty now
        if not any(OLD_HISTORY_DIR.iterdir()):
            OLD_HISTORY_DIR.rmdir()
    except OSError as e:
        print(f"Note: couldn't move old scans from {OLD_HISTORY_DIR} ({e})")


#
# Function: suggested_network - The network this computer is on, e.g. "192.168.0.0/24", to fill in the Network box. None if unknown.
# Input argument: none
# Output argument: none
# Return: the network as text, e.g. "192.168.0.0/24", or None
# Dependencies: discovery.py - own_ips; scanner.py - ScanError, check_network
#
def suggested_network():
    # this computer's IP addresses
    for ip in sorted(discovery.own_ips()):
        try:
            # turns 192.168.0.23 into 192.168.0.0/24 (and rejects public IPs)
            net = scanner.check_network(ip)
            # skip 127.0.0.1
            if not net.is_loopback:
                return str(net)
        # not a home network address, try the next one
        except scanner.ScanError:
            continue
    return None


# ---------------------------------------------------------------------------
# The background scan (only one can run at a time)
# ---------------------------------------------------------------------------

#
# Class: ScanJob - keeps track of the scan that's running: its progress, result, or error
#
class ScanJob:

    #
    # Function: __init__
    # Input argument: none
    # Output argument: none
    # Return: none
    # Dependencies: threading - Lock
    #
    def __init__(self):
        # stops two threads changing things at the same time
        self.lock = threading.Lock()
        # the running scanner.py process
        self.proc = None
        self.reset()

    #
    # Function: reset - Clear everything for a new scan.
    # Input argument: none
    # Output argument: self - every value of the scan job goes back to the start
    # Return: none
    # Dependencies: none
    #
    def reset(self):
        # idle, running, done, error or cancelled
        self.state = "idle"
        # progress bar number and message
        self.pct, self.text = 0, ""
        self.network = None
        self.started = self.finished = None
        # the scan results when it's done
        self.result = None
        self.error = self.details = None
        self.cancel_requested = False
        # the last few lines scanner.py printed (shown if something breaks)
        self.log_tail = []

    #
    # Function: snapshot - A copy of where the scan is at, for /api/scan/status.
    # Input argument: none
    # Output argument: none
    # Return: {state, pct, text, network, elapsed} plus the result or error if it's finished
    # Dependencies: time - time
    #
    def snapshot(self):
        with self.lock:
            out = {"state": self.state, "pct": self.pct, "text": self.text, "network": self.network,
                   "elapsed": round((self.finished or time.time()) - self.started, 1) if self.started else 0}
            if self.state == "done":
                out["result"] = self.result
            if self.state in ("error", "cancelled"):
                out["error"], out["details"] = self.error, self.details
            return out

    #
    # Function: start - Start a scan in a background thread. Returns False if one is already running.
    # Input argument: network - the network to scan, e.g. 192.168.1.0/24
    # Output argument: self - the job is marked as running
    # Return: True if the scan started, False if one was already running
    # Dependencies: threading - Thread; time - time
    #
    def start(self, network):
        with self.lock:
            if self.state == "running":
                return False
            self.reset()
            self.state, self.network, self.started = "running", network, time.time()
            self.text = "Starting the scan"
        # daemon = dies with the server
        threading.Thread(target=self._run, args=(network,), daemon=True).start()
        return True

    #
    # Function: cancel - Stop the scan (the Stop button). Returns False if nothing was running.
    # Input argument: none
    # Output argument: self - the job is marked as cancelled
    # Return: True if there was a scan to stop
    # Dependencies: os - killpg; signal - SIGTERM
    #
    def cancel(self):
        with self.lock:
            if self.state != "running":
                return False
            self.cancel_requested = True
            proc = self.proc
        # poll() is None means it's still running
        if proc and proc.poll() is None:
            try:
                # Mac/Linux: stop scanner.py AND the nmap programs it started
                if hasattr(os, "killpg"):
                    os.killpg(proc.pid, signal.SIGTERM)
                # Windows
                else:
                    proc.terminate()
            # it already finished
            except (ProcessLookupError, PermissionError, OSError):
                pass
        return True

    #
    # Function: _finish - Save how the scan ended.
    # Input argument: state - how the scan ended: done, error or cancelled
    #                 result - the scan results (a dictionary)
    #                 error - the error message, if there was one
    #                 details - extra details about the error
    # Output argument: self - the job's state, result and error are saved
    # Return: none
    # Dependencies: time - time
    #
    def _finish(self, state, result=None, error=None, details=None):
        with self.lock:
            self.state, self.result, self.error, self.details = state, result, error, details
            self.finished = time.time()
            self.proc = None
            if state == "done":
                self.pct, self.text = 100, "Done"

    #
    # Function: _read_stderr - Read scanner.py's messages as they come in. Progress lines move the bar, the rest go to the terminal.
    # Input argument: stream - scanner.py's error output, read line by line
    # Output argument: self - the progress number and message are updated
    # Return: none
    # Dependencies: json - loads; sys - stderr
    #
    def _read_stderr(self, stream):
        # keeps going until scanner.py closes stderr
        for line in iter(stream.readline, ""):
            line = line.rstrip("\n")
            # e.g. @@PROGRESS {"pct": 40, "text": "..."}
            if line.startswith(PROGRESS_TAG):
                try:
                    p = json.loads(line[len(PROGRESS_TAG):])
                    with self.lock:
                        # never let the bar go backwards
                        self.pct = max(self.pct, int(p.get("pct", 0)))
                        self.text = str(p.get("text", ""))[:200]
                except (ValueError, TypeError):
                    pass
                continue
            # a normal message: show it and remember it
            if line.strip():
                print("scanner.py: " + line, file=sys.stderr)
                # keep only the last 20 lines
                self.log_tail = (self.log_tail + [line])[-20:]

    #
    # Function: _run - The actual scan (runs in the background thread).
    # Input argument: network - the network to scan, e.g. 192.168.1.0/24
    # Output argument: self - the job ends up done, error or cancelled
    # Return: none
    # Dependencies: json - JSONDecodeError, loads; report.py - data_dir, save_scan; security.py - assess; subprocess - PIPE, Popen; sys - executable, stderr; threading - Event, Thread, Timer; latest_scan_of, load_names
    #
    def _run(self, network):
        print(f"Scanning {network} ...", file=sys.stderr, flush=True)
        try:
            # start_new_session puts scanner.py in its own group so cancel() can stop everything it started
            kwargs = {"start_new_session": True} if hasattr(os, "killpg") else {}
            proc = subprocess.Popen([sys.executable, str(SCANNER), network],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, cwd=str(HERE), **kwargs)
        except OSError as e:
            return self._finish("error", error=f"Couldn't start scanner.py: {e}")
        with self.lock:
            self.proc = proc
        reader = threading.Thread(target=self._read_stderr, args=(proc.stderr,), daemon=True)
        # read progress while we wait
        reader.start()

        # stop the scan if it runs way too long
        timed_out = threading.Event()
        #
        # Function: too_long
        # Input argument: none
        # Output argument: timed_out (from _run) - gets set, and the scan is cancelled
        # Return: none
        # Dependencies: none
        #
        def too_long():
            timed_out.set()
            self.cancel()
        timer = threading.Timer(SCAN_TIMEOUT, too_long)
        timer.daemon = True
        timer.start()
        try:
            # wait for the JSON (stderr is read by the other thread)
            out = proc.stdout.read()
            proc.wait()
        finally:
            # finished in time, so turn off the timer
            timer.cancel()
        reader.join(timeout=2)
        if timed_out.is_set():
            return self._finish("error", error=f"The scan took longer than {SCAN_TIMEOUT // 60} "
                                               "minutes and was stopped. Try a smaller network.")
        if self.cancel_requested:
            return self._finish("cancelled", error="Scan stopped.")

        # what scanner.py printed (should be JSON)
        printed = (out or "").strip()
        try:
            data = json.loads(printed) if printed else None
        except json.JSONDecodeError:
            data = None
        # last few messages, in case something went wrong
        details = "\n".join(self.log_tail[-6:])
        # scanner.py explained the problem itself
        if isinstance(data, dict) and data.get("error"):
            return self._finish("error", error=data["error"], details=details)
        # it crashed or printed garbage
        if proc.returncode != 0 or not isinstance(data, dict):
            hint = ("scanner.py crashed" if proc.returncode != 0 else
                    "scanner.py printed nothing" if not printed else
                    "scanner.py printed something that isn't a device list")
            return self._finish("error", error=hint, details=(printed[-800:] + "\n" + details).strip())

        # compare with the last scan, work out the score, and save everything
        try:
            security.assess(data, latest_scan_of(data.get("network")), load_names())
        except Exception as e:
            data.setdefault("warnings", []).append(f"couldn't build the security report ({e})")
        try:
            json_path, report_path = report.save_scan(data, load_names())
            print(f"Saved {json_path}" + (f"\n  and {report_path}" if report_path else ""), file=sys.stderr)
            if not report_path:
                data.setdefault("warnings", []).append("couldn't write the plain-English report")
            # the page shows where it was saved
            data["saved_to"] = str(report.data_dir())
        except OSError as e:
            data.setdefault("warnings", []).append(f"couldn't save this scan to your computer ({e})")
        self._finish("done", result=data)


# the one scan job the whole server shares
JOB = ScanJob()


# ---------------------------------------------------------------------------
# The web server part
# ---------------------------------------------------------------------------

#
# Class: Handler - handles every request the browser makes.
# Python's web server calls do_GET or do_POST for every request
#
class Handler(SimpleHTTPRequestHandler):

    #
    # Function: __init__
    # Input argument: *args
    # Output argument: none
    # Return: none
    # Dependencies: none
    #
    def __init__(self, *args, **kwargs):
        # serve files from this folder
        super().__init__(*args, directory=str(HERE), **kwargs)

    # --- safety checks ---
    #
    # Function: host_ok - Only answer requests that are addressed to us.
    # Input argument: none
    # Output argument: none
    # Return: True if the request was addressed to us
    # Dependencies: none
    #
    def host_ok(self):
        # This blocks a trick called "DNS rebinding", where a website makes your
        # browser think its address is 127.0.0.1 so it can talk to local servers.
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    #
    # Function: api_ok - Every API call has to send "X-Scanner: 1".
    # Input argument: none
    # Output argument: none
    # Return: True if the request has the X-Scanner header
    # Dependencies: none
    #
    def api_ok(self):
        # Browsers don't let other websites add custom headers like this one, so a
        # random site you visit can't start scans or rename your devices (CSRF).
        return self.headers.get("X-Scanner") == "1"

    #
    # Function: read_body - Read the JSON the page sent with a POST. Gives {} if it's missing, too big, or broken.
    # Input argument: limit - the most bytes we'll accept
    # Output argument: none
    # Return: the JSON as a dictionary, or {}
    # Dependencies: json - loads
    #
    def read_body(self, limit=MAX_BODY):
        try:
            # how many bytes it says it's sending
            n = int(self.headers.get("Content-Length", 0))
            if not 0 < n <= limit:
                return {}
            data = json.loads(self.rfile.read(n))
            return data if isinstance(data, dict) else {}
        except (ValueError, OSError):
            return {}

    # --- GET requests (loading pages, reading data) ---
    #
    # Function: do_GET
    # Input argument: none
    # Output argument: none
    # Return: none (sends a page, a file or JSON back to the browser)
    # Dependencies: urllib.parse - urlparse; history_dir, history_list, is_admin, load_names, read_json, suggested_network
    #
    def do_GET(self):
        if not self.host_ok():
            return self.send_error(403, "Forbidden")
        # the part of the URL without ?query
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            if not self.api_ok():
                return self.send_json(403, {"error": "Missing X-Scanner header"})
            # the page checks this when it loads
            if path == "/api/health":
                return self.send_json(200, {"ok": True, "admin": is_admin(),
                                            "scanning": JOB.state == "running",
                                            "network": suggested_network()})
            # asked every second during a scan
            if path == "/api/scan/status":
                return self.send_json(200, JOB.snapshot())
            if path == "/api/history":
                return self.send_json(200, history_list())
            # one scan, e.g. /api/history/scan-20261118-154841
            if path.startswith("/api/history/"):
                hid = path.rsplit("/", 1)[-1]
                # check the id first so nobody can ask for ../../something
                data = read_json(history_dir() / f"{hid}.json") if HISTORY_ID.match(hid) else None
                return self.send_json(200, data) if data else self.send_json(404, {"error": "No such scan"})
            if path == "/api/names":
                return self.send_json(200, load_names())
            return self.send_json(404, {"error": "Unknown API call"})
        # the plain-English report, opened in a new tab
        if path.startswith("/report/"):
            return self.send_report(path.rsplit("/", 1)[-1])
        # the home page is the dashboard
        if path == "/":
            self.path = "/dashboard.html"
        # anything not on our list gets a 404
        elif path not in SERVED_FILES:
            return self.send_error(404, "Not found")
        # let Python's built-in server send the file
        return super().do_GET()

    # --- POST requests (doing things) ---
    #
    # Function: do_POST
    # Input argument: none
    # Output argument: none
    # Return: none (sends JSON back to the browser)
    # Dependencies: urllib.parse - urlparse; load_names, write_json
    #
    def do_POST(self):
        if not self.host_ok():
            return self.send_error(403, "Forbidden")
        if not self.api_ok():
            return self.send_json(403, {"error": "Missing X-Scanner header"})
        path = urlparse(self.path).path
        # "Save a copy" can send a whole scan, so it gets a bigger limit
        if path == "/api/scan/save":
            return self.save_copy(self.read_body(MAX_SAVE_BODY))
        body = self.read_body()
        if path == "/api/scan/start":
            return self.start_scan(str(body.get("cidr", "")))
        if path == "/api/scan/cancel":
            return self.send_json(200, {"cancelled": JOB.cancel()})
        # rename a device
        if path == "/api/names":
            # limit the lengths
            key, name = str(body.get("key", ""))[:64], str(body.get("name", "")).strip()[:60]
            if not key:
                return self.send_json(400, {"error": "Missing device key"})
            names = load_names()
            if name:
                # set the name
                names[key] = name
            else:
                # empty name = remove it
                names.pop(key, None)
            try:
                write_json(NAMES_FILE, names)
            except OSError as e:
                return self.send_json(500, {"error": f"Couldn't save the name ({e})"})
            return self.send_json(200, names)
        return self.send_json(404, {"error": "Unknown API call"})

    #
    # Function: start_scan - Check what the user typed and start the scan.
    # Input argument: cidr - the network or single IP the user typed
    # Output argument: none
    # Return: none (sends JSON back to the browser)
    # Dependencies: scanner.py - ScanError, check_network
    #
    def start_scan(self, cidr):
        try:
            # accepts a network OR a single IP (we scan the network it's on)
            net = scanner.check_network(cidr)
        except scanner.ScanError as e:
            return self.send_json(400, {"error": str(e)})
        if not JOB.start(str(net)):
            return self.send_json(409, {"error": "A scan is already running."})
        return self.send_json(202, {"started": True, "network": str(net),
                                    # tells the page we picked the network from an IP
                                    "from_ip": "/" not in cidr})

    #
    # Function: save_copy - The "Save a copy" button: save the scan into scans/ and reports/ (and nowhere else).
    # Input argument: body - the JSON the page sent
    # Output argument: none
    # Return: none (sends JSON back to the browser)
    # Dependencies: report.py - data_dir, save_copy; security.py - assess; history_dir, load_names, read_json
    #
    def save_copy(self, body):
        data = None
        hid = str(body.get("id") or "")
        # a scan that's already saved: load it from our folder
        if HISTORY_ID.match(hid):
            data = read_json(history_dir() / f"{hid}.json")
        # a scan from a file they opened
        if data is None and isinstance(body.get("scan"), dict):
            data = body["scan"]
            if not isinstance(data.get("devices"), list):
                return self.send_json(400, {"error": "That doesn't look like a scan."})
            # very old scans have no safety report yet, so make one
            if not data.get("report"):
                try:
                    security.assess(data, None, load_names())
                except Exception:
                    pass
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "There's no scan to save."})
        try:
            json_path, report_path, status = report.save_copy(data, load_names())
        except OSError as e:
            return self.send_json(500, {"error": f"Couldn't save it ({e})"})
        return self.send_json(200, {"id": data.get("id"), "status": status, "folder": str(report.data_dir()),
                                    "json": json_path.name, "report": report_path.name if report_path else None})

    #
    # Function: send_report - Send the plain-English report for a scan.
    # Input argument: hid - the scan's id, e.g. scan-20261118-154841
    # Output argument: none
    # Return: none (sends the report page back to the browser)
    # Dependencies: report.py - build_report, reports_dir; history_dir, load_names, read_json
    #
    def send_report(self, hid):
        data = read_json(history_dir() / f"{hid}.json") if HISTORY_ID.match(hid) else None
        name = (data or {}).get("report_file") or ""
        path = report.reports_dir() / name
        # no saved report (or a weird name)
        if not name or "/" in name or "\\" in name or not path.is_file():
            if not isinstance(data, dict):
                return self.send_error(404, "No such report")
            # make one on the spot
            body = report.build_report(data, load_names()).encode()
        else:
            body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --- small stuff ---
    #
    # Function: end_headers - Extra headers on every response.
    # Input argument: none
    # Output argument: none (adds headers to the response)
    # Return: none
    # Dependencies: none
    #
    def end_headers(self):
        # never show an old copy
        self.send_header("Cache-Control", "no-cache" if not self.path.startswith("/api/") else "no-store")
        # browser must trust our file types
        self.send_header("X-Content-Type-Options", "nosniff")
        # don't leak our address to other sites
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    #
    # Function: log_message - Keep the terminal readable: don't print the icon requests or the once-a-second status checks.
    # Input argument: fmt - the message format (from Python's web server)
    #                 *args
    # Output argument: none
    # Return: none
    # Dependencies: none
    #
    def log_message(self, fmt, *args):
        if "icon" not in self.path and "/api/scan/status" not in self.path:
            super().log_message(fmt, *args)

    #
    # Function: send_json - Send a JSON answer back to the page.
    # Input argument: status - the HTTP status code, e.g. 200
    #                 obj - the data to send back as JSON
    # Output argument: none
    # Return: none
    # Dependencies: json - dumps
    #
    def send_json(self, status, obj):
        body = json.dumps(obj).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        # the tab was closed, nothing to do
        except (BrokenPipeError, ConnectionResetError):
            pass


# ---------------------------------------------------------------------------
# Starting up
# ---------------------------------------------------------------------------

#
# Function: become_admin - On Mac/Linux, restart this file with sudo so the scan can see everything.
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: os - environ.get, execvp, pathsep.join; pathlib - Path; shutil - which; site; sys - argv, executable; is_admin
#
def become_admin():
    # sudo asks for your password right in the terminal.
    # To skip it (you'll get less info): NO_SUDO=1 python3 server.py
    # already admin, Windows, or skipped
    if is_admin() or not hasattr(os, "geteuid") or os.environ.get("NO_SUDO"):
        return
    # no sudo on this computer
    if not shutil.which("sudo"):
        return
    print("Admin access is needed to see device makers, operating systems and names.")
    print("Enter your computer password (nothing shows while you type):")
    try:
        # packages installed with "pip install --user" (like python-nmap) live in your home folder,
        # and sudo can't see them by default, so we pass their location along with PYTHONPATH
        import site
        paths = [p for p in [site.getusersitepackages(), os.environ.get("PYTHONPATH")] if p]
        os.execvp("sudo", ["sudo", "env", "PYTHONPATH=" + os.pathsep.join(paths),
                           # replaces this process with the sudo one
                           sys.executable, str(Path(__file__).resolve())] + sys.argv[1:])
    except OSError as e:
        print(f"Couldn't restart with sudo ({e}); carrying on with limited results.")


#
# Function: check_setup - Stop early with a clear message if something we need is missing.
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: nmap; pathlib - Path; scanner.py - NMAP_PATHS; sys - executable, exit; is_admin
#
def check_setup():
    if not SCANNER.exists():
        sys.exit(f"Can't find {SCANNER}")
    for name in ("device_type_guesser.py", "discovery.py", "DHCP.py", "security.py",
                 "vulnerability_identifier.py", "report.py",
                 "dashboard.html", "styles.css", "labels.js", "render.js", "dashboard.js"):
        if not (HERE / name).exists():
            print(f"Warning: {name} is missing from {HERE}")
    try:
        # python-nmap
        import nmap
    except ImportError:
        sys.exit("python-nmap isn't installed for this Python. Run:\n"
                 f"  sudo {sys.executable} -m pip install python-nmap")
    try:
        # fails if the nmap program isn't installed
        nmap.PortScanner(nmap_search_path=scanner.NMAP_PATHS)
    except Exception:
        sys.exit("The nmap program wasn't found. Install it from https://nmap.org/download.html\n"
                 "  Mac: brew install nmap    Linux: sudo apt install nmap")
    if not is_admin():
        print("Note: not running as administrator/root. Scans will work but won't show\n"
              "      device makers or operating systems. For full results use:\n"
              f"      sudo {sys.executable} {Path(__file__).name}")


#
# Function: start - Start the web server on the port we want, or the next free one if it's taken.
# Input argument: port - the port number to try first
# Output argument: none
# Return: (the web server, the port it's using)
# Dependencies: http.server - ThreadingHTTPServer; sys - exit; Handler
#
def start(port):
    # try up to 10 ports
    for p in range(port, port + 10):
        try:
            return ThreadingHTTPServer((HOST, p), Handler), p
        # port already in use (maybe an old server is still running)
        except OSError:
            print(f"Port {p} is busy, trying {p + 1} ...")
    sys.exit(f"Couldn't find a free port between {port} and {port + 9}.")


#
# Function: start_dhcp - Start listening for device names in the background. Everything still works if this fails.
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: DHCP.py; sys - stderr
#
def start_dhcp():
    try:
        import DHCP
    except Exception as e:
        print(f"Device names (DHCP) are off: couldn't load DHCP.py ({e})")
        return
    DHCP.start_background(log=lambda msg: print(msg, file=sys.stderr))


if __name__ == "__main__":
    # ask for the password (restarts this file with sudo)
    become_admin()
    # make sure nmap etc. are installed
    check_setup()
    # move scans from older versions
    move_old_history()
    print(f"Scans and reports are saved in: {report.data_dir()}")
    start_dhcp()
    wanted = PORT
    # a port number was given, e.g. python3 server.py 8080
    if len(sys.argv) > 1:
        try:
            wanted = int(sys.argv[1])
        except ValueError:
            sys.exit("Usage: python3 server.py [port]")
    httpd, port = start(wanted)
    print(f"Dashboard at http://{HOST}:{port}  (Ctrl+C to stop)")
    try:
        # keep answering requests until Ctrl+C
        httpd.serve_forever()
    except KeyboardInterrupt:
        # stop any scan that's running
        JOB.cancel()
        print("\nStopped.")
    finally:
        httpd.server_close()
