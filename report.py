# report.py - saves every scan on the computer and writes a plain-English report for it
#
# Everything goes in the user's Documents folder:
#
#     Documents/Device Scanner/
#         scans/     scan-20261118-154841.json                  the full scan results (JSON)
#         reports/   Network report 2026-11-18 15-48-41.html    the same scan as a short to-do list
#
# server.py calls save_scan() after every scan, and save_copy() when someone
# presses "Save a copy" on the dashboard. The report is a normal HTML file, so you
# can double-click it, it works without internet, and it prints on one or two pages.
#
# If you want the files somewhere else, set the DEVICE_SCANNER_DATA environment variable.

# html.escape() so names with < or & can't break the page
import html
# for writing the scan file
import json
# file paths, permissions, environment variables
import os
# cleaning up company names
import re
# printing warnings to stderr
import sys
# dates and times for file names
import time
# nicer way to work with file paths
from pathlib import Path

# the folder we make inside Documents
APP_FOLDER_NAME = "Device Scanner"


# ---------------------------------------------------------------------------
# Where things get saved
# ---------------------------------------------------------------------------

#
# Function: real_user_home - The home folder of the actual person, even though server.py runs with sudo.
# Input argument: none
# Output argument: none
# Return: the real user's home folder (a Path)
# Dependencies: os - environ.get; pathlib - Path; pwd
#
def real_user_home():
    # When you use sudo, Python thinks you're "root", whose home folder is /var/root.
    # sudo leaves the real username in SUDO_USER, so we use that to find the real home.
    # the person who typed sudo
    user = os.environ.get("SUDO_USER")
    if user and user != "root":
        try:
            # Mac/Linux only: looks up user accounts
            import pwd
            # e.g. /Users/derek
            return Path(pwd.getpwnam(user).pw_dir)
        # Windows, or the user wasn't found
        except (ImportError, KeyError):
            pass
    # not using sudo, so the normal home folder is right
    return Path.home()


#
# Function: data_dir - The main folder: Documents/Device Scanner (or wherever DEVICE_SCANNER_DATA says).
# Input argument: none
# Output argument: none
# Return: the Documents/Device Scanner folder (a Path)
# Dependencies: os - environ.get; pathlib - Path; real_user_home
#
def data_dir():
    # lets us use a test folder
    override = os.environ.get("DEVICE_SCANNER_DATA")
    if override:
        return Path(override).expanduser()
    home = real_user_home()
    docs = home / "Documents"
    # use the home folder if there's no Documents
    return (docs if docs.is_dir() else home) / APP_FOLDER_NAME


#
# Function: scans_dir - Where the JSON files go.
# Input argument: none
# Output argument: none
# Return: the scans folder (a Path)
# Dependencies: data_dir
#
def scans_dir():
    return data_dir() / "scans"


#
# Function: reports_dir - Where the plain-English reports go.
# Input argument: none
# Output argument: none
# Return: the reports folder (a Path)
# Dependencies: data_dir
#
def reports_dir():
    return data_dir() / "reports"


#
# Function: give_to_user - Files made with sudo belong to root, so we hand them back to the real user (otherwise they can't delete them).
# Input argument: path - the file to write
# Output argument: none
# Return: none
# Dependencies: os - chown, environ
#
def give_to_user(path):
    try:
        # the real user's ids, set by sudo
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        # change the owner
        os.chown(path, uid, gid)
    # not using sudo, or on Windows
    except (KeyError, ValueError, OSError, AttributeError):
        pass


#
# Function: make_dirs - Make the folders if they don't exist yet.
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: data_dir, give_to_user, reports_dir, scans_dir
#
def make_dirs():
    for d in (data_dir(), scans_dir(), reports_dir()):
        # parents=True makes Documents/Device Scanner too if needed
        d.mkdir(parents=True, exist_ok=True)
        give_to_user(d)


#
# Function: write_file - Write a file safely: write to a temp file first, then swap it in.
# Input argument: path - the file to write
#                 text - what to write in it
# Output argument: none
# Return: none
# Dependencies: os - replace; pathlib - Path; give_to_user
#
def write_file(path, text):
    # That way if the program crashes halfway, we never end up with half a file.
    path = Path(path)
    # e.g. "scan-....json.tmp"
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    # swap the temp file in (this step is all-or-nothing)
    os.replace(tmp, path)
    give_to_user(path)


#
# Function: _write_both - Save the JSON and the report under the names we picked. Returns (json path, report path or None).
# Input argument: result - the scan results (a dictionary)
#                 names - the names the user gave their devices, {device id: name} (optional)
#                 scan_id - the scan's id, e.g. scan-20261118-154841
#                 report_name - the file name for the report
# Output argument: result - gets "id" and "report_file"
# Return: (path of the JSON file, path of the report or None if the report failed)
# Dependencies: json - dumps; sys - stderr; build_report, reports_dir, scans_dir, write_file
#
def _write_both(result, names, scan_id, report_name):
    # the dashboard uses this to find the scan again
    result["id"] = scan_id
    # so we can open the matching report later
    result["report_file"] = report_name
    json_path = scans_dir() / f"{scan_id}.json"
    # indent=2 makes the JSON readable
    write_file(json_path, json.dumps(result, indent=2))
    report_path = reports_dir() / report_name
    try:
        write_file(report_path, build_report(result, names or {}))
    # if only the report fails, the JSON is still saved
    except Exception as e:
        print(f"Warning: couldn't write the plain-English report ({e})", file=sys.stderr)
        return json_path, None
    return json_path, report_path


#
# Function: save_scan - Save a brand new scan (called automatically after every scan). Returns (json path, report path).
# Input argument: result - the scan results (a dictionary)
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: result - gets "id" and "report_file"
# Return: (path of the JSON file, path of the report or None)
# Dependencies: time - localtime, strftime; _write_both, make_dirs
#
def save_scan(result, names=None):
    make_dirs()
    # the current date and time
    now = time.localtime()
    # e.g. scan-20261118-154841
    scan_id = time.strftime("scan-%Y%m%d-%H%M%S", now)
    report_name = time.strftime("Network report %Y-%m-%d %H-%M-%S.html", now)
    return _write_both(result, names, scan_id, report_name)


#
# Function: save_copy - What the "Save a copy" button does. Only writes into our two folders (nothing goes to Downloads).
# Input argument: result - the scan results (a dictionary)
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: result - gets "id" and "report_file"
# Return: (path of the JSON file, path of the report or None, "updated" or "added")
# Dependencies: re - fullmatch; time - localtime, strftime, strptime; _write_both, make_dirs, scans_dir
#
def save_copy(result, names=None):
    # - If the scan is already in our folder, we just re-save it so the report has
    #   the latest device names you typed in (no duplicate files).
    # - If it came from somewhere else (like a file you opened), we add it to our folders.
    # Returns (json path, report path, "updated" or "added").
    make_dirs()
    scan_id = str(result.get("id") or "")
    if re.fullmatch(r"scan-\d{8}-\d{6}", scan_id) and (scans_dir() / f"{scan_id}.json").exists():
        report_name = result.get("report_file") or f"Network report {scan_id[5:9]}-{scan_id[9:11]}-{scan_id[11:13]} " \
                                                   f"{scan_id[14:16]}-{scan_id[16:18]}-{scan_id[18:20]}.html"
        # don't let a weird file name write somewhere else
        if "/" in report_name or "\\" in report_name:
            report_name = f"Network report {scan_id}.html"
        return (*_write_both(result, names, scan_id, report_name), "updated")
    # not in our folder yet: name it after when it was scanned (or now, if we don't know)
    try:
        when = time.strptime(str(result.get("scanned_at")), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        when = time.localtime()
    scan_id = time.strftime("scan-%Y%m%d-%H%M%S", when)
    report_name = time.strftime("Network report %Y-%m-%d %H-%M-%S.html", when)
    # same scan opened twice = no duplicate
    status = "updated" if (scans_dir() / f"{scan_id}.json").exists() else "added"
    return (*_write_both(result, names, scan_id, report_name), status)


# ---------------------------------------------------------------------------
# The plain-English report
# ---------------------------------------------------------------------------

# how we describe each device type (one, many)
TYPE_WORDS = {"phone": ("Phone or tablet", "phones or tablets"), "computer": ("Computer", "computers"),
              "game_console": ("Game console", "game consoles"), "tv_media": ("TV / streaming", "TVs or streaming devices"),
              "iot_other": ("Smart-home / other", "smart-home or other gadgets"),
              "unknown": ("Couldn't identify", "devices we couldn't identify")}
# the urgency groups in the report: (heading, colour, how many points each one costs)
URGENCY = {"critical": ("Fix now", "#b4321f", 40), "high": ("Fix soon", "#c2410c", 25),
           "medium": ("Worth fixing", "#9a5a0b", 12), "low": ("Minor", "#5d6b7a", 5)}
# the one-line verdict for each score range
BAND_WORDS = {
    "excellent": ("Excellent", "Nothing serious found."),
    "good": ("Good", "Only small things to tidy up."),
    "fair": ("Fair", "A few settings could let someone in."),
    "poor": ("Needs attention", "Risky settings are switched on."),
    "at_risk": ("At risk", "Someone on your Wi-Fi could get into at least one device."),
}


#
# Function: _e - Escape text for HTML. Short name because we use it a lot.
# Input argument: x - any value to show on the page
# Output argument: none
# Return: the text, safe to put in HTML
# Dependencies: html - escape
#
def _e(x):
    return html.escape(str(x if x is not None else ""))


#
# Function: _maker - Shorten company names, e.g. "Intel Corporate" -> "Intel".
# Input argument: v - a company name
# Output argument: none
# Return: the shorter company name
# Dependencies: re - I, sub
#
def _maker(v):
    v = re.sub(r",?\s*(Inc\.?|Ltd\.?|Limited|Corporation|Corporate|Corp\.?|Co\.?)\s*$", "", str(v), flags=re.I)
    return v.strip(" ,")


#
# Function: _device_name - Same naming rules as security.py: your name for it, its own name, its model, then its maker.
# Input argument: d - one device (a dictionary from scanner.py)
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: none
# Return: the best name we have for the device
# Dependencies: _maker
#
def _device_name(d, names):
    key = (d.get("mac") or "").upper() or "ip:" + str(d.get("ip"))
    return (names.get(key) or d.get("hostname") or d.get("mdns_model")
            or ("Your router" if d.get("is_router") else None)
            or (f"{_maker(d['vendor'])} device" if d.get("vendor") else None)
            or f"Unknown device ({d.get('ip')})")


#
# Function: _when - '2026-11-18T15:48:41' -> 'Wed Nov 18, 2026, 3:48 PM'.
# Input argument: ts - a date and time like "2026-11-18T15:48:41"
# Output argument: none
# Return: the date written out, e.g. "Wed Nov 18, 2026, 3:48 PM"
# Dependencies: time - strftime, strptime
#
def _when(ts):
    try:
        t = time.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        # remove leading zeros like "03:48"
        return time.strftime("%a %b %d, %Y, %I:%M %p", t).replace(" 0", " ")
    except (TypeError, ValueError):
        return str(ts or "unknown time")


#
# Function: _ip_key - Sort devices by IP like numbers (.9 before .10).
# Input argument: d - one device
# Output argument: none
# Return: a list of numbers to sort by
# Dependencies: none
#
def _ip_key(d):
    return [int(x) if x.isdigit() else 0 for x in str(d.get("ip", "")).split(".")]


#
# Function: _todo_item - One line on the to-do list. Detailed ones also say why and how; minor ones are a single line.
# Input argument: f - one finding (a problem found by security.py)
#                 detailed - True for the full version, False for one line
# Output argument: none
# Return: the HTML for one to-do item
# Dependencies: _e
#
def _todo_item(f, detailed):
    head = (f'<label class="todo"><input type="checkbox"> <span><b>{_e(f.get("action") or f.get("title"))}</b>'
            f' on <b>{_e(f.get("device"))}</b> <span class="ip">({_e(f.get("ip"))})</span>')
    # minor: just "do this on that device - what's wrong"
    if not detailed:
        return f'<li>{head} <span class="why">{_e(f.get("title"))}.</span></span></label></li>'
    tech = ""
    det = f.get("details") or {}
    # technical bits, hidden by default
    if f.get("tech") or det.get("weaknesses") or det.get("remediations"):
        tech = ("<details><summary>Technical details</summary>"
                + (f"<p>{_e(f.get('tech'))}</p>" if f.get("tech") else "")
                + (f"<p><b>Known weaknesses:</b> {_e('; '.join(det.get('weaknesses', [])))}</p>" if det.get("weaknesses") else "")
                + (f"<p><b>Technical fixes:</b> {_e(' '.join(det.get('remediations', [])))}</p>" if det.get("remediations") else "")
                + "</details>")
    return (f'<li>{head}</span></label>'
            f'<p><b>Problem:</b> {_e(f.get("title"))}. {_e(f.get("why"))}</p>'
            f'<p><b>How:</b> {_e(f.get("fix"))}</p>{tech}</li>')


#
# Function: build_report - Make the whole HTML report for one scan.
# Input argument: result - the scan results (a dictionary)
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: none
# Return: the whole report as an HTML page (text)
# Dependencies: _device_name, _e, _ip_key, _maker, _todo_item, _when
#
def build_report(result, names=None):
    names = names or {}
    devices = sorted([d for d in (result.get("devices") or []) if isinstance(d, dict)], key=_ip_key)
    # the part security.py added
    rep = result.get("report") or {}
    score = rep.get("score")
    band_name, band_text = BAND_WORDS.get(rep.get("band"), ("", ""))
    score_color = {"excellent": "#2f7d4f", "good": "#5f8a3a", "fair": "#9a5a0b"}.get(rep.get("band"), "#b4321f")

    # new-device findings go in their own section, everything else is the to-do list
    is_new_item = lambda f: f.get("title") == "A new device joined your Wi-Fi"
    findings = [f for f in rep.get("findings") or [] if not is_new_item(f)]
    # group by urgency
    by_sev = {s: [f for f in findings if f.get("severity") == s] for s in URGENCY}
    new = [d for d in devices if d.get("is_new")]
    gone = rep.get("gone") or []

    # --- the quick summary at the top ---
    facts = [f"{len(devices)} device{'s' if len(devices) != 1 else ''} found"]
    # e.g. "1 to fix now", "2 worth fixing"
    for sev in URGENCY:
        n = len(by_sev[sev])
        if n:
            facts.append(f"{n} {URGENCY[sev][0].lower() if sev != 'low' else 'minor'}")
    if new and not rep.get("first_scan"):
        facts.append(f"{len(new)} new since last scan")
    # the most important thing to do
    urgent = by_sev["critical"] or by_sev["high"]
    first_step = (f'<p class="first"><b>Do this first:</b> {_e(urgent[0].get("action"))} on '
                  f'{_e(urgent[0].get("device"))} ({_e(urgent[0].get("ip"))}).</p>') if urgent else ""

    # --- the to-do list, grouped by urgency ---
    groups = []
    for sev, (heading, color, pts) in URGENCY.items():
        items = by_sev[sev]
        # skip empty groups
        if not items:
            continue
        # minor items stay one line each
        detailed = sev != "low"
        groups.append(f'<h3><span class="tag" style="background:{color}">{heading}</span> '
                      f'<span class="cost">{len(items)} item{"s" if len(items) != 1 else ""}, -{pts} points each</span></h3>'
                      f'<ul class="todos">{"".join(_todo_item(f, detailed) for f in items)}</ul>')
    todo = "".join(groups) or "<p class='good'>Nothing to fix. Keep your devices updated and scan again now and then.</p>"

    # --- what changed since last time ---
    changes = ""
    if not rep.get("first_scan"):
        rows = "".join(f"<li><b>New:</b> {_e(_device_name(d, names))} ({_e(d.get('ip'))}"
                       f"{', made by ' + _e(_maker(d['vendor'])) if d.get('vendor') else ''}). "
                       f"If you don't recognise it, change your Wi-Fi password.</li>" for d in new)
        rows += "".join(f"<li><b>Gone:</b> {_e(g.get('device'))} ({_e(g.get('ip'))}). Probably just switched off.</li>"
                        for g in gone)
        changes = ("<h2>Changes since your last scan</h2>"
                   + (f"<ul>{rows}</ul>" if rows else "<p>None. Same devices as last time.</p>"))
    else:
        changes = "<h2>Changes since your last scan</h2><p>This is your first scan of this network. Next time we'll list new and missing devices here.</p>"

    # --- table of every device ---
    #
    # Function: problems_cell
    # Input argument: d - one device
    # Output argument: none
    # Return: the HTML for the "To do" column
    # Dependencies: _e
    #
    def problems_cell(d):
        mine = [f for f in findings if f.get("ip") == d.get("ip")]
        if not mine:
            return "None"
        # just the actions, one per line
        return "<br>".join(_e(f.get("action")) for f in mine)

    dev_rows = "".join(f"""
        <tr><td>{_e(_device_name(d, names))}{' <span class="new">new</span>' if d.get('is_new') and not rep.get('first_scan') else ''}</td>
            <td>{_e(TYPE_WORDS.get(d.get('category'), TYPE_WORDS['unknown'])[0])}</td>
            <td>{_e(_maker(d['vendor']) if d.get('vendor') else ('Hidden (private address)' if d.get('randomized_mac') else 'Unknown'))}</td>
            <td class="mono">{_e(d.get('ip'))}</td>
            <td class="num">{_e(d.get('score', 100))}</td>
            <td>{problems_cell(d)}</td></tr>""" for d in devices)

    warnings = result.get("warnings") or []
    warn_html = ("<h2>Notes about this scan</h2><ul>" + "".join(f"<li>{_e(w)}</li>" for w in warnings) + "</ul>") if warnings else ""

    # the whole page. CSS is inside the file so the report works on its own
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network report - {_e(_when(result.get('scanned_at')))}</title>
<style>
  body{{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;color:#26251e;background:#f7f7f4;margin:0;padding:32px 16px}}
  main{{max-width:780px;margin:0 auto;background:#fff;border:1px solid #e4e3dd;border-radius:14px;padding:30px 34px}}
  h1{{font-size:26px;margin:0}} h2{{font-size:18px;margin:28px 0 10px}} h3{{font-size:15px;margin:18px 0 6px}}
  .sub{{color:#7a7972;margin:2px 0 0}}
  .top{{display:flex;gap:18px;align-items:center;background:#f0efea;border-radius:12px;padding:14px 16px;margin:18px 0 10px}}
  .big{{min-width:96px;text-align:center;color:#fff;background:{score_color};border-radius:10px;padding:10px 8px;font-size:34px;font-weight:700;line-height:1}}
  .big small{{display:block;font-size:12px;font-weight:500;margin-top:3px;opacity:.9}}
  .top p{{margin:0}} .facts{{color:#5d5c55;font-size:14px}}
  .first{{background:#fdf0ec;border-left:4px solid #b4321f;padding:8px 12px;border-radius:6px;margin:10px 0 0}}
  .tag{{color:#fff;font-size:11.5px;font-weight:700;border-radius:5px;padding:2px 7px;text-transform:uppercase;letter-spacing:.03em}}
  .cost{{color:#7a7972;font-weight:400;font-size:13px}}
  .todos{{list-style:none;padding:0;margin:0;display:grid;gap:8px}}
  .todos li{{border:1px solid #e4e3dd;border-radius:10px;padding:9px 12px}}
  .todos p{{margin:4px 0 0 24px;font-size:14px}}
  .todo{{display:flex;gap:8px;align-items:flex-start;cursor:pointer}} .todo input{{margin-top:4px}}
  .ip{{color:#7a7972;font-family:ui-monospace,Menlo,monospace;font-size:13px}} .why{{color:#5d5c55}}
  details{{margin:6px 0 0 24px;font-size:13px;color:#5d5c55}} summary{{cursor:pointer;color:#7a7972}} details p{{margin:4px 0}}
  table{{width:100%;border-collapse:collapse;font-size:13.5px}} th,td{{text-align:left;padding:7px 6px;border-bottom:1px solid #e4e3dd;vertical-align:top}}
  th{{color:#7a7972;font-weight:500}} .num{{text-align:right}} .mono{{font-family:ui-monospace,Menlo,monospace}}
  .new{{background:#fbf1e2;color:#9a5a0b;font-size:10.5px;font-weight:700;border-radius:4px;padding:1px 5px;text-transform:uppercase}}
  .good{{color:#2f7d4f;font-weight:500}}
  footer{{color:#7a7972;font-size:12.5px;margin-top:26px;border-top:1px solid #e4e3dd;padding-top:12px}}
  @media print{{body{{background:#fff;padding:0}} main{{border:0;padding:0}} .todos li{{break-inside:avoid}}}}
</style></head><body><main>
  <h1>Home network report</h1>
  <p class="sub">{_e(_when(result.get('scanned_at')))} &middot; network {_e(result.get('network'))}</p>

  <div class="top">
    <div class="big">{_e(score if score is not None else '?')}<small>out of 100</small></div>
    <div><p><b>{_e(band_name)}.</b> {_e(band_text)}</p><p class="facts">{_e(' · '.join(facts))}</p></div>
  </div>
  {first_step}

  <h2>To-do list</h2>
  {todo}

  {changes}

  <h2>All devices</h2>
  <table><thead><tr><th>Device</th><th>Type</th><th>Made by</th><th>Address</th><th class="num">Score</th><th>To do</th></tr></thead>
  <tbody>{dev_rows or '<tr><td colspan="6">No devices found.</td></tr>'}</tbody></table>

  {warn_html}

  <footer><b>How the score works:</b> each device starts at 100 and loses 40 / 25 / 12 / 5 points for each
  Fix now / Fix soon / Worth fixing / Minor item. The network score is the average of the devices that had at least one item.
  Made by Device Scanner. This file stays on your computer. Only scan networks you own or have permission to check.</footer>
</main></body></html>
"""
