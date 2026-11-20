/* dashboard.js - makes the dashboard work

   This file has the page's "state" (everything we're showing right now), all
   the calls to server.py, and what happens when you click or type things.
   The drawing itself is in render.js and the words are in labels.js.

   Load order in dashboard.html: labels.js, then render.js, then this file.
*/

/* S = "state". Everything the page is showing right now lives in here.
   render.js reads it, and the functions below change it. */
const S = {
  // the devices from the scan on screen
  devices: [],
  // the safety score + problems (made by security.py)
  report: null,
  // problems the scan had (like "not running as admin")
  warnings: [],
  // e.g. "192.168.1.0/24"
  network: null,
  // the whole scan exactly as we got it (for Save a copy)
  raw: null,
  // e.g. "scan-20261118-154841" if it's saved in our folder
  scanId: null,
  // the names the user gave their devices
  names: {},
  // the list of saved scans for the dropdown
  history: [],
  // which device type button is clicked (null = show all)
  filter: null,
  // what's typed in the search box
  query: "",
  // which column the list is sorted by
  sortKey: "ip",
  // 1 = going up, -1 = going down
  sortDir: 1,
  // the IPs of the rows that are expanded
  open: new Set(),
  // the IP of the device being renamed (null = none)
  renaming: null,
  // where the scan came from: none, live, file or history
  source: "none",
  // true while a scan is running
  scanning: false,
};

// ask the server for progress every 1 second
const POLL_MS = 1000;
/**
 * Function: fmtTime - Writing seconds as minutes and seconds
 * 75 seconds -> "1:15"
 *
 * Input argument: s - a number of seconds
 * Output argument: none
 * Return: text like "1:15"
 * Dependencies: none
 */
const fmtTime = s => `${Math.floor(s/60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
/**
 * Function: stamp - Getting the time right now
 * the time right now, e.g. "3:48 PM"
 *
 * Input argument: none
 * Output argument: none
 * Return: text like "3:48 PM"
 * Dependencies: none
 */
const stamp = () => new Date().toLocaleTimeString([], {hour:"numeric", minute:"2-digit"});
// false if someone double-clicked dashboard.html instead of using server.py
const onServer = location.protocol !== "file:";
// becomes true once the user types in the Network box (so we don't overwrite it)
let typedNetwork = false;

/**
 * Function: api - Sending a request to server.py
 * Every call to server.py goes through this function.
 * The "X-Scanner: 1" header proves the request came from our page (other websites can't add it).
 * Always gives back {ok, status, data} and never throws, so the rest of the code stays simple.
 *
 * Input argument: path - the API address, e.g. "api/history"
 *                 body - the data to send (leave it out for a GET)
 * Output argument: none
 * Return: a Promise of {ok, status, data} (status 0 means the server couldn't be reached)
 * Dependencies: browser - fetch
 */
async function api(path, body)
{
  try
  {
    const r = await fetch(path, {
      // if we pass a body it's a POST
      method: body === undefined ? "GET" : "POST",
      // always ask the server, never use an old answer
      cache: "no-store",
      headers: {"X-Scanner": "1", ...(body === undefined ? {} : {"Content-Type": "application/json"})},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = null;
    // some answers aren't JSON, that's ok
    try { data = await r.json(); } catch {}
    return {ok: r.ok, status: r.status, data};
  }
  catch
  {
    // status 0 = couldn't reach the server at all
    return {ok: false, status: 0, data: null};
  }
}

/* ---------------- Showing a scan ---------------- */
/**
 * Function: showResults - Showing a scan on the page
 * Input argument: data - the scan
 *                 src - where it came from: live, file or history
 * Output argument: S - gets the scan's devices, report, warnings and id
 * Return: true if it was a scan, false if not
 * Dependencies: render.js - $, normalize, renderAll, renderScanMenu, unwrap; dashboard.js - S, onServer
 */
function showResults(data, src)
{
  // handles old and new scan formats
  const u = unwrap(data);
  // not a scan
  if (!u) return false;
  Object.assign(S, {source: src, devices: normalize(u.list), warnings: u.warnings, report: u.report,
                    network: u.network, raw: data, scanId: data.id || null, renaming: null});
  // close all the rows
  S.open.clear();
  // show which network this scan was
  if (u.network){ $("#cidr").value = u.network; typedNetwork = false; }
  $("#saveBtn").disabled = false;
  // the report only exists for saved scans
  $("#reportBtn").hidden = !(onServer && S.scanId);
  renderAll(); renderScanMenu();
  return true;
}
/**
 * Function: warnText - Getting the scan's warnings for the end of the status line
 * warnings at the end of the status line
 *
 * Input argument: none
 * Output argument: none
 * Return: the warnings as text, or ""
 * Dependencies: dashboard.js - S
 */
const warnText = () => S.warnings.length ? " · ⚠ " + S.warnings.join(" · ") : "";
/**
 * Function: doneMeta - Getting the "Found 8 devices · 3:48 PM" text
 * Input argument: none
 * Output argument: none
 * Return: the text
 * Dependencies: dashboard.js - S, stamp
 */
const doneMeta = () => `Found ${S.devices.length} device${S.devices.length === 1 ? "" : "s"} · ${stamp()}`;

/* ---------------- Scanning ----------------
   1. ask the server to start a scan
   2. ask how it's going every second (follow) until it's done */
/**
 * Function: scan - Starting a scan (the Scan network button)
 * Input argument: none
 * Output argument: S - the old results are cleared
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - $, renderAll, setStatus; dashboard.js - S, api, follow, notReachable, onServer
 */
async function scan()
{
  // already scanning
  if (S.scanning) return;
  // the page was opened as a file, so there's no server to ask
  if (!onServer)
  {
    setStatus({state:"Open this page through server.py", meta:"Run python3 server.py, then go to the address it prints.", off:true});
    return;
  }
  // a network (192.168.1.0/24) or just one IP (192.168.1.1)
  const typed = $("#cidr").value.trim();
  // quick check: numbers, dots and maybe a /24 at the end
  if (!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(typed))
  {
    setStatus({state:"Check the network address", meta:"Type any IP on the network (like 192.168.1.1) or a whole network (like 192.168.1.0/24).", off:true});
    $("#cidr").focus();
    return;
  }
  // server.py works out the full network from an IP
  const r = await api("api/scan/start", {cidr: typed});
  if (r.status === 0) return notReachable();
  // 409 means a scan is already running, we just follow that one
  if (!r.ok && r.status !== 409)
  {
    setStatus({state:"The scan couldn't start", meta:r.data?.error || `Error ${r.status}`, off:true});
    return;
  }
  // show the network we picked from their IP
  if (r.data?.from_ip) $("#cidr").value = r.data.network;
  // clear the old results
  S.devices = []; S.report = null; S.open.clear(); S.source = "none";
  renderAll();
  follow(r.data?.from_ip ? `the network ${typed} is on` : "");
}

/**
 * Function: follow - Checking on the scan every second until it's done
 * Input argument: note - extra text for the status line (optional)
 * Output argument: S - scanning is set, then the results are saved in it
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - $, setStatus; dashboard.js - POLL_MS, S, api, doneMeta, fmtTime, loadHistory, notReachable, showResults, warnText; browser - setTimeout
 */
async function follow(note = "")
{
  S.scanning = true;
  setStatus({state:"Starting the scan…", scanning:true, pct:0});
  // how many times in a row the server didn't answer
  let failures = 0;
  while (S.scanning)
  {
    const r = await api("api/scan/status");
    if (!r.ok || !r.data)
    {
      // give up after 5 tries
      if (++failures >= 5){ S.scanning = false; return notReachable(); }
    }
    else
    {
      failures = 0;
      // {state, pct, text, elapsed, network, result...}
      const j = r.data;
      if (j.state === "running")
      {
        setStatus({state:`${j.text || "Scanning"}…`,
                   meta:`${j.network || ""}${note ? ` (${note})` : ""} · ${fmtTime(j.elapsed)} so far`,
                   scanning:true, pct:j.pct});
      // finished one way or another
      }
      else
      {
        S.scanning = false;
        if (j.state === "done" && showResults(j.result, "live"))
        {
          setStatus({state:"Scan finished", meta:`${doneMeta()} · took ${fmtTime(j.elapsed)}` +
            (j.result.saved_to ? ` · Saved in ${j.result.saved_to}` : "") + warnText()});
          // the new scan is now in the dropdown
          loadHistory();
          // move keyboard/screen reader users to the score
          $("#report summary").focus();
        }
        else if (j.state === "cancelled")
        {
          setStatus({state:"Scan stopped", meta:"Press Scan network to start again.", off:true});
        }
        else if (j.state === "error")
        {
          // last 2 lines of detail
          const extra = j.details ? " · " + String(j.details).split("\n").filter(Boolean).slice(-2).join(" ") : "";
          setStatus({state:"The scan couldn't run", meta:(j.error || "Unknown problem") + extra, off:true});
        }
        else
        {
          setStatus({state:"Not scanned yet", off:true});
        }
        return;
      }
    }
    // wait a second before asking again
    await new Promise(res => setTimeout(res, POLL_MS));
  }
}

/**
 * Function: cancelScan - Stopping the scan (the Stop scan button)
 * Input argument: none
 * Output argument: none
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - $, setStatus; dashboard.js - api
 */
async function cancelScan()
{
  // so it can't be clicked twice
  $("#cancelBtn").disabled = true;
  setStatus({state:"Stopping…", scanning:true, pct:null});
  // follow() sees the "cancelled" state on its next check
  await api("api/scan/cancel", {});
  $("#cancelBtn").disabled = false;
}

/**
 * Function: notReachable - Telling the user the scanner isn't running
 * Input argument: none
 * Output argument: S - source goes back to "none"
 * Return: none
 * Dependencies: render.js - renderAll, setStatus; dashboard.js - S
 */
function notReachable()
{
  S.source = "none"; renderAll();
  setStatus({state:"Can't reach the scanner", meta:"Start it with python3 server.py, then reload this page.", off:true});
}

/* ---------------- Saved scans, names and files ---------------- */
/**
 * Function: loadHistory - Getting the list of saved scans from server.py
 * Input argument: none
 * Output argument: S - history gets the list
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - renderScanMenu; dashboard.js - S, api
 */
async function loadHistory()
{
  const r = await api("api/history");
  if (r.ok && Array.isArray(r.data)){ S.history = r.data; renderScanMenu(); }
}

/**
 * Function: openHistory - Opening one saved scan
 * Input argument: id - the scan's id, e.g. scan-20261118-154841
 * Output argument: S - gets that scan
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - fmtDate, renderScanMenu, setStatus; dashboard.js - S, api, showResults, warnText
 */
async function openHistory(id)
{
  const r = await api(`api/history/${encodeURIComponent(id)}`);
  if (r.ok && showResults(r.data, "history"))
  {
    setStatus({state:"Showing a saved scan", meta:`${S.devices.length} devices · scanned ${fmtDate(r.data.scanned_at)}${warnText()}`});
  }
  else
  {
    setStatus({state:"Couldn't open that scan", meta:"It may have been deleted.", off:true});
    renderScanMenu();
  }
}

/**
 * Function: onScanMenu - Handling a pick from the Saved scans dropdown
 * the one "Saved scans" dropdown: pick a saved scan, or the last option to open a file
 *
 * Input argument: e - the change event
 * Output argument: none
 * Return: none
 * Dependencies: render.js - $, OPEN_FILE, renderScanMenu; dashboard.js - openHistory
 */
function onScanMenu(e)
{
  const v = e.target.value;
  // "Open a scan file from your computer…"
  if (v === OPEN_FILE)
  {
    // put the dropdown back on the current scan
    renderScanMenu();
    // opens the normal file picker
    $("#fileIn").click();
  }
  else if (v)
  {
    openHistory(v);
  }
}

/**
 * Function: loadNames - Getting the user's device names from server.py
 * Input argument: none
 * Output argument: S - names gets the list
 * Return: a Promise (nothing useful inside)
 * Dependencies: dashboard.js - S, api
 */
async function loadNames()
{
  const r = await api("api/names");
  if (r.ok && r.data && typeof r.data === "object") S.names = r.data;
}

/**
 * Function: saveName - Saving a new name for a device
 * Input argument: ip - the device's IP
 *                 name - the new name (empty removes it)
 * Output argument: S - names gets the new name
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - deviceKey, renderAll, setStatus; dashboard.js - S, api, onServer; browser - CSS, document
 */
async function saveName(ip, name)
{
  const d = S.devices.find(x => x.ip === ip); if (!d) return;
  const key = deviceKey(d);
  // remember the old name in case saving fails
  const before = S.names[key];
  name = name.trim();
  // show the new name right away
  if (name) S.names[key] = name; else delete S.names[key];
  S.renaming = null; renderAll();
  if (!onServer) return;
  const r = await api("api/names", {key, name});
  if (r.ok && r.data) S.names = r.data;
  // saving failed, so put the old name back
  else
  {
    if (before) S.names[key] = before; else delete S.names[key];
    renderAll();
    setStatus({state:"Couldn't save that name", meta:r.data?.error || "Is server.py still running?", off:true});
  }
  document.querySelector(`.row[data-ip="${CSS.escape(ip)}"]`)?.focus();
}

/**
 * Function: saveCopy - Saving the scan into Documents/Device Scanner (the Save a copy button)
 * "Save a copy": saves into Documents/Device Scanner/scans and /reports only (nothing goes to Downloads).
 * For a scan that's already saved, this updates its report with your latest device names.
 *
 * Input argument: none
 * Output argument: S - scanId gets the saved scan's id
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - $, setStatus; dashboard.js - S, api, loadHistory, onServer
 */
async function saveCopy()
{
  if (!S.raw) return;
  if (!onServer)
  {
    setStatus({state:"Can't save without the scanner running", meta:"Start python3 server.py and open the address it prints.", off:true});
    return;
  }
  $("#saveBtn").disabled = true;
  // saved scans just send their id, opened files send the whole scan
  const body = S.scanId ? {id: S.scanId} : {scan: S.raw};
  const r = await api("api/scan/save", body);
  $("#saveBtn").disabled = false;
  if (!r.ok)
  {
    setStatus({state:"Couldn't save a copy", meta:r.data?.error || "Is server.py still running?", off:true});
    return;
  }
  // it's in our folder now
  S.scanId = r.data.id; S.raw.id = r.data.id;
  $("#reportBtn").hidden = false;
  await loadHistory();
  setStatus({state: r.data.status === "added" ? "Saved a copy" : "Saved",
             meta:`${r.data.folder}: scans/${r.data.json}` + (r.data.report ? ` and reports/${r.data.report}` : "")});
}

/**
 * Function: openFile - Opening a scan file from the computer
 * Input argument: f - the file the user picked
 * Output argument: none (showResults updates S when it's read)
 * Return: none
 * Dependencies: render.js - setStatus; dashboard.js - doneMeta, showResults, warnText; browser - FileReader
 */
function openFile(f)
{
  // reads the file inside the browser
  const rd = new FileReader();
  rd.onload = () => {
    try
    {
      if (!showResults(JSON.parse(rd.result), "file")) throw 0;
      setStatus({state:"Opened a scan file", meta:`${doneMeta()} · press Save a copy to add it to your saved scans${warnText()}`});
    }
    catch
    {
      setStatus({state:"That file isn't a saved scan", meta:"Pick a scan .json file (they're in Documents/Device Scanner/scans).", off:true});
    }
  };
  rd.onerror = () => setStatus({state:"Couldn't read that file", meta:"Try picking it again.", off:true});
  rd.readAsText(f);
}

/**
 * Function: goTo - Scrolling to a device in the list and opening it
 * scroll to a device in the list and open it (used by the map and the problem list)
 *
 * Input argument: ip - the device's IP
 * Output argument: S - the filter and search are cleared, and the device is opened
 * Return: none
 * Dependencies: render.js - $, domId, renderList, renderSummary; dashboard.js - S; browser - document, matchMedia, setTimeout
 */
function goTo(ip)
{
  // clear filters so the device is definitely visible
  S.filter = null; S.query = ""; $("#q").value = ""; S.open.add(ip);
  renderSummary(); renderList();
  const el = document.getElementById(domId(ip));
  if (!el) return;
  el.scrollIntoView({behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block:"center"});
  el.querySelector(".row")?.focus({preventScroll:true});
  // flash it so you can see which one
  el.classList.add("flash"); setTimeout(() => el.classList.remove("flash"), 1300);
}

/* ---------------- Clicks and typing ---------------- */
$("#scanBtn").addEventListener("click", scan);
$("#cancelBtn").addEventListener("click", cancelScan);
// pressing Enter in the box also scans
$("#cidr").addEventListener("keydown", e => { if (e.key === "Enter") scan(); });
$("#cidr").addEventListener("input", () => { typedNetwork = true; });
$("#cidr").addEventListener("change", renderMap);
$("#saveBtn").addEventListener("click", saveCopy);
// opens the report in a new tab
$("#reportBtn").addEventListener("click", () => { if (S.scanId) window.open(`report/${encodeURIComponent(S.scanId)}`, "_blank", "noopener"); });
$("#fileIn").addEventListener("change", e => { const f = e.target.files[0]; if (f) openFile(f); e.target.value = ""; });
$("#scanMenu").addEventListener("change", onScanMenu);
// the device type buttons
$("#legend").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  // clicking the same one again turns it off
  S.filter = S.filter === b.dataset.cat ? null : b.dataset.cat;
  renderSummary(); renderList();
});
// search as you type
$("#q").addEventListener("input", e => { S.query = e.target.value; renderList(); });
// clicking a column title sorts by it
document.querySelector(".cols").addEventListener("click", e => {
  const b = e.target.closest("[data-sort]"); if (!b) return;
  const k = b.dataset.sort;
  // same column again = flip the direction
  S.sortDir = S.sortKey === k ? -S.sortDir : 1;
  S.sortKey = k; renderList();
});
// one listener for the whole list (works for rows added later)
$("#list").addEventListener("click", e => {
  const start = e.target.closest("[data-rename-start]");
  // "Give it a name"
  if (start){ S.renaming = start.dataset.renameStart; renderList(); return; }
  // "Cancel"
  if (e.target.closest("[data-rename-cancel]"))
  {
    const ip = S.renaming; S.renaming = null; renderList();
    document.querySelector(`[data-rename-start="${CSS.escape(ip)}"]`)?.focus();
    return;
  }
  // clicks inside the open details shouldn't close it
  if (e.target.closest(".detail")) return;
  const r = e.target.closest(".row"); if (!r) return;
  const ip = r.dataset.ip;
  // open or close the row
  S.open.has(ip) ? S.open.delete(ip) : S.open.add(ip);
  renderList();
  // keep keyboard focus on the same row
  document.querySelector(`.row[data-ip="${CSS.escape(ip)}"]`)?.focus();
});
// the rename form
$("#list").addEventListener("submit", e => {
  const f = e.target.closest("[data-rename]"); if (!f) return;
  // stop the page from reloading
  e.preventDefault();
  saveName(f.dataset.rename, f.querySelector("input").value);
});
// Esc cancels renaming
$("#list").addEventListener("keydown", e => { if (e.key === "Escape" && S.renaming){ S.renaming = null; renderList(); } });
// clicking a device name in the problem list
$("#findings").addEventListener("click", e => {
  const b = e.target.closest("[data-goto]"); if (!b) return;
  e.preventDefault(); goTo(b.dataset.goto);
});
$("#map").addEventListener("click", e => { const ip = e.target.closest("[data-ip]")?.dataset.ip; if (ip) goTo(ip); });
const mapHint = "Each square is one spot on your network. Pick a colored one to see that device.";
/**
 * Function: showTip - Showing a device's name under the map when you point at it
 * show the device's name under the map on hover/focus
 *
 * Input argument: e - the mouse or focus event
 * Output argument: none
 * Return: none
 * Dependencies: labels.js - CATS; render.js - $, displayName; dashboard.js - S, mapHint
 */
const showTip = e =>
{
  const ip = e.target.closest?.("[data-ip]")?.dataset.ip;
  const d = S.devices.find(x => x.ip === ip);
  $("#mapTip").textContent = d ? `${displayName(d)} (${(CATS[d.category] || CATS.unknown).label}) · ${d.ip}` : mapHint;
};
$("#map").addEventListener("mouseover", showTip);
$("#map").addEventListener("focusin", showTip);

/* ---------------- When the page first loads ---------------- */
/**
 * Function: init - Getting the page ready when it first loads
 * Input argument: none
 * Output argument: S - gets the names, saved scans and the last scan
 * Return: a Promise (nothing useful inside)
 * Dependencies: render.js - $, fmtDate, renderAll, renderScanMenu, setStatus; dashboard.js - S, api, follow, loadHistory, loadNames, notReachable, onServer, openHistory, typedNetwork
 */
(async function init()
{
  renderAll(); renderScanMenu();
  // opened as a file: you can still open scan files
  if (!onServer)
  {
    setStatus({state:"Not connected", meta:"Start python3 server.py and open the address it prints. You can still open a scan file from the Saved scans menu.", off:true});
    return;
  }
  setStatus({state:"Not scanned yet", off:true});
  // is the server there? which network are we on?
  const h = await api("api/health");
  if (!h.ok) return notReachable();
  // fill in this computer's network
  if (h.data.network && !typedNetwork) $("#cidr").value = h.data.network;
  await loadNames();
  await loadHistory();
  if (h.data.admin === false)
    setStatus({state:"Not scanned yet", meta:"The server isn't running as admin, so makers and operating systems won't show.", off:true});
  // a scan was already running (page reloaded), keep showing it
  if (h.data.scanning) follow();
  // otherwise show the latest saved scan
  else if (S.history.length)
  {
    await openHistory(S.history[0].id);
    setStatus({state:"Showing your last scan", meta:`From ${fmtDate(S.history[0].scanned_at)} · press Scan network for a fresh one`});
  }
})();
