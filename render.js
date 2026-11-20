/* render.js - draws the page

   Every function here reads the current state (the S object, which lives in
   dashboard.js) and turns it into HTML. Nothing in here talks to the server,
   that's all in dashboard.js. Splitting it up like this made it way easier to
   find bugs, because if something looks wrong it's in here, and if something
   doesn't load it's in dashboard.js.
*/

/**
 * Function: $ - Shortcut for finding one element on the page
 * shortcut, like jQuery: $("#scanBtn") gets the element with id="scanBtn"
 *
 * Input argument: s - a CSS selector like "#scanBtn"
 * Output argument: none
 * Return: the element, or null
 * Dependencies: browser - document
 */
const $ = s => document.querySelector(s);
/**
 * Function: esc - Making text safe to put inside HTML
 * escape text before putting it in HTML, so a device named "<script>" can't run code on our page
 *
 * Input argument: s - any text
 * Output argument: none
 * Return: the text with & < > " ' escaped
 * Dependencies: none
 */
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
/**
 * Function: ipNum - Turning an IP into one number so IPs sort properly
 * turn "192.168.1.10" into one number so IPs sort properly (.9 before .10)
 *
 * Input argument: ip - an IP address like "192.168.1.10"
 * Output argument: none
 * Return: the IP as a number (or a huge number if it isn't an IPv4 address)
 * Dependencies: none
 */
const ipNum = ip =>
{
  // ["192","168","1","10"]
  const p = String(ip).split(".");
  // not an IPv4 address, put it last
  if (p.length !== 4 || !p.every(x => /^\d+$/.test(x))) return Number.MAX_SAFE_INTEGER;
  // 192*256^3 + 168*256^2 + ...
  return p.reduce((a, x) => a*256 + +x, 0);
};
/**
 * Function: cv - Getting the CSS colour for a device type
 * the CSS colour for a device type
 *
 * Input argument: k - the device type, e.g. "phone"
 * Output argument: none
 * Return: text like "var(--c-phone)"
 * Dependencies: labels.js - CATS
 */
const cv = k => `var(${CATS[k]?.c || "--c-unknown"})`;
/**
 * Function: domId - Making a page id from an IP
 * "192.168.1.1" -> "dev-192-168-1-1" (ids can't have dots)
 *
 * Input argument: ip - an IP address
 * Output argument: none
 * Return: an id like "dev-192-168-1-1"
 * Dependencies: none
 */
const domId = ip => "dev-" + String(ip).replace(/[^0-9a-zA-Z]/g, "-");

/**
 * Function: deviceKey - Getting a device's ID that stays the same between scans
 * same rule as security.py's device_key(): MAC if we have one, otherwise the IP
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: its MAC in capitals, or "ip:" + its IP
 * Dependencies: none
 */
const deviceKey = d => d.mac ? d.mac.toUpperCase() : "ip:" + d.ip;

/**
 * Function: parseReason - Splitting a clue into its points, type and reason
 * scanner.py writes clues like "+5 phone: hostname 'iPhone'". This splits that into {pts: 5, cat: "phone", why: "hostname 'iPhone'"}
 *
 * Input argument: r - a clue like "+5 phone: hostname 'iPhone'"
 * Output argument: none
 * Return: {pts, cat, why}
 * Dependencies: none
 */
function parseReason(r)
{
  // + number, a word, a colon, then the rest
  const m = /^\+(\d+)\s+(\w+):\s*(.*)$/.exec(r);
  // clues without points just keep their text
  return m ? {pts:+m[1], cat:m[2], why:m[3]} : {pts:0, cat:null, why:String(r)};
}

/**
 * Function: unwrap - Reading a scan in either the new or the old format
 * Saved scans come in two shapes: the new one {devices:[...], report:...} and really old ones that are just a list
 *
 * Input argument: data - a saved scan
 * Output argument: none
 * Return: {list, warnings, network, report}, or null if it isn't a scan
 * Dependencies: none
 */
function unwrap(data)
{
  // old format
  if (Array.isArray(data)) return {list:data, warnings:[], network:null, report:null};
  // new format
  if (data && Array.isArray(data.devices))
    return {list:data.devices, warnings:Array.isArray(data.warnings) ? data.warnings : [],
            network:data.network || null, report:data.report || null};
  // not a scan at all
  return null;
}

/**
 * Function: normalize - Cleaning up the device list so every device has every field
 * Clean up the device list so the rest of the code doesn't have to worry about missing fields
 *
 * Input argument: list - the devices from the scan
 * Output argument: none
 * Return: a new list of cleaned-up devices
 * Dependencies: labels.js - CATS; render.js - parseReason
 */
function normalize(list)
{
  // skip anything without an IP
  return list.filter(d => d && typeof d.ip === "string" && d.ip).map(d => {
    // split every clue
    const parsed = (d.reasons || []).map(parseReason);
    // backup scores, worked out from the clues
    const added = {};
    parsed.forEach(r => { if (r.cat) added[r.cat] = (added[r.cat] || 0) + r.pts; });
    const conf = Number(d.confidence);
    // keep everything scanner.py sent, and fix up:
    return {...d,
      mac: d.mac || "",
      // unknown type names become "unknown"
      category: CATS[d.category] ? d.category : "unknown",
      // keep it between 0 and 1
      confidence: Number.isFinite(conf) ? Math.min(1, Math.max(0, conf)) : 0,
      parsed,
      scores: (d.scores && typeof d.scores === "object") ? d.scores : added,
      open_ports: Array.isArray(d.open_ports) ? d.open_ports : []};
  });
}

/**
 * Function: clueCount - Counting the clues that gave points
 * how many clues gave points
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: how many clues gave points
 * Dependencies: none
 */
const clueCount = d => d.parsed.filter(r => r.cat).length;
/**
 * Function: needsReview - Checking if we're unsure about a device
 * we call it a "best guess" if we don't know the type, aren't very sure, or only had one clue
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: true if it's a best guess
 * Dependencies: labels.js - REVIEW_BELOW; render.js - clueCount
 */
const needsReview = d => d.category === "unknown" || d.confidence < REVIEW_BELOW || clueCount(d) <= 1;
/**
 * Function: reviewNote - Explaining why a device is only a best guess
 * Input argument: d - one device
 * Output argument: none
 * Return: a sentence for the details panel
 * Dependencies: render.js - clueCount
 */
function reviewNote(d)
{
  const n = clueCount(d);
  if (d.category === "unknown") return n ? "The clues we found weren't strong enough to tell what this is." : "We didn't find any clues about what this is.";
  if (n <= 1) return "We only found one clue, so this is a best guess.";
  return "The clues point different ways, so this is a best guess.";
}
/**
 * Function: customName - Getting the name the user gave a device
 * the name the user gave it, if any
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: the name, or "" if they didn't give one
 * Dependencies: render.js - deviceKey; dashboard.js - S
 */
const customName = d => S.names[deviceKey(d)] || "";
/**
 * Function: displayName - Picking the best name to show for a device
 * Input argument: d - one device
 * Output argument: none
 * Return: the user's name, its own name, its model, "Router" or "Unnamed device"
 * Dependencies: render.js - customName
 */
const displayName = d => customName(d) || d.hostname || d.mdns_model || (d.is_router ? "Router" : "Unnamed device");
/**
 * Function: sureWord - Picking the words for the "How sure we are" column
 * the words in the "How sure we are" column
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: "Can't tell", "Best guess", "Very sure" or "Fairly sure"
 * Dependencies: render.js - needsReview
 */
const sureWord = d => d.category === "unknown" ? "Can't tell" : needsReview(d) ? "Best guess" : d.confidence >= 0.85 ? "Very sure" : "Fairly sure";
/**
 * Function: issuesFor - Getting the problems found on one device
 * the problems found on one device
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: a list of findings
 * Dependencies: dashboard.js - S
 */
const issuesFor = d => (S.report?.findings || []).filter(f => f.ip === d.ip);
/**
 * Function: fmtDate - Writing a date the short way
 * "Nov 18, 3:48 PM"
 *
 * Input argument: ts - a date like "2026-11-18T15:48:41"
 * Output argument: none
 * Return: text like "Nov 18, 3:48 PM"
 * Dependencies: none
 */
const fmtDate = ts => new Date(ts).toLocaleString([], {month:"short", day:"numeric", hour:"numeric", minute:"2-digit"});

/* ---------------- The safety score (a dropdown at the top) ----------------
   Closed, it's just one bar: the score, what it means and how many problems.
   Click it to drop down the full list of problems. */
/**
 * Function: renderReport - Drawing the safety score dropdown
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: labels.js - SEVERITY, SEV_ORDER, bandFor; render.js - $, esc, fmtDate, techDetails; dashboard.js - S
 */
function renderReport()
{
  const r = S.report, box = $("#report");
  // no scan yet, so hide it
  if (!r){ box.hidden = true; return; }
  box.hidden = false;
  const score = Number.isFinite(Number(r.score)) ? Math.round(Number(r.score)) : null;
  // e.g. [60, "poor", "Needs attention", "..."]
  const band = score == null ? null : bandFor(score);
  $("#grade").innerHTML = score == null ? "?" : `${score}<small>/100</small>`;
  // CSS uses this to pick the colour
  $("#grade").dataset.band = band ? band[1] : "";
  $("#gradeWords").textContent = band ? `${band[2]}. ${band[3]}` : "";
  const c = r.counts || {};
  // ["1 to fix now", "2 worth fixing"]
  const parts = SEV_ORDER.filter(k => c[k]).map(k => `${c[k]} ${SEVERITY[k].count}`);
  $("#gradeMeta").textContent = parts.length ? parts.join(" · ") : "Nothing to fix";
  // for screen readers
  $("#summaryLabel").textContent = `Safety score ${score ?? "unknown"} out of 100, ${band ? band[2] : ""}. ${parts.join(", ")}`;
  $("#compared").textContent = r.first_scan
    ? "This is your first scan of this network, so next time we'll also point out new devices."
    : r.compared_to ? `Compared with your scan from ${fmtDate(r.compared_to)}.` : "";

  const findings = r.findings || [];
  $("#findings").innerHTML = findings.length ? findings.map(f => `
    <li class="finding sev-${esc(f.severity)}">
      <details>
        <summary>
          <span class="sev">${esc(SEVERITY[f.severity]?.label || f.severity)}</span>
          <span class="ftitle">${esc(f.title)}</span>
          <button type="button" class="link" data-goto="${esc(f.ip)}" aria-label="Show ${esc(f.device)} in the device list">${esc(f.device)}</button>
        </summary>
        <p><b>Why it matters:</b> ${esc(f.why)}</p>
        <p><b>What to do:</b> ${esc(f.fix)}</p>
        ${techDetails(f)}
      </details>
    </li>`).join("") : `<li class="finding none-found">We didn't find anything to fix. Nice work.</li>`;

  // devices from last time that weren't here
  const gone = r.gone || [];
  $("#gone").hidden = !gone.length;
  $("#gone").textContent = gone.length ? `Not seen this time: ${gone.map(x => x.device).join(", ")}. They're probably just switched off or away from home.` : "";
}

/**
 * Function: techDetails - Drawing the "For the technically curious" part of a problem
 * the "For the technically curious" part under each problem: port details, weaknesses and fixes from vulnerability_identifier.py
 *
 * Input argument: f - one finding
 * Output argument: none
 * Return: the HTML, or "" if there's nothing technical
 * Dependencies: render.js - esc
 */
function techDetails(f)
{
  const d = f.details || {};
  // nothing technical to show
  if (!f.tech && !d.weaknesses?.length && !d.remediations?.length) return "";
  const list = (title, xs) => xs?.length ? `<b>${title}</b><ul>${xs.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : "";
  return `<div class="tech"><details><summary>For the technically curious</summary>
    ${f.tech ? `<p>${esc(f.tech)}</p>` : ""}${list("Known weaknesses", d.weaknesses)}${list("Recommended fixes", d.remediations)}
  </details></div>`;
}

/* ---------------- "What's connected" box and the network map ---------------- */
/**
 * Function: renderSummary - Drawing the "What's connected" box
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: labels.js - CATS, ORDER; render.js - $, cv, displayName, needsReview; dashboard.js - S
 */
function renderSummary()
{
  // start every type at 0
  const counts = Object.fromEntries(ORDER.map(k => [k, 0]));
  S.devices.forEach(d => counts[d.category] = (counts[d.category] || 0) + 1);
  const n = S.devices.length;
  $("#total").textContent = `${n} device${n === 1 ? "" : "s"}`;
  // the coloured bar: each type gets a piece as wide as how many devices it has
  $("#mix").innerHTML = ORDER.filter(k => counts[k]).map(k => `<i style="flex:${counts[k]};background:${cv(k)}" title="${CATS[k].label}: ${counts[k]}"></i>`).join("");
  // the buttons under it (click one to only show that type). "Unknown" only shows up if there are any
  $("#legend").innerHTML = ORDER.filter(k => counts[k] || k !== "unknown").map(k =>
    `<button type="button" data-cat="${k}" class="${S.filter === k ? "on" : ""}" aria-pressed="${S.filter === k}"><span class="sw" style="background:${cv(k)}"></span>${CATS[k].label}<span class="n">${counts[k] || 0}</span></button>`).join("");
  // the yellow note: new devices and ones we're unsure about
  const rev = S.devices.filter(needsReview), fresh = S.devices.filter(d => d.is_new);
  const notes = [];
  if (fresh.length) notes.push(`${fresh.length} new since your last scan: ${fresh.map(displayName).join(", ")}.`);
  if (rev.length) notes.push(`We're not sure about ${rev.length} device${rev.length > 1 ? "s" : ""}: ${rev.map(displayName).join(", ")}.`);
  $("#attn").hidden = !notes.length;
  $("#attn").textContent = notes.join(" ");
}

/**
 * Function: renderMap - Drawing the network map (one square per address)
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: labels.js - CATS; render.js - $, cv, displayName, esc; dashboard.js - S
 */
function renderMap()
{
  // the network we're showing
  const net = S.network || $("#cidr").value;
  // "192.168.1"
  const base = (net.split("/")[0] || "192.168.1.0").split(".").slice(0, 3).join(".");
  $("#mapNet").textContent = net;
  $("#winTitle").textContent = "Your network · " + net;
  // devices by the last number of their IP
  const byLast = {};
  S.devices.forEach(d => { if (String(d.ip).startsWith(base + ".")) byLast[+d.ip.split(".")[3]] = d; });
  let h = "";
  // one square for every address .0 to .255
  for (let i = 0; i < 256; i++)
  {
    const d = byLast[i];
    h += d ? `<button type="button" class="cell on${d.is_router ? " gw" : ""}${d.is_new ? " new" : ""}" data-ip="${esc(d.ip)}" style="background:${cv(d.category)}" aria-label="${esc(d.ip)}, ${esc(displayName(d))}, ${esc(CATS[d.category].label)}" title="${esc(d.ip)} · ${esc(displayName(d))}"></button>`
           // empty spot
           : `<i class="cell" aria-hidden="true"></i>`;
  }
  $("#map").innerHTML = h;
}

/* ---------------- The device list ---------------- */
/**
 * Function: sorted - Sorting the devices by the column the user picked
 * Input argument: list - the devices to sort
 * Output argument: none
 * Return: a new sorted list
 * Dependencies: labels.js - ORDER; render.js - displayName, ipNum; dashboard.js - S
 */
function sorted(list)
{
  // which column we're sorting by
  const k = S.sortKey;
  // [...list] makes a copy so we don't change the original
  return [...list].sort((a, b) => {
    let x, y;
    if (k === "ip"){ x = ipNum(a.ip); y = ipNum(b.ip); }
    else if (k === "name"){ x = displayName(a).toLowerCase(); y = displayName(b).toLowerCase(); }
    else if (k === "category"){ x = ORDER.indexOf(a.category); y = ORDER.indexOf(b.category); }
    else { x = a.confidence; y = b.confidence; }
    // sortDir is 1 (up) or -1 (down)
    return (x < y ? -1 : x > y ? 1 : 0) * S.sortDir;
  });
}

/**
 * Function: renderSortHeaders - Showing which column is sorted, and which way
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: dashboard.js - S; browser - document
 */
function renderSortHeaders()
{
  document.querySelectorAll(".cols [data-sort]").forEach(b => {
    // is this the column we're sorting by?
    const on = b.dataset.sort === S.sortKey;
    // screen readers announce this
    b.closest("[role=columnheader]")?.setAttribute("aria-sort", on ? (S.sortDir > 0 ? "ascending" : "descending") : "none");
    b.querySelector(".arrow").textContent = on ? (S.sortDir > 0 ? "↑" : "↓") : "";
  });
}

/**
 * Function: deviceRow - Drawing one row of the device list
 * one row in the list (the part you always see)
 *
 * Input argument: d - one device
 * Output argument: none
 * Return: the HTML for the row
 * Dependencies: labels.js - CATS, FEATURES, SEV_ORDER, maker; render.js - cv, deviceDetail, displayName, domId, esc, issuesFor, sureWord; dashboard.js - S
 */
function deviceRow(d)
{
  const cat = CATS[d.category] || CATS.unknown, c = cv(d.category), pct = Math.round(d.confidence * 100);
  const sub = d.is_self ? "This computer" : d.vendor ? "Made by " + maker(d.vendor) : (d.randomized_mac ? "Uses a private address" : "Maker unknown");
  // Set removes duplicates (80 and 443 are both "Settings page")
  const acts = [...new Set(d.open_ports.map(p => FEATURES[p] || `Port ${p}`))];
  const ports = acts.length ? acts.map(a => `<span class="port">${esc(a)}</span>`).join("") : `<span class="none">Nothing open</span>`;
  const issues = issuesFor(d);
  // the worst problem decides the badge colour
  const worst = SEV_ORDER.find(s => issues.some(f => f.severity === s)) || null;
  const badges = (d.is_new ? `<span class="badge new">New</span>` : "") +
    (worst ? `<span class="badge sev-${worst}" title="${issues.length} thing${issues.length > 1 ? "s" : ""} to check on this device">${issues.length} to check</span>` : "");
  // is this row expanded?
  const isOpen = S.open.has(d.ip);
  return `<div class="dev${isOpen ? " open" : ""}" id="${domId(d.ip)}" style="--c:${c}" role="listitem">
    <button class="row" type="button" data-ip="${esc(d.ip)}" aria-expanded="${isOpen}" aria-controls="${domId(d.ip)}-detail">
      <span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${cat.icon}</svg></span>
      <span class="name"><b>${esc(displayName(d))}${badges}</b><small>${esc(sub)}</small></span>
      <span class="type"><span class="chip"><span class="sw" aria-hidden="true"></span>${cat.label}</span></span>
      <span class="ipmac mono">${esc(d.ip)}<span class="${d.randomized_mac ? "rand" : ""}" title="${esc(d.mac)}">${esc(d.mac)}</span></span>
      <span class="ports">${ports}</span>
      <span class="conf"><span class="bar" aria-hidden="true"><i style="width:${pct}%"></i></span><span class="pct">${sureWord(d)}</span></span>
      <svg class="chev" aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 6 6 6-6 6"/></svg>
    </button>
    ${isOpen ? deviceDetail(d, issues) : ""}
  </div>`;
}

/**
 * Function: deviceDetail - Drawing the part that opens when you click a row
 * the part that opens up when you click a row
 *
 * Input argument: d - one device
 *                 issues - the problems found on it
 * Output argument: none
 * Return: the HTML for the details
 * Dependencies: labels.js - CATS, ORDER, SEVERITY, maker, plain; render.js - customName, cv, domId, esc, needsReview, reviewNote; dashboard.js - S
 */
function deviceDetail(d, issues)
{
  // biggest score, so the bars can be scaled to it
  const maxS = Math.max(1, ...Object.values(d.scores).map(Number).filter(Number.isFinite));
  const scoreRows = ORDER.filter(k => k !== "unknown").map(k =>
    `<div class="sc"><span>${CATS[k].label}</span><span class="bar" aria-hidden="true"><i style="width:${(d.scores[k] || 0) / maxS * 100}%;background:${cv(k)}"></i></span><span class="v">${d.scores[k] || 0}</span></div>`).join("");
  const reasons = d.parsed.map(r =>
    `<li style="--c:${cv(r.cat)}"><span class="pts">${r.pts ? "+" + r.pts : ""}</span><span class="why">${esc(plain(r.why))} <em>${r.cat ? "(points for " + (CATS[r.cat]?.label || r.cat) + ")" : ""}</em></span></li>`).join("");
  const sec = issues.length
    ? `<ul class="dissues">${issues.map(f => `<li class="sev-${esc(f.severity)}"><span class="sev">${esc(SEVERITY[f.severity]?.label || f.severity)}</span> <b>${esc(f.title)}</b><br>${esc(f.fix)}</li>`).join("")}</ul>`
    : `<p class="ok">Nothing to fix on this device.</p>`;
  // are we showing the rename box?
  const editing = S.renaming === d.ip;
  return `<div class="detail" id="${domId(d.ip)}-detail">
    <div><h3>Points for each type</h3><div class="scores">${scoreRows}</div>
      ${needsReview(d) ? `<p class="review">${esc(reviewNote(d))}</p>` : ""}</div>
    <div><h3>Clues we found</h3><ul class="reasons">${reasons}</ul>
      <h3>Safety check${d.score != null ? ` <span class="dscore">${esc(d.score)}/100</span>` : ""}</h3>${sec}</div>
    <div><h3>Details</h3>
      <div class="rename">${editing
        ? `<form data-rename="${esc(d.ip)}"><label class="sr-only" for="rn-${domId(d.ip)}">New name</label><input id="rn-${domId(d.ip)}" value="${esc(customName(d) || d.hostname || "")}" maxlength="60" placeholder="e.g. Diego's laptop"><button class="btn small" type="submit">Save</button><button class="btn small" type="button" data-rename-cancel>Cancel</button></form>`
        : `<button class="btn small" type="button" data-rename-start="${esc(d.ip)}">${customName(d) ? "Change name" : "Give it a name"}</button>`}</div>
      <dl>
        <dt>Name</dt><dd>${esc(customName(d) ? `${customName(d)} (your name)` : d.hostname || "No name given")}</dd>
        ${customName(d) && d.hostname ? `<dt>Calls itself</dt><dd>${esc(d.hostname)}</dd>` : ""}
        <dt>Model</dt><dd>${esc(d.mdns_model || "Not shared")}</dd>
        ${d.os ? `<dt>System</dt><dd>${esc(d.os)}</dd>` : ""}
        <dt>Maker</dt><dd>${esc(d.vendor ? maker(d.vendor) : (d.randomized_mac ? "Hidden (private address)" : "Unknown"))}</dd>
        <dt>Network address</dt><dd>${esc(d.ip)}</dd>
        <dt>Hardware ID</dt><dd>${esc(d.mac || (d.is_self ? "This computer" : "Not seen"))}</dd>
      </dl></div>
  </div>`;
}

/**
 * Function: renderList - Drawing the device list (with the search and type filter)
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: labels.js - CATS, maker; render.js - $, customName, deviceRow, renderSortHeaders, sorted; dashboard.js - S; browser - document
 */
function renderList()
{
  // what's typed in the search box
  const q = S.query.toLowerCase();
  const shown = sorted(S.devices.filter(d =>
    // matches the type button they clicked (if any)
    (!S.filter || d.category === S.filter) &&
    (!q || [d.ip, d.mac, d.hostname, customName(d), d.vendor, d.vendor && maker(d.vendor), d.mdns_model, CATS[d.category]?.label]
             // and the search text appears somewhere
             .join(" ").toLowerCase().includes(q))));
  $("#listTitle").textContent = S.filter ? CATS[S.filter].label : "All devices";
  renderSortHeaders();
  if (!S.devices.length){ $("#list").innerHTML = `<div class="empty">${S.source === "none" ? "No devices yet. Press Scan network to start." : "No devices answered. Check the network address matches your Wi-Fi and scan again."}</div>`; return; }
  if (!shown.length){ $("#list").innerHTML = `<div class="empty">No devices match. Clear the search or pick another type.</div>`; return; }
  $("#list").innerHTML = shown.map(deviceRow).join("");
  // if the rename box is open, put the cursor in it
  const input = document.querySelector("[data-rename] input");
  if (input){ input.focus(); input.select(); }
}

/* ---------------- The "Saved scans" dropdown ----------------
   One menu for everything: every scan saved in Documents/Device Scanner,
   plus the last option, which lets you open a scan file from anywhere. */
// the value of the "open a file" option
const OPEN_FILE = "__file__";
/**
 * Function: renderScanMenu - Filling in the Saved scans dropdown
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: render.js - $, OPEN_FILE, esc, fmtDate; dashboard.js - S
 */
function renderScanMenu()
{
  const sel = $("#scanMenu");
  const items = S.history || [];
  // is the scan on screen one of the saved ones?
  const current = items.some(h => h.id === S.scanId);
  sel.innerHTML =
    `<option value="" ${current ? "" : "selected"}>${items.length ? `Saved scans (${items.length})` : "Saved scans"}</option>` +
    items.map(h => `<option value="${esc(h.id)}"${h.id === S.scanId ? " selected" : ""}>${esc(fmtDate(h.scanned_at))} · ${esc(h.devices)} devices${h.score != null ? ` · ${esc(h.score)}/100` : ""}</option>`).join("") +
    `<option disabled>──────────</option>` +
    `<option value="${OPEN_FILE}">Open a scan file from your computer…</option>`;
}

/**
 * Function: renderAll - Redrawing everything
 * redraw everything
 *
 * Input argument: none
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: render.js - renderList, renderMap, renderReport, renderSummary
 */
function renderAll(){ renderReport(); renderSummary(); renderMap(); renderList(); }

/* ---------------- The status bar ---------------- */
/**
 * Function: setStatus - Updating the status line and progress bar
 * Input argument: {state, meta, scanning, pct, off} - what to show (all but state are optional)
 * Output argument: none (updates the page)
 * Return: none
 * Dependencies: render.js - $; dashboard.js - S
 */
function setStatus({state, meta = "", scanning = false, pct = null, off = false})
{
  // makes the dot blink
  $("#status").classList.toggle("scanning", scanning);
  $("#status").classList.toggle("off", off);
  // the bold part
  $("#stState").textContent = state;
  // the grey part after it
  $("#stMeta").textContent = meta;
  // only show the progress bar when we have a number
  $("#prog").hidden = pct == null;
  if (pct != null){ $("#prog i").style.width = pct + "%"; $("#prog").setAttribute("aria-valuenow", Math.round(pct)); }
  // the small tag at the end
  $("#srcTag").textContent = scanning ? "Scanning" : ({none:"Not connected", live:"Your network", file:"Opened from a file", history:"Saved scan"}[S.source] || "");
  // swap Scan for Stop while scanning
  $("#scanBtn").hidden = scanning;
  $("#cancelBtn").hidden = !scanning;
}
