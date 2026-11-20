/* labels.js - all the words and icons the dashboard uses

   We kept these in their own file so render.js and dashboard.js stay shorter,
   and so if we want to change some wording we only have to look in one place.
   Nothing in this file touches the page, it's just data and two small helper functions.

   Load order in dashboard.html: labels.js, then render.js, then dashboard.js
*/

/* The device types. For each one:
     label = the name we show
     c     = the CSS colour variable (defined in styles.css)
     icon  = the inside of a small SVG drawing (24x24) */
const CATS = {
  phone:{label:"Phone",c:"--c-phone",icon:'<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18.5h2"/>'},
  computer:{label:"Computer",c:"--c-computer",icon:'<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>'},
  game_console:{label:"Game console",c:"--c-console",icon:'<path d="M7 8h10a4 4 0 0 1 4 4l.6 4.2a2 2 0 0 1-3.5 1.6L16 15H8l-2.1 2.8a2 2 0 0 1-3.5-1.6L3 12a4 4 0 0 1 4-4z"/><path d="M8 10.5v3M6.5 12h3"/><circle cx="16" cy="11" r=".6" fill="currentColor"/><circle cx="17.5" cy="13" r=".6" fill="currentColor"/>'},
  tv_media:{label:"TV & streaming",c:"--c-tv",icon:'<rect x="2.5" y="5" width="19" height="12" rx="1.5"/><path d="M8 21h8M9 2.5l3 2.5 3-2.5"/>'},
  iot_other:{label:"Smart home & other",c:"--c-iot",icon:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1"/>'},
  unknown:{label:"Unknown",c:"--c-unknown",icon:'<path d="M9.2 9a3 3 0 1 1 4.3 2.7c-.9.4-1.5 1.2-1.5 2.2v.6"/><circle cx="12" cy="18" r=".8" fill="currentColor"/>'},
};
// the order types show up in lists
const ORDER = ["phone","computer","game_console","tv_media","iot_other","unknown"];
// if we're less than 60% sure about a device, we call it a "best guess"
const REVIEW_BELOW = 0.6;

/* How urgent each problem is, in normal words.
   label = the tag on each problem, count = used in sentences like "2 to fix now" */
const SEVERITY = {
  critical:{label:"Fix now", count:"to fix now"},
  high:{label:"Fix soon", count:"to fix soon"},
  medium:{label:"Worth fixing", count:"worth fixing"},
  low:{label:"Worth a look", count:"worth a look"},
};
// worst first
const SEV_ORDER = ["critical","high","medium","low"];

/* Score ranges, highest first: [lowest score in the range, key, name, one-line meaning]
   (these match BANDS in security.py) */
const SCORE_BANDS = [
  [90, "excellent", "Excellent", "Nothing serious found."],
  [80, "good", "Good", "Only small things to tidy up."],
  [70, "fair", "Fair", "A few settings could let someone in."],
  [60, "poor", "Needs attention", "Risky settings are switched on."],
  [0, "at_risk", "At risk", "Someone on your Wi-Fi could get into at least one device."],
];
/**
 * Function: bandFor - Finding the score range a score falls in
 * find the range a score falls in, e.g. 72 -> the "fair" row
 *
 * Input argument: score - the safety score, 0 to 100
 * Output argument: none
 * Return: the matching row of SCORE_BANDS, e.g. [70, "fair", "Fair", "..."]
 * Dependencies: labels.js - SCORE_BANDS
 */
const bandFor = score => SCORE_BANDS.find(b => score >= b[0]) || SCORE_BANDS[SCORE_BANDS.length-1];

/* What an open port is used for, as a short tag in the "What it's doing" column */
const FEATURES = {
  21: "File transfer",
  22: "Remote login",
  23: "Old remote login",
  53: "Handles web addresses",
  80: "Settings page",
  443: "Settings page",
  135: "Windows sharing",
  139: "Windows sharing",
  445: "File sharing",
  631: "Printing",
  9100: "Printing",
  1883: "Smart-home messaging",
  3074: "Xbox online play",
  3306: "Database",
  1433: "Database",
  5432: "Database",
  6379: "Database",
  27017: "Database",
  9200: "Search database",
  3389: "Remote Desktop",
  5555: "Android debugging",
  5900: "Screen sharing",
  7000: "AirPlay",
  8001: "TV remote",
  8002: "TV remote",
  8008: "Casting",
  8009: "Casting",
  8060: "Roku remote",
  9197: "Screen mirroring",
  9295: "PlayStation Remote Play",
  9296: "PlayStation Remote Play",
  9297: "PlayStation Remote Play",
  62078: "iPhone syncing",
};

/* The same ports as a full sentence, for the "Clues we found" list */
const PORT_SENTENCE = {
  22: "Remote login is turned on",
  135: "Windows sharing is turned on",
  139: "Windows sharing is turned on",
  445: "File sharing is turned on",
  3389: "Remote Desktop is turned on, which only computers have",
  5900: "Screen sharing is turned on",
  62078: "It's ready to sync with a computer, which iPhones do",
  5555: "Android debugging is turned on",
  9295: "PlayStation Remote Play is turned on",
  9296: "PlayStation Remote Play is turned on",
  9297: "PlayStation Remote Play is turned on",
  3074: "It uses Xbox online play",
  8001: "It accepts a TV remote app (Samsung TVs do)",
  8002: "It accepts a TV remote app (Samsung TVs do)",
  9197: "It accepts screen mirroring",
  8008: "It accepts casting from phones",
  8009: "It accepts casting from phones",
  8060: "It can be controlled by a Roku remote app",
  7000: "It accepts AirPlay",
  631: "It accepts print jobs",
  9100: "It accepts print jobs",
  53: "It handles web addresses for other devices, like routers do",
  3306: "A database is running on it",
};

/* Bonjour (mDNS) services a device can announce, as sentences */
const SERVICE_SENTENCE = {
  "_apple-mobdev2._tcp": "It offers iPhone/iPad syncing",
  "_companion-link._tcp": "It talks to other Apple devices nearby",
  "_rdlink._tcp": "It offers Apple remote features",
  "_smb._tcp": "It shares files with other computers",
  "_afpovertcp._tcp": "It shares files with other computers",
  "_ssh._tcp": "It allows remote logins",
  "_sftp-ssh._tcp": "It allows remote logins",
  "_rfb._tcp": "It allows screen sharing",
  "_googlecast._tcp": "It accepts casting from phones (like a Chromecast)",
  "_androidtvremote2._tcp": "It's an Android/Google TV",
  "_amzn-wplay._tcp": "It's a Fire TV",
  "_airplay._tcp": "It accepts AirPlay",
  "_raop._tcp": "It can play AirPlay music",
  "_spotify-connect._tcp": "It works with Spotify Connect",
  "_ipp._tcp": "It's a printer",
  "_printer._tcp": "It's a printer",
  "_hap._tcp": "It's a smart home accessory",
};

/**
 * Function: maker - Shortening a company name
 * Shorten company names: "Intel Corporate" -> "Intel", "ASUSTek COMPUTER INC." -> "ASUS"
 *
 * Input argument: v - the company name, e.g. "Intel Corporate"
 * Output argument: none
 * Return: the shorter name, e.g. "Intel"
 * Dependencies: none
 */
const maker = v => String(v ?? "").replace(/,?\s*(Inc\.?|Ltd\.?|Limited|Corporation|Corporate|Corp\.?|Co\.?|Foundation|Trading)\s*$/i,"").replace(/,\s*$/,"").replace(/\s+COMPUTER$/i,"").replace(/^ASUSTek$/i,"ASUS").trim();

/**
 * Function: plain - Turning one of scanner.py's clues into a normal sentence
 * scanner.py writes its clues in a short technical way (like "TCP 445 open").
 * This turns each one into a sentence anyone can read. Each "if" checks for one
 * kind of clue using a regular expression and builds the sentence from it.
 *
 * Input argument: why - the clue, e.g. "TCP 445 open"
 * Output argument: none
 * Return: the sentence to show on the page
 * Dependencies: labels.js - CATS, PORT_SENTENCE, SERVICE_SENTENCE, maker
 */
function plain(why)
{
  // holds whatever the regular expression matched
  let m;
  // nmap's operating system guess
  if ((m = /^OS guess '(.+)'$/.exec(why))) return `Looks like it runs ${m[1]}`;
  // how it asked the router for an address
  if ((m = /^DHCP class '(.+)'$/.exec(why)))
    return /android/i.test(m[1]) ? "It asked for its address the way Android phones do"
         // "MSFT 5.0" = Windows
         : /msft/i.test(m[1]) ? "It asked for its address the way Windows computers do"
         : `It identified itself as "${m[1]}"`;
  if (/gateway/.test(why)) return "It's the gateway every device uses to reach the internet, so it's your router";
  // the final answer line
  if ((m = /^Our guess: (.+)$/.exec(why)))
  {
    // "tv media" -> "tv_media"
    const k = m[1].trim().replace(/\s+/g,"_");
    return `Our guess: ${(CATS[k]?.label || m[1]).toLowerCase()}`;
  }
  if ((m = /^answered PlayStation discovery as (.+)$/.exec(why))) return `It answered a PlayStation check and said it's a ${m[1]}`;
  // the maker from the MAC address
  if ((m = /^MAC vendor '(.+)'$/.exec(why))) return `It was made by ${maker(m[1])}`;
  if (/^randomized/.test(why)) return "It uses a private Wi-Fi address, which phones and tablets do by default";
  if (/^this computer/.test(why)) return "This is the computer running the scan";
  if (/^seen recently/.test(why)) return "This computer saw it recently, but it didn't answer the scan (it may be asleep)";
  // the name it gave itself
  if ((m = /^hostname '(.+)'$/.exec(why))) return `It calls itself "${m[1]}"`;
  // Bonjour
  if ((m = /^advertises (.+)$/.exec(why))) return SERVICE_SENTENCE[m[1]] || "It announced a service on the network";
  if ((m = /^Apple model '(.+)'$/.exec(why))) return `It told us its model is ${m[1]}`;
  // an open port
  if ((m = /^TCP (\d+) open$/.exec(why))) return PORT_SENTENCE[m[1]] || `Connection point ${m[1]} is open`;
  // what it announced over UPnP
  if ((m = /^SSDP '(.*)'$/.exec(why)))
  {
    const s = m[1].toLowerCase();
    if (/gateway|igd/.test(s)) return "It announced itself as a router";
    if (/windows/.test(s)) return "It announced itself as a Windows computer";
    if (/xbox/.test(s)) return "It announced itself as an Xbox";
    if (/roku/.test(s)) return "It announced itself as a Roku";
    return "It announced itself as a TV or streaming device";
  }
  if (/no strong signals/.test(why)) return "We didn't find enough clues to tell";
  // anything we don't recognise is shown as-is
  return why;
}

