// hal-id: #HAL-20261110-0011-PK-V2
// Safe Attachment Viewer. Everything in report.json is attacker-influenced: it is only ever placed with
// textContent / setAttribute on fixed attribute names. Never innerHTML. Links are shown defanged, never as <a>.

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => {
	const n = document.createElement(tag);
	for (const [k, v] of Object.entries(props)) {
		if (k === "text") n.textContent = v;
		else if (k === "cls") n.className = v;
		else if (k === "on")
			for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
		else n.setAttribute(k, v);
	}
	for (const c of kids) if (c != null) n.append(c);
	return n;
};

const params = new URLSearchParams(location.search);
const caseId = (params.get("case") || "").replace(/[^A-Za-z0-9._-]/g, "");
const base = `cases/${caseId}/`;
const state = {
	rep: null,
	file: null,
	page: 0,
	onlyFlagged: false,
	tab: "findings",
	query: "",
};

function pageFindings(f, n) {
	const at = (arr) => arr.filter((x) => x.page === n);
	return {
		links: at(f.links),
		qr: at(f.qr),
		phones: at(f.phones),
		emails: at(f.emails),
		flags: at(f.flags),
	};
}
const hasFindings = (f, n) =>
	Object.values(pageFindings(f, n)).some((a) => a.length);
const visiblePages = () =>
	state.file.pages.filter(
		(p) => !state.onlyFlagged || hasFindings(state.file, p.n),
	);

function sevOf(f) {
	if (f.av) return "malicious";
	if (f.flags.some((x) => x.severity === "high")) return "high";
	if (f.flags.some((x) => x.severity === "medium")) return "medium";
	return "ok";
}

async function load() {
	if (!caseId) return fatal("No case selected (?case=<id>).");
	let r;
	try {
		r = await fetch(base + "report.json", { cache: "no-store" });
	} catch {
		return fatal("Could not load report.");
	}
	if (!r.ok) return fatal(`Report not found for case ${caseId}.`);
	state.rep = await r.json();
	header();
	// Open on the attachment that most needs eyes: viewable first, then worst severity, then most flags.
	const rank = { malicious: 0, high: 1, medium: 2, ok: 3 };
	const first = [...state.rep.files].sort(
		(a, b) =>
			!a.pages.length - !b.pages.length ||
			rank[sevOf(a)] - rank[sevOf(b)] ||
			b.flags.length - a.flags.length,
	)[0];
	selectFile(first);
}

function fatal(msg) {
	$("case").textContent = msg;
}

function header() {
	const rep = state.rep;
	const v = $("verdict");
	v.textContent = rep.verdict;
	v.className = "badge v-" + rep.verdict.toLowerCase().replace(/\s+/g, "-");
	$("case").textContent = `Case ${rep.caseId}`;
	const iso = rep.isolation;
	const offline = !iso.internetReached && !iso.dnsResolved;
	$("iso").textContent =
		(offline
			? "Analyzed offline (no internet, no DNS)"
			: "WARNING: sandbox was online") +
		` · ${rep.summary.pages} pages · ${rep.timing.total_s}s`;
	$("iso").className = offline ? "muted" : "warn";
	const nav = $("files");
	nav.replaceChildren();
	for (const f of rep.files) {
		const label = (f.parent ? "↳ " : "") + f.name;
		nav.append(
			el("button", {
				type: "button",
				cls: "file sev-" + sevOf(f),
				"data-id": f.id,
				text: label,
				title: `${f.kind} · ${f.size} bytes · sha256 ${f.sha256}`,
				on: { click: () => selectFile(f) },
			}),
		);
	}
}

function selectFile(f) {
	state.file = f;
	state.page = 0;
	for (const b of $("files").children)
		b.classList.toggle("active", b.dataset.id === f.id);
	const esc = $("escalate");
	esc.hidden = !(f.escalate || f.av);
	$("escalate-text").textContent = f.av
		? `Antivirus: ${f.av}. Do not open. ` + (f.escalate || "")
		: f.escalate || "";
	thumbs();
	show();
	tabs();
}

function thumbs() {
	const box = $("thumbs");
	box.replaceChildren();
	const f = state.file;
	for (const p of visiblePages()) {
		const pf = pageFindings(f, p.n);
		const marks = el("div", { cls: "marks" });
		if (pf.flags.length)
			marks.append(
				el("span", {
					cls: "m m-flag",
					text: "!" + pf.flags.length,
					title: "flags",
				}),
			);
		if (pf.links.length)
			marks.append(
				el("span", {
					cls: "m m-link",
					text: "🔗" + pf.links.length,
					title: "links",
				}),
			);
		if (pf.qr.length)
			marks.append(el("span", { cls: "m m-qr", text: "QR", title: "QR code" }));
		if (pf.phones.length)
			marks.append(
				el("span", { cls: "m m-phone", text: "☎", title: "phone number" }),
			);
		if (p.ocr)
			marks.append(
				el("span", {
					cls: "m m-ocr",
					text: "OCR",
					title: "text read from image",
				}),
			);
		const hit = state.query && p.text.toLowerCase().includes(state.query);
		box.append(
			el(
				"button",
				{
					type: "button",
					cls:
						"thumb" +
						(hasFindings(f, p.n) ? " flagged" : "") +
						(hit ? " hit" : ""),
					"data-n": String(p.n),
					on: { click: () => go(f.pages.indexOf(p)) },
				},
				el("img", { src: base + p.thumb, alt: `page ${p.n}`, loading: "lazy" }),
				el("span", { cls: "pn", text: String(p.n) }),
				marks,
			),
		);
	}
}

function show() {
	const f = state.file;
	const img = $("pageimg"),
		pre = $("plaintext"),
		wrap = $("pagewrap");
	$("boxes").replaceChildren();
	if (!f.pages.length) {
		wrap.hidden = true;
		pre.hidden = false;
		pre.textContent =
			f.text != null
				? f.text
				: f.notes.join("\n") || "No preview for this file.";
		$("pageno").textContent =
			f.text != null
				? "text view (shown as plain text, never executed)"
				: "no preview";
		return;
	}
	wrap.hidden = false;
	pre.hidden = true;
	const p = f.pages[state.page];
	img.src = base + p.image;
	$("pageno").textContent =
		`Page ${p.n} of ${f.pageCount}` +
		(f.pages.length < f.pageCount ? ` (first ${f.pages.length} rendered)` : "");
	const pf = pageFindings(f, p.n);
	for (const [kind, arr] of [
		["link", pf.links],
		["qr", pf.qr],
	]) {
		for (const x of arr) {
			if (!x.rect) continue;
			const [l, t, w, h] = x.rect;
			const b = el("div", {
				cls: "box box-" + kind,
				title: kind === "qr" ? `QR: ${x.text}` : `opens ${x.defanged}`,
			});
			b.style.left = `${l * 100}%`;
			b.style.top = `${t * 100}%`;
			b.style.width = `${w * 100}%`;
			b.style.height = `${h * 100}%`;
			$("boxes").append(b);
		}
	}
	for (const t of $("thumbs").children)
		t.classList.toggle("current", t.dataset.n === String(p.n));
	const cur = $("thumbs").querySelector(".current");
	if (cur) cur.scrollIntoView({ block: "nearest" });
	if (state.tab === "page") tabs();
}

function go(i) {
	const f = state.file;
	if (!f.pages.length) return;
	state.page = Math.max(0, Math.min(f.pages.length - 1, i));
	show();
}
function step(d) {
	const vis = visiblePages();
	const cur = vis.findIndex((p) => p.n === state.file.pages[state.page].n);
	const nxt =
		vis[cur === -1 ? 0 : Math.max(0, Math.min(vis.length - 1, cur + d))];
	if (nxt) go(state.file.pages.indexOf(nxt));
}
function stepFlag(d) {
	const f = state.file,
		pages = f.pages;
	for (let i = state.page + d; i >= 0 && i < pages.length; i += d)
		if (hasFindings(f, pages[i].n)) return go(i);
}
function goPage(n) {
	if (n == null) return;
	const i = state.file.pages.findIndex((p) => p.n === n);
	if (i >= 0) go(i);
}

// ---------------------------------------------------------------- right panel
const TABS = [
	["findings", "Findings"],
	["links", "Links"],
	["page", "Page text"],
	["macros", "Macros"],
	["file", "File"],
];

function tabs() {
	const f = state.file;
	const counts = {
		findings: f.flags.length,
		links: f.links.length + f.qr.length + f.phones.length + f.emails.length,
		macros: f.macros ? f.macros.modules.length : 0,
	};
	const bar = $("tabs");
	bar.replaceChildren();
	for (const [id, label] of TABS) {
		if (id === "macros" && !f.macros) continue;
		bar.append(
			el("button", {
				type: "button",
				cls: "tab" + (state.tab === id ? " active" : ""),
				text: label + (counts[id] ? ` (${counts[id]})` : ""),
				on: {
					click: () => {
						state.tab = id;
						tabs();
					},
				},
			}),
		);
	}
	const body = $("tabbody");
	body.replaceChildren();
	(
		({
			findings: tabFindings,
			links: tabLinks,
			page: tabPage,
			macros: tabMacros,
			file: tabFile,
		})[state.tab] || tabFindings
	)(body, f);
}

const pageBtn = (n) =>
	n == null
		? el("span", { cls: "pg muted", text: "file" })
		: el("button", {
				type: "button",
				cls: "pg",
				text: `p.${n}`,
				on: { click: () => goPage(n) },
			});
const copyBtn = (value) =>
	el("button", {
		type: "button",
		cls: "copy",
		text: "copy",
		title: "Copy (defanged)",
		on: {
			click: (e) => {
				navigator.clipboard?.writeText(value);
				e.target.textContent = "copied";
			},
		},
	});

function tabFindings(body, f) {
	if (f.av)
		body.append(
			el(
				"div",
				{ cls: "flag sev-malicious" },
				el("strong", { text: "Antivirus: " }),
				f.av,
			),
		);
	if (!f.flags.length && !f.av)
		body.append(
			el("p", {
				cls: "muted",
				text: "No flags. Review links and pages as usual.",
			}),
		);
	const order = { high: 0, medium: 1, low: 2 };
	for (const x of [...f.flags].sort(
		(a, b) => order[a.severity] - order[b.severity],
	))
		body.append(
			el(
				"div",
				{ cls: "flag sev-" + x.severity },
				pageBtn(x.page),
				el("span", { text: x.text }),
			),
		);
	if (f.notes.length)
		body.append(
			el("h4", { text: "Notes" }),
			...f.notes.map((n) => el("p", { cls: "muted", text: n })),
		);
	if (f.htmlSignals && Object.keys(f.htmlSignals).length)
		body.append(
			el("h4", { text: "HTML signals" }),
			...Object.entries(f.htmlSignals).map(([k, v]) =>
				el("p", { text: `${k}: ${v}` }),
			),
		);
}

function tabLinks(body, f) {
	const sec = (title, items, row) => {
		body.append(el("h4", { text: `${title} (${items.length})` }));
		if (!items.length) body.append(el("p", { cls: "muted", text: "none" }));
		// Page order; file-level items (no page, e.g. links inside macros or .rels) last.
		const byPage = [...items].sort((a, b) => (a.page ?? 1e9) - (b.page ?? 1e9));
		for (const x of byPage) body.append(row(x));
	};
	sec("Links", f.links, (x) =>
		el(
			"div",
			{ cls: "item" },
			pageBtn(x.page),
			el(
				"div",
				{ cls: "grow" },
				el("code", { text: x.defanged }),
				el("div", {
					cls: "muted small",
					text: [
						x.anchor ? `shown as “${x.anchor}”` : null,
						`found via ${x.sources.join(", ")}`,
					]
						.filter(Boolean)
						.join(" · "),
				}),
			),
			copyBtn(x.defanged),
		),
	);
	sec("QR codes", f.qr, (x) =>
		el(
			"div",
			{ cls: "item" },
			pageBtn(x.page),
			el("code", { cls: "grow", text: x.defanged || x.text }),
			copyBtn(x.defanged || x.text),
		),
	);
	sec("Phone numbers", f.phones, (x) =>
		el(
			"div",
			{ cls: "item" },
			pageBtn(x.page),
			el("code", { cls: "grow", text: x.number }),
			el("span", { cls: "muted small", text: x.source }),
		),
	);
	sec("E-mail addresses", f.emails, (x) =>
		el(
			"div",
			{ cls: "item" },
			pageBtn(x.page),
			el("code", { cls: "grow", text: x.addr }),
		),
	);
}

function tabPage(body, f) {
	const p = f.pages[state.page];
	const txt = p ? p.text : f.text || "";
	body.append(
		el("p", {
			cls: "muted small",
			text: p ? `Page ${p.n}${p.ocr ? " · includes OCR text" : ""}` : "",
		}),
		el("pre", { cls: "pagetext", text: txt || "(no text on this page)" }),
	);
}

function tabMacros(body, f) {
	for (const x of f.macros.findings)
		body.append(
			el(
				"div",
				{ cls: "flag sev-" + (x.type === "IOC" ? "medium" : "high") },
				el("strong", { text: `${x.type}: ${x.keyword}` }),
				el("span", { cls: "muted", text: " " + x.description }),
			),
		);
	for (const m of f.macros.modules)
		body.append(
			el("h4", { text: m.name }),
			el("pre", { cls: "code", text: m.code }),
		);
}

function tabFile(body, f) {
	const rows = [
		["Name", f.name],
		["Detected type", f.kind],
		["Size", `${f.size} bytes`],
		["SHA-256", f.sha256],
		["Pages", `${f.pages.length} rendered of ${f.pageCount}`],
		["Antivirus", f.av || `clean (${state.rep.engines.clamav || "n/a"})`],
	];
	for (const [k, v] of rows)
		body.append(
			el(
				"div",
				{ cls: "kv" },
				el("span", { cls: "muted", text: k }),
				el("code", { text: v }),
			),
		);
	body.append(copyBtn(f.sha256));
	body.append(
		el("p", {
			cls: "muted small",
			text: "Next step for anything unknown: look up the hash in your EDR/threat intel before spending a sandbox detonation.",
		}),
	);
}

// ---------------------------------------------------------------- search + keys
$("search").addEventListener("input", (e) => {
	state.query = e.target.value.trim().toLowerCase();
	thumbs();
	if (state.query) {
		const i = state.file.pages.findIndex((p) =>
			p.text.toLowerCase().includes(state.query),
		);
		if (i >= 0) go(i);
	}
});
$("only-flagged").addEventListener("change", (e) => {
	state.onlyFlagged = e.target.checked;
	thumbs();
	step(0);
});
$("prev").addEventListener("click", () => step(-1));
$("next").addEventListener("click", () => step(1));
$("next-flag").addEventListener("click", () => stepFlag(1));
document.addEventListener("keydown", (e) => {
	if (e.target.tagName === "INPUT") {
		if (e.key === "Escape") e.target.blur();
		return;
	}
	const k = e.key;
	if (k === "ArrowRight" || k === "j") step(1);
	else if (k === "ArrowLeft" || k === "k") step(-1);
	else if (k === "n") stepFlag(1);
	else if (k === "p") stepFlag(-1);
	else if (k === "f") {
		const c = $("only-flagged");
		c.checked = !c.checked;
		c.dispatchEvent(new Event("change"));
	} else if (k === "/") {
		e.preventDefault();
		$("search").focus();
	} else return;
	e.preventDefault();
});

load();
