// hal-id: #HAL-20261113-0012-PK-T2
// Outlook task pane: read the selection (IDs + shared-mailbox owner only, never attachments), get the analyst's
// token by nested app authentication (no extra sign-in inside Outlook), ask the portal to start the previews, open
// the preview tab, and show progress. Subjects are untrusted text: only ever set with textContent.

let cfg = null;
let pca = null;
let token = null;
let selection = [];
let autoStarted = false;

const $ = (id) => document.getElementById(id);
const STAGES = {
	queued: "Waiting for a renderer",
	starting: "Starting",
	fetching: "Copying the email into the sandbox",
	locked: "Network locked, opening files",
	rendering: "Rendering pages",
	scanning: "Virus scan",
	checking: "Checking the output",
	done: "Ready",
	failed: "Failed: escalate manually",
};

function say(text, cls) {
	$("msg").textContent = text || "";
	$("msg").className = cls || "";
}

function call(fn) {
	return new Promise((resolve, reject) =>
		fn((r) =>
			r.status === Office.AsyncResultStatus.Succeeded
				? resolve(r.value)
				: reject(r.error),
		),
	);
}

function toRest(ewsId) {
	try {
		return Office.context.mailbox.convertToRestId(
			ewsId,
			Office.MailboxEnums.RestVersion.v2_0,
		);
	} catch (e) {
		return ewsId;
	}
}

async function sharedOwner(item) {
	if (!item || typeof item.getSharedPropertiesAsync !== "function") return null;
	try {
		const p = await call((cb) => item.getSharedPropertiesAsync(cb));
		return (p && p.owner) || null;
	} catch (e) {
		return null; // not in a shared folder or mailbox
	}
}

async function readSelection(auto) {
	const mbx = Office.context.mailbox;
	let items = [];
	if (
		Office.context.requirements.isSetSupported("Mailbox", "1.13") &&
		typeof mbx.getSelectedItemsAsync === "function"
	) {
		try {
			items = (await call((cb) => mbx.getSelectedItemsAsync(cb))).map((i) => ({
				ewsId: i.itemId,
				subject: i.subject,
			}));
		} catch (e) {
			items = [];
		}
	}
	if (!items.length && mbx.item)
		items = [{ ewsId: mbx.item.itemId, subject: mbx.item.subject }];

	if (items.length === 1 && mbx.item && items[0].ewsId === mbx.item.itemId) {
		items[0].mailbox = await sharedOwner(mbx.item);
	} else if (
		items.length &&
		Office.context.requirements.isSetSupported("Mailbox", "1.15")
	) {
		for (const it of items) {
			try {
				const loaded = await call((cb) => mbx.loadItemByIdAsync(it.ewsId, cb));
				it.mailbox = await sharedOwner(loaded);
				await call((cb) => loaded.unloadAsync(cb));
			} catch (e) {
				it.mailbox = null; // the portal falls back to what the analyst can access
			}
		}
	}
	selection = items
		.slice(0, cfg.maxItems)
		.map((it) => ({ ...it, id: toRest(it.ewsId) }));
	const list = $("selection");
	list.replaceChildren();
	for (const it of selection) {
		const li = document.createElement("li");
		li.textContent = it.subject || "(no subject)";
		if (it.mailbox) {
			const m = document.createElement("span");
			m.className = "muted";
			m.textContent = ` · ${it.mailbox}`;
			li.append(m);
		}
		list.append(li);
	}
	if (!selection.length)
		list.innerHTML = '<li class="muted">Select one or more emails.</li>';
	$("sel-title").textContent =
		selection.length > 1
			? `${selection.length} selected emails`
			: "Selected email";
	if (items.length > cfg.maxItems)
		say(`Only the first ${cfg.maxItems} emails will be previewed.`, "warn");
	$("go").textContent =
		selection.length > 1
			? `Preview ${selection.length} emails safely`
			: "Preview safely";
	$("go").disabled = !selection.length;
	if (auto && selection.length && !autoStarted) {
		autoStarted = true; // clicking the ribbon button is the request; don't make them click twice
		start();
	}
}

async function getToken() {
	if (!Office.context.requirements.isSetSupported("NestedAppAuth", "1.1"))
		return null;
	if (!pca) {
		pca = await msal.createNestablePublicClientApplication({
			auth: {
				clientId: cfg.clientId,
				authority: `https://login.microsoftonline.com/${cfg.tenantId}`,
			},
		});
	}
	const req = { scopes: [cfg.apiScope] };
	try {
		return (await pca.acquireTokenSilent(req)).accessToken;
	} catch (e) {
		return (await pca.acquireTokenPopup(req)).accessToken;
	}
}

function openUrl(url) {
	try {
		Office.context.ui.openBrowserWindow(url);
	} catch (e) {
		window.open(url, "_blank", "noopener");
	}
}

function b64url(s) {
	return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function start() {
	$("go").disabled = true;
	say("Starting…");
	const items = selection.map((s) => ({
		id: s.id,
		mailbox: s.mailbox || null,
	}));
	try {
		token = await getToken();
	} catch (e) {
		token = null;
	}
	if (!token) {
		// Older Outlook without nested app auth: the browser signs in instead (same access rules).
		openUrl(`${cfg.portal}/start?items=${b64url(JSON.stringify(items))}`);
		say("Continue in your browser.", "ok");
		$("go").disabled = false;
		return;
	}
	let r;
	let j = {};
	try {
		r = await fetch(`${cfg.portal}/api/cases`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${token}`,
			},
			body: JSON.stringify({ items }),
		});
		j = await r.json().catch(() => ({}));
	} catch (e) {
		say("Can't reach the preview service.", "err");
		$("go").disabled = false;
		return;
	}
	if (!j.cases) {
		say(j.error || `Request failed (${r.status}).`, "err");
		$("go").disabled = false;
		return;
	}
	if (j.open && j.cases.some((c) => c.id)) openUrl(j.open);
	$("cases-wrap").hidden = false;
	const ul = $("cases");
	ul.replaceChildren();
	j.cases.forEach((c, i) => {
		const li = document.createElement("li");
		const subj = (selection[i] && selection[i].subject) || "(no subject)";
		if (c.id) {
			const a = document.createElement("a");
			a.href = c.url;
			a.textContent = subj;
			a.addEventListener("click", (ev) => {
				ev.preventDefault();
				openUrl(c.url);
			});
			const st = document.createElement("span");
			st.className = "stage";
			st.dataset.case = c.id;
			st.textContent = STAGES.queued;
			li.append(a, document.createElement("br"), st);
		} else {
			li.textContent = `${subj}: ${c.error}`;
			li.className = "err";
		}
		ul.append(li);
	});
	say("");
	$("go").disabled = false;
	poll();
}

async function poll() {
	const pending = [...document.querySelectorAll(".stage[data-case]")].filter(
		(el) => !["done", "failed"].includes(el.dataset.stage),
	);
	for (const el of pending) {
		try {
			const r = await fetch(
				`${cfg.portal}/api/cases/${el.dataset.case}/status`,
				{
					headers: { Authorization: `Bearer ${token}` },
				},
			);
			if (!r.ok) continue;
			const s = (await r.json()).status || {};
			el.dataset.stage = s.stage;
			let t = STAGES[s.stage] || s.stage;
			if (s.stage === "rendering" && s.page)
				t += `: ${s.file || "file"}, page ${s.page}${s.pages ? ` of ${s.pages}` : ""}`;
			el.textContent = t;
			el.className = `stage s-${s.stage}`;
		} catch (e) {
			/* keep polling */
		}
	}
	if (pending.length) setTimeout(poll, 2000);
}

Office.onReady(async () => {
	try {
		cfg = await (await fetch("config.json", { cache: "no-store" })).json();
	} catch (e) {
		say("Can't reach the preview service.", "err");
		return;
	}
	$("go").addEventListener("click", start);
	if (Office.EventType && Office.EventType.SelectedItemsChanged) {
		try {
			Office.context.mailbox.addHandlerAsync(
				Office.EventType.SelectedItemsChanged,
				() => readSelection(false),
			);
		} catch (e) {
			/* older Outlook: single item only */
		}
	}
	await readSelection(true);
});
