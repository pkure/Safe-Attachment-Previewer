// hal-id: #HAL-20261113-0014-PK-S1
// Case list: refresh the status column of cases still in progress.

(function poll() {
	const rows = [...document.querySelectorAll("tr[data-case]")].filter(
		(r) => !["done", "failed"].includes(r.querySelector(".st").textContent),
	);
	if (!rows.length) return;
	Promise.all(
		rows.map((r) =>
			fetch(`/api/cases/${encodeURIComponent(r.dataset.case)}/status`, {
				cache: "no-store",
			})
				.then((x) => (x.ok ? x.json() : null))
				.then((j) => {
					if (j && j.status)
						r.querySelector(".st").textContent = j.status.stage;
				})
				.catch(() => {}),
		),
	).then(() => setTimeout(poll, 2000));
})();
