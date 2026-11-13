---
hal-id: "#HAL-20261107-0023-PK-H1"
---

# Safe Attachment Preview: how to run it

**What it is:** a safe way to look at a suspicious email attachment without opening it on your computer.
1. The attachment goes into a sealed box (a "container") that has **no internet at all**.
2. Inside the box, the file is turned into plain pictures of each page, plus its text, its links and any QR codes or
   phone numbers. Anything that looks like a phishing trick gets a warning.
3. You look at the pictures in a web page. The original file never touches your computer.
4. The box is thrown away after every file. Nothing runs in between, so it costs nothing while waiting.

**Test samples only.** Only fake test files go in here, never real company email.

**Two ways to run it:**
- **On this Mac** (below, "Preview a file"): $0, for trying files quickly.
- **In the cloud lab with classic Outlook** (next section): the way a security team would really use it.

## The cloud lab: one button in classic Outlook

**What happens when an analyst clicks "Preview safely":**
1. They select one or more emails in the shared security mailbox and click **Preview safely** on the ribbon.
2. A browser tab opens with a checklist that fills in live: email copied into the sealed storage, network lock
   checked, pages being drawn ("page 4 of 12"), virus scan, ready.
3. The tab turns into the preview. The attachment was never downloaded or opened on their computer.

**Who can use it:** only people in the **SecOps Triage Analysts** group. That same group is what gives Full Access to
the shared mailbox, so one membership controls both. The tool reads an email *as the analyst who clicked*, so it can
never see a mailbox that analyst couldn't open in Outlook anyway.

**Money:** the previewer costs about $0–1 a month (nothing runs between clicks). The lab's Windows "analyst PC" costs
about $0.10 an hour while it's on and turns itself off every evening at 7 PM; it also costs about $10 a month just for
its disk while it exists.

| Task | How |
|---|---|
| Turn the analyst PC on / off | `scripts/cloud.sh vm-start` / `scripts/cloud.sh vm-stop` |
| Its admin password (to the Keychain, not the screen) | `scripts/cloud.sh vm-password` |
| Connect to it | Azure portal → **vm-analyst** → **Connect** → **Bastion** → user `labadmin` |
| See who did what (last hour) | `scripts/cloud.sh logs` |
| Remove the whole cloud lab | `scripts/cloud.sh down` |
| Deploy it again | `scripts/cloud.sh up` |

**One-time steps that need a person (an admin):**
1. ★ `scripts/lab-analyst.sh <domain>`: makes the test analyst `analyst1` (password goes to the Keychain).
2. ★ `pwsh scripts/exchange-setup-v2.ps1 -Domain <domain>`: makes the group, gives it the shared mailbox.
3. `scripts/cloud.sh up`: builds everything (about 10 minutes).
4. ★ On the analyst PC, in classic Outlook, signed in as analyst1: **File → Account Settings → Account Settings →
   Change → More Settings → Advanced → Add** the shared mailbox (group access doesn't add it automatically).
5. ★ Load the add-in: in Outlook, **Get Add-ins → My add-ins → Add a custom add-in → From URL**, and paste the
   address from `scripts/cloud.sh status` (`addin_manifest_url`). In a real company, IT pushes it to the group
   instead (Microsoft 365 admin center → Integrated apps).

**Paperwork for a real company:** [docs/controls.md](docs/controls.md) maps every safeguard to the NIST 800-53
controls security reviewers ask about, and lists what the organization still has to provide.

## One-time setup

| Step | How |
|---|---|
| Docker Desktop running | Open **Docker** from Applications (whale icon in the menu bar) |
| Build the box | `scripts/preview-local.sh build` (about 5 minutes the first time, and needs internet once) |
| Make the test files | `scripts/preview-local.sh samples` |

Run these from the project folder (`~/hal/code/attachment-sandbox`), or just ask HAL.

## Preview a file

```
scripts/preview-local.sh render dist/samples-v2/long-report.pdf
```

Your browser opens the viewer. You can give it several files at once and they become one case.

A suspicious **email** works too: in Outlook, save it as a file (`.eml`) and render that. You'll see the sender
checks, the body, and every attachment inside it. (`.msg` isn't supported yet.)

**Preview samples** (fake, made by `samples`): a forwarded phishing email, a vendor bank-change letter, a fake sign-in
page, a voicemail screenshot, a clean timesheet, plus the older test files. All live in `dist/samples-v2/` and `dist/samples/`.

**In the viewer:**
- The **← / →** arrow keys turn pages. **n** / **p** jump to the next or previous finding. **f** hides pages with
  nothing on them, so long documents get short.
- The **link list** shows every web address with the page it's on. Addresses are "defanged" (`hxxps`, `[.]`) so
  they can't be clicked by accident. Use **copy** if you need one for a lookup.
- Red and amber **flags** explain what looked wrong, for example "link text shows contoso.com but opens somewhere else".
- A file that can't be shown safely, like a program pretending to be a PDF, gets a red **don't open** banner.
  Escalate it by hand the way the team already does (hash lookup, sandbox).

## Check that it still works

`scripts/preview-local.sh test` should end with **41 passed** (the engine). The cloud portal has its own 27 tests,
run automatically on GitHub every night along with a security scan of both programs.

## If something goes wrong

- **"Cannot connect to the Docker daemon"**: Docker Desktop isn't running. Open it and try again.
- **Viewer page won't load**: run `scripts/preview-local.sh serve`, then open http://127.0.0.1:8765/
- **Need fresh antivirus signatures**: run `build` again. Signatures are baked into the box when it's built.
  On GitHub, a nightly job does this automatically (Actions tab → nightly-image).

## The old version (v1)

v1 was a throwaway Windows computer in Azure, run with `scripts/poc.sh` (its Terraform is archived in
`terraform/v1/`). It's kept for reference and is torn down.
Its run steps are in `docs/v1/how-to.md`.
