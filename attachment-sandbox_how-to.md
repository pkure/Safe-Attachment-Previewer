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

**Money:** $0. It all runs on this Mac. (The cloud version is planned. It costs nothing while idle, and its price
will be confirmed before anything gets built.)

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
- A file that can't be shown safely, like a program pretending to be a PDF, gets an **Escalate** card. Next step:
  look up its hash, then send it to the company's detonation sandbox if needed.

## Check that it still works

`scripts/preview-local.sh test` should end with **27 passed**.

## If something goes wrong

- **"Cannot connect to the Docker daemon"**: Docker Desktop isn't running. Open it and try again.
- **Viewer page won't load**: run `scripts/preview-local.sh serve`, then open http://127.0.0.1:8765/
- **Need fresh antivirus signatures**: run `build` again. Signatures are baked into the box when it's built.
  On GitHub, a nightly job does this automatically (Actions tab → nightly-image).

## The old version (v1)

v1 was a throwaway Windows computer in Azure, run with `scripts/poc.sh`. It's kept for reference and is torn down.
Its run steps are in `docs/v1/how-to.md`.
