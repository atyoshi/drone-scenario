# Plan: Drone Doctor presentation

## Goal
Create a concise, visually polished presentation explaining the Drone Doctor network-emulation lab, its response paths, demonstration, and evidence limits.

## Current context / assumptions
- Audience: technically curious stakeholders with mixed networking backgrounds; 6–8 minute overview, not a training manual. This is a default, not an established user requirement.
- Deliverable: `docs/drone-doctor-slides.html`, an offline, self-contained browser presentation. HTML is the simplest portable default; confirm with the user before substituting PowerPoint or adding speaker notes.
- Authoritative current sources: `README.md`, `scenario.py`, `doctor.py`, `guard.py`, `policy.py`, `services.py`, and `docs/Drone Doctor CORE Walkthrough.docx`. Archives are historical; do not source claims from them. The walkthrough is already modified: preserve it untouched.
- `README.md` reports that a later live CORE/Docker firewall case passed its checks; other cases and real llama.cpp inference were not verified live. This is a documented prior result, not a test performed while building the deck.
- The runnable topology has four drone containers, a separate router and client container, and one CORE wireless LAN node. The XML file previews the topology; the runner creates and provisions a separate session. The emulated links are disconnected from the physical network; CORE Docker nodes nevertheless have privileges needed for emulation.

## Architecture / proposed approach
Use a **Decide/Learn** slide deck: one takeaway per slide, with a precise topology diagram and short, presenter-friendly copy. Implement a single local HTML document with embedded CSS, inline SVG, and minimal vanilla JavaScript—no build, remote assets, or runtime dependency. The artifact must work offline and print as one 16:9 slide per page, with navigation and a visible counter in screen mode.

## Design specification
- Canvas: 1920×1080 logical coordinates, scale proportionally to fit the browser viewport; provide a simple print stylesheet that displays every slide without controls.
- Palette: one warm off-white background (`#F4F1E8`), near-black ink (`#172322`), muted gray-green (`#52635E`), and a single deep teal accent (`#087E73`). Use amber (`#A75C16`) only to distinguish caution/limits. Solid colors, no gradients or glass effects.
- Typography: `Georgia, serif` for short slide headlines; `Arial, sans-serif` for body; `monospace` only for commands. Headline 70–84 px, body at least 32 px, citations at least 24 px in the logical canvas. Left-align copy; generous whitespace; no rounded-card grids, arbitrary statistics, or decorative stock imagery.
- Persistent lower edge: section label at left, `current / total` and Previous/Next buttons at right. The controls must have accessible names, visible keyboard focus, and disabled states at boundaries. ArrowLeft/ArrowRight, PageUp/PageDown, Home, and End navigate. Store the slide index in `localStorage`, guarded with `try/catch` so file:// or privacy restrictions cannot break the deck. Present the first slide if the stored index is invalid. Do not intercept keyboard shortcuts while focus is in an interactive control.
- Use semantic slide headings and stable slide IDs. Only the current slide is visible and exposed to assistive technology in screen mode; all slides are visible in print. Avoid animation unless reduced motion is respected.

## Step-by-step tasks

### 1. Reconfirm facts and preserve existing work (2–5 minutes)
1. From the workspace root, run:
   ```sh
   git status --short
   git branch --show-current
   python3 -c "from pathlib import Path; print('\n'.join(f'{p}: {Path(p).exists()}' for p in ['README.md','scenario.py','doctor.py','guard.py','policy.py','services.py','docs/Drone Doctor CORE Walkthrough.docx']))"
   ```
   Expected: every listed source prints `True`; `git status` may show the pre-existing modified walkthrough. Do not reset or overwrite it. Read `README.md` and relevant code again if they have changed since the plan was written; update claims to match current code.
2. Do not start CORE, build Docker images, or run the scenario merely to construct the deck; live results would require a properly provisioned separate environment.

### 2. Draft the eight slide compositions and copy (5-minute increments)
Create `docs/drone-doctor-slides.html`. Use exactly the following slide order and copy as the starting script; small edits for fit are fine if the meaning remains intact. Use the cited files as unobtrusive footer references, not invented external sources. Do not quote numerical outcomes from a run that has not been supplied.

1. `title` — **Drone Doctor** / “An isolated lab for detection, containment, and recovery” / “CORE network emulation · four drones · controlled faults”. Compose an editorial title with a small abstract network motif, not fake aircraft photography. Source: `README.md`.
2. `purpose` — **Protect the mission while responding** / “Observe repeated external connection attempts” / “Choose a scoped, temporary response” / “Keep mission health and peer checks independent”. Show three short sequential lines with a quiet rule underneath. Source: `README.md`, `doctor.py`.
3. `topology` — **One external path, one mission network**. Draw an accessible inline SVG with text labels and a `title`/`desc`: `Lab client → Router → Drone 1 :80`; `Drone 1`, `Drone 2`, `Drone 3`, and `Drone 4` all connect to `Mission WLAN · mutual TLS :443`. Label the edge path “emulated, isolated”; do not depict the router as a physical Internet gateway or claim all drones receive external traffic. Source: `scenario.py:193–265`, `services.py:88–94`.
4. `response` — **Evidence drives a bounded response** / “Suricata observes external TCP attempts” / “3 distinct attempts in 10 seconds trigger a decision” / “Firewall: source-scoped block for 30 seconds” / “Decoy: 60-second inspected path when prerequisites hold”. Use a left-to-right evidence → policy → action flow and a concise footnote: “Decoy requires enabled configuration, healthy mission service, and resource headroom.” Source: `policy.py:10–59`, `guard.py:280–325`, `README.md`.
5. `recovery` — **Recovery runs alongside containment** / “Two failed local health checks can trigger a restart; budget: two per minute” / “Peers mark status stale after three missed polls; two successes restore it” / “The firewall case moves Drone 4 out of range for eight seconds”. Use a two-lane diagram for local service and peer status. Source: `doctor.py:29–52,105–136`, `scenario.py:478–498`.
6. `cases` — **Four controlled cases**. Use four unequal horizontal rows, not feature cards: “Firewall — block, restart, and reconnect”; “Decoy — ordinary reply, test-marker drop, fail-closed behavior”; “Mixed — overlapping service crash and port 80 attempts”; “Pressure — synthetic pressure selects firewall”. Add “These are lab fixtures, not real attacks.” Source: `README.md:24–33`.
7. `demo` — **Follow the firewall case**. Show the following exact commands in a legible monospace block, with a separate prerequisite note: “On a provisioned CORE host, after building the image and passing preflight.”
   ```sh
   python3 scenario.py --case firewall --keep
   ```
   Below: “Join the printed session ID in CORE → inspect checks → read the printed `summary.json` path → delete the retained session.” Label `timeline.jsonl` and Suricata EVE as supporting evidence. Do not imply this plan ran the lab. Source: `README.md:9–35`.
8. `limits` — **What the evidence does—and does not—show**. Left: “A documented prior live firewall run passed its checks.” / “Reports contain checks, timelines, and resource measurements.” Right, visually distinguished in amber: “Other cases and real model inference were not verified live in the documented run.” / “RF, aircraft performance, power, and production readiness require separate testing.” Small closing line: “Optional local model mode validates permitted actions and falls back to rules on failure or timeout.” Source: `README.md:37–55`, walkthrough.

### 3. Implement layout and interaction (5-minute increments)
1. In `docs/drone-doctor-slides.html`, create eight semantic `<section>` elements with the exact IDs above, each with one `<h1>` or `<h2>`. Add a single `<main>` and a labeled `<nav>` with native buttons. Include a meaningful HTML `<title>` and a viewport meta tag.
2. Implement the visual system and SVG from the specification. Keep content and CSS together in the HTML file, including all fonts via local system fallbacks. Keep each slide readable at a typical 16:9 presentation viewport; do not depend on hover to reveal content.
3. Implement one `showSlide(index)` function that clamps valid indices, updates visibility/`aria-hidden`, updates the live slide counter and disabled buttons, and saves the index defensively. Wire the buttons and keyboard events to this function. Print CSS must override screen hiding and scaling; hide the navigation controls on paper. Do not add network calls or a JS framework.
4. If static validation below fails, fix `docs/drone-doctor-slides.html` and rerun it. Avoid adding a permanent test framework for this one-off artifact.

### 4. Validate structure and content (2–5 minutes)
Run this exact static check from the repository root:
```sh
python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path

class Check(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = []
        self.remote = []
        self.text = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'section':
            self.sections.append(attrs.get('id'))
        for key in ('src', 'href'):
            if attrs.get(key, '').startswith(('http://', 'https://', '//')):
                self.remote.append(attrs[key])
    def handle_data(self, data):
        self.text.append(data)

p = Path('docs/drone-doctor-slides.html')
parser = Check()
parser.feed(p.read_text(encoding='utf-8'))
assert parser.sections == ['title', 'purpose', 'topology', 'response', 'recovery', 'cases', 'demo', 'limits'], parser.sections
assert not parser.remote, parser.remote
text = ' '.join(parser.text)
for term in ('Drone Doctor', 'Suricata', 'firewall', 'Decoy', 'summary.json', 'not verified live'):
    assert term.lower() in text.lower(), term
print('PASS: 8 ordered slides, required terms, no remote assets')
PY
```
Expected: `PASS: 8 ordered slides, required terms, no remote assets`. This does not validate rendering or CSS/JS dependencies; inspect those separately. If copy changes for accuracy, adjust the exact checks rather than deleting coverage.

### 5. Browser, print, and accessibility checks (5-minute increments)
1. Open the absolute path to `docs/drone-doctor-slides.html` as a `file://` URL in a real browser. Clear or account for any prior saved index. Confirm all eight slides render with legible text, no cut-off diagram labels, no horizontal clipping, and no console errors. Inspect at 1920×1080 and 1280×720; also inspect a narrow viewport for proportional fit and reachable controls.
2. Verify Previous/Next, ArrowLeft/ArrowRight, PageUp/PageDown, Home/End, disabled first/last buttons, visible focus, and `3 / 8` counter after reaching slide three. Reload and confirm the index persists when storage is allowed. Use browser devtools to deny storage and confirm navigation still works.
3. Open print preview and verify eight 16:9 pages, one complete slide per page, with controls hidden. Test screen reader/accessibility tree: the visible slide heading and named controls are exposed; hidden slide headings are not exposed in screen mode. If the print/browser renderer is unavailable, report this explicitly; do not claim visual or print verification.
4. Review slide claims against source references; confirm no fabricated metrics, no claim of real-hardware protection or physical RF validation, and no claim that unverified cases passed. Check that the topology SVG matches `scenario.py` rather than implying the client directly reaches the mission WLAN.
5. Run `git status --short` and `git diff --check`; expected: no whitespace errors, new presentation visible, and the original walkthrough remains modified but untouched. Because the HTML file is untracked until staged, `git diff --check` does not inspect it; structural and browser checks above cover the artifact itself. Do not stage, commit, or push without an explicit user request.

## Tests / validation
- This is a presentation artifact, not an application feature; use static document assertions followed by real-browser interaction, visual, accessibility, and print checks rather than forcing unrelated unit-test infrastructure. For any nontrivial navigation bug discovered, reproduce it first in the browser, fix minimally, and repeat the exact reproduction before continuing.
- Preserve existing tests and runtime files. No existing test execution is needed to validate a new standalone document; do not represent offline tests or earlier live runs as having been run for this presentation.
- Completion requires the saved HTML, passing structural check, inspected slide visuals and navigation, and explicit disclosure of any unavailable checks. Provide the user the exact artifact path and indicate the format is HTML.

## Risks, tradeoffs, and open questions
- Audience, duration, output format, and branding were not specified; the technical mixed-audience HTML deck is a reversible default. Ask before substantial conversion to PPTX or externally branded presentation.
- File URL storage behavior and print scaling vary by browser; guarded storage and explicit print validation are required.
- The prior firewall result is a documented assertion, not newly verified evidence. Do not invent performance numbers or generalize lab results to live drones.
- The current walkthrough has user modifications; treat it as read-only. The historical archives do not represent current code.
