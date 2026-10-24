#!/usr/bin/env python3
"""
Records the ~3 minute BlueWatch demo video from the running lab (no screen-recorder needed).

Drives headless Edge through the story, burns the captions into the page, hides dev-only items on
screen (nothing is removed from the code), saves timestamped frames and encodes an MP4 with ffmpeg.
Also writes the captions as an .srt file and a timed Markdown script for a voice-over.

Prepare fresh data first (see demo/README in DEMO_RUN.md), then:

    python demo/record_video.py --out ../bluewatch-mobile/video
"""

import argparse
import base64
import json
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import imageio_ffmpeg
import requests
import websocket

BASE_URL = "http://127.0.0.1:5000"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
W, H = 1280, 720
VICTIM = "George Clark"
SIDELOADED = {"SYSTEM_ALERT_WINDOW": 1, "BIND_ACCESSIBILITY_SERVICE": 1, "RECEIVE_SMS": 1, "READ_SMS": 1,
              "SEND_SMS": 1, "BIND_NOTIFICATION_LISTENER_SERVICE": 1, "RECEIVE_BOOT_COMPLETED": 1,
              "REQUEST_INSTALL_PACKAGES": 1, "READ_PHONE_STATE": 1, "READ_CONTACTS": 1, "INTERNET": 1,
              "dangerous": 11, "nr_permissions": 22, "total_perm": 24, "NrServices": 5, "NrIntReceiversActions": 6}

# Dev-only items hidden on screen for the recording (they stay in the product).
HIDE_CSS = """
.topnav a[href*='5601'], a[href*='5601'] { display: none !important; }
details.help { display: none !important; }
#samples, #samples ~ *, .card:has(#samples), .card:has(#adhoc-perms) { display: none !important; }
#bw-cap { position: fixed; left: 50%; bottom: 22px; transform: translateX(-50%); z-index: 99999;
  max-width: 1080px; width: max-content; background: rgba(17,18,20,.9); color: #fff; padding: 12px 20px;
  border-radius: 12px; font: 500 21px/1.35 Inter, 'Segoe UI', system-ui, sans-serif; text-align: center;
  box-shadow: 0 6px 24px rgba(0,0,0,.25); }
#bw-tag { position: fixed; right: 14px; top: 84px; z-index: 99999; background: #fff4d6; color: #6b4b00;
  font: 600 12px 'Segoe UI', system-ui, sans-serif; padding: 4px 10px; border-radius: 999px; }
.bw-hl { outline: 3px solid #eb6834 !important; outline-offset: 4px; border-radius: 10px; }
"""

TITLE_HTML = """<!doctype html><meta charset=utf-8><body style="margin:0;height:100vh;display:grid;place-items:center;
background:#111214;color:#fff;font-family:'Segoe UI',system-ui,sans-serif"><div style="text-align:center;max-width:900px">
<div style="display:inline-flex;gap:12px;align-items:center;font-size:20px;color:#9fc3f2;font-weight:600">
<span style="width:34px;height:34px;border-radius:9px;background:#2a78d6;display:inline-block"></span>BlueWatch Mobile</div>
<h1 style="font-size:50px;line-height:1.1;margin:22px 0 14px">{title}</h1>
<p style="font-size:22px;color:#c9ccd1;margin:0">{sub}</p></div>"""


class Recorder:
    def __init__(self, frames_dir):
        self.frames_dir = frames_dir
        self.frames = []          # (path, t)
        self.captions = []        # (t, text)
        self.t0 = None
        self.n = 0
        self.caption = ""

    def start(self):
        profile = tempfile.mkdtemp()
        self.proc = subprocess.Popen([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                                      "--remote-debugging-port=9334", f"--user-data-dir={profile}", "about:blank"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            try:
                tabs = requests.get("http://127.0.0.1:9334/json", timeout=1).json()
                break
            except requests.RequestException:
                time.sleep(0.5)
        self.ws = websocket.create_connection(next(t for t in tabs if t["type"] == "page")["webSocketDebuggerUrl"],
                                              timeout=60)
        self.cdp("Page.enable")
        self.cdp("Emulation.setDeviceMetricsOverride", width=W, height=H, deviceScaleFactor=1, mobile=False)

    def stop(self):
        self.ws.close()
        self.proc.terminate()

    def cdp(self, method, **params):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.n:
                return m.get("result", {})

    def js(self, expr):
        return self.cdp("Runtime.evaluate", expression=expr, awaitPromise=True,
                        returnByValue=True).get("result", {}).get("value")

    def snap(self):
        data = self.cdp("Page.captureScreenshot", format="jpeg", quality=85)["data"]
        if self.t0 is None:
            self.t0 = time.time()
        p = self.frames_dir / f"f{len(self.frames):05d}.jpg"
        p.write_bytes(base64.b64decode(data))
        self.frames.append((p, time.time() - self.t0))

    def dress(self):
        """Inject the caption bar, the lab tag and the hide-list after every page load."""
        self.js(f"""(() => {{
            if (!document.getElementById('bw-css')) {{
                const s = document.createElement('style'); s.id = 'bw-css'; s.textContent = {json.dumps(HIDE_CSS)};
                document.head.appendChild(s);
                const t = document.createElement('div'); t.id = 'bw-tag'; t.textContent = 'Lab demo · simulated bank data';
                document.body.appendChild(t);
                const c = document.createElement('div'); c.id = 'bw-cap'; document.body.appendChild(c);
            }}
            const c = document.getElementById('bw-cap'); c.textContent = {json.dumps(self.caption)};
            c.style.display = {json.dumps('block' if self.caption else 'none')};
        }})()""")

    def go(self, url, settle=2.5, tag=True):
        self.cdp("Page.navigate", url=url)
        end = time.time() + settle
        while time.time() < end:
            time.sleep(0.15)
            if tag and self.js("document.readyState") == "complete":
                self.dress()
            self.snap()

    def say(self, text, hold):
        self.caption = text
        self.dress()
        if self.t0 is not None:
            self.captions.append((time.time() - self.t0, text))
        else:
            self.captions.append((0.0, text))
        self.hold(hold)

    def hold(self, seconds, each=None):
        end = time.time() + seconds
        while time.time() < end:
            if each:
                each(1 - (end - time.time()) / seconds)
            self.snap()

    def scroll(self, y, seconds, box="window"):
        start = self.js("window.scrollY" if box == "window" else f"document.querySelector('{box}').scrollTop") or 0
        target = y if isinstance(y, (int, float)) else self.js(
            f"(() => {{ const e = document.querySelector({json.dumps(y)}); if (!e) return 0;"
            + ("return e.getBoundingClientRect().top + window.scrollY - 90; })()" if box == "window" else
               f"const b = document.querySelector('{box}'); return e.getBoundingClientRect().top - b.getBoundingClientRect().top + b.scrollTop - 20; }})()"))

        def step(f):
            f = min(1.0, max(0.0, f))
            ease = f * f * (3 - 2 * f)
            pos = start + (target - start) * ease
            self.js(f"window.scrollTo(0, {pos})" if box == "window" else
                    f"document.querySelector('{box}').scrollTop = {pos}")
        self.hold(seconds, step)

    def highlight(self, selector):
        self.js(f"document.querySelectorAll('.bw-hl').forEach(e => e.classList.remove('bw-hl'));"
                f"(document.querySelector({json.dumps(selector)}) || document.body).classList.add('bw-hl')" if selector
                else "document.querySelectorAll('.bw-hl').forEach(e => e.classList.remove('bw-hl'))")

    def title(self, title, sub, seconds, caption=""):
        html = TITLE_HTML.format(title=title, sub=sub)
        self.cdp("Page.navigate", url="data:text/html;base64," + base64.b64encode(html.encode()).decode())
        time.sleep(0.4)
        self.caption = caption
        self.say(caption, seconds) if caption else self.hold(seconds)

    def encode(self, out_mp4):
        lst = self.frames_dir / "frames.txt"
        lines = []
        for (p, t), nxt in zip(self.frames, self.frames[1:] + [(None, self.frames[-1][1] + 0.5)]):
            lines += [f"file '{p.as_posix()}'", f"duration {max(0.01, nxt[1] - t):.3f}"]
        lines.append(f"file '{self.frames[-1][0].as_posix()}'")
        lst.write_text("\n".join(lines), encoding="utf-8")
        subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
                        "-i", str(lst), "-vf", "fps=25,format=yuv420p", "-c:v", "libx264", "-preset", "medium",
                        "-crf", "20", "-movflags", "+faststart", str(out_mp4)], check=True)

    def write_script(self, srt_path, md_path):
        total = self.frames[-1][1]
        cues = [(t, (self.captions[i + 1][0] if i + 1 < len(self.captions) else total), text)
                for i, (t, text) in enumerate(self.captions) if text]

        def ts(s):
            return f"{int(s // 3600):02d}:{int(s % 3600 // 60):02d}:{int(s % 60):02d},{int(s * 1000 % 1000):03d}"
        srt_path.write_text("\n".join(f"{i}\n{ts(a)} --> {ts(b)}\n{text}\n" for i, (a, b, text) in enumerate(cues, 1)),
                            encoding="utf-8")
        md = ["# BlueWatch demo video: voice-over script", "",
              f"Length {total:.0f} s. Read each line when its time comes up; the captions in the video match.", "",
              "| Time | Say |", "|---|---|"]
        md += [f"| {int(a // 60)}:{int(a % 60):02d} | {text} |" for a, _, text in cues]
        md_path.write_text("\n".join(md) + "\n", encoding="utf-8")


def api():
    s = requests.Session()
    s.post(f"{BASE_URL}/login", data={"username": "analyst", "password": "password123"}, timeout=30)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    frames = Path(tempfile.mkdtemp(prefix="bw-frames-"))

    s = api()
    s.get(f"{BASE_URL}/api/mobile/model", timeout=300)        # warm the classifier before filming
    busy = threading.Event()

    def payments():                                            # live money movement while the home page is up
        while not busy.is_set():
            try:
                s.post(f"{BASE_URL}/api/bank/simulate", json={"n": 2}, timeout=20)
            except requests.RequestException:
                pass
            busy.wait(3)

    r = Recorder(frames)
    r.start()
    try:
        r.go(f"{BASE_URL}/login", 1.5, tag=False)
        r.js("document.getElementById('username').value='analyst';document.getElementById('password').value='password123';"
             "document.querySelector('form').submit()")
        time.sleep(2.5)
        r.frames.clear()
        r.t0 = None

        # 1. Title
        r.title("Catch Android banking malware<br>before the money leaves",
                "YES AI Hackathon 2026 · Challenge 3 · BlueWatch Mobile", 9,
                "BlueWatch helps a bank's security team spot Android banking malware, and the fraud that follows it.")

        # 2. The bank is live
        threading.Thread(target=payments, daemon=True).start()
        r.caption = "This is SecureBank's staff app. Payments move between customer accounts in real time (simulated lab data)."
        r.go(f"{BASE_URL}/dashboard", 2)
        r.say(r.caption, 9)
        r.highlight(".card:has(#live-chip)")
        r.say("Every payment is checked as it happens. Most are ordinary: rent, groceries, salaries.", 9)

        # 3. The attack
        r.highlight(None)
        r.say(f"Now: {VICTIM} installs a 'FlashPlayer update' from outside the Play Store. "
              "It is a banking trojan.", 7)
        result = {}

        def attack():
            result.update(s.post(f"{BASE_URL}/api/bank/scenario/compromised-device", json={"victim": VICTIM},
                                 timeout=180).json())
        th = threading.Thread(target=attack)
        th.start()
        r.say("Minutes later R38,500 leaves his account for a new payee.", 6)
        th.join(60)
        busy.set()
        r.js("loadBank()")
        r.hold(1.2)
        r.highlight("#bank-feed > *:first-child, .feed > *:first-child")
        r.say("BlueWatch flags it, and says why: the risky app on his phone, and 32 critical known flaws "
              "in his Android version (US NVD).", 11)
        iid = result.get("incident_id")

        # start the AI case brief now; it runs on a local model while we keep filming
        brief = {}

        def write_brief():
            try:
                inc = s.get(f"{BASE_URL}/api/soc/incidents/{iid}", timeout=30).json()
                brief.update(s.post(f"{BASE_URL}/api/mobile/brief", json={"assessment_id": inc["assessment_id"]},
                                    timeout=200).json())
            except (requests.RequestException, KeyError):
                pass
        bth = threading.Thread(target=write_brief, daemon=True)
        bth.start()

        # 4. Why the app was flagged
        r.highlight(None)
        r.caption = "Why was the app flagged? A model trained on 475 measured behaviours of real Android apps scores it."
        r.go(f"{BASE_URL}/mobile-risk", 2)
        r.js(f"document.getElementById('result').scrollIntoView();"
             f"run({{sample_id: 'FlashPlayer Update.apk', features: {json.dumps(SIDELOADED)}}})")
        r.hold(1.5)
        r.scroll("#result", 1.2)
        r.say(r.caption, 7)
        r.say("Score 0.78, above the 0.5 line, so a person should check it. It never blocks a customer by itself.", 8)
        r.scroll("#result table, #result .profile, #result h4", 2)
        r.say("It explains itself in plain words: screen overlays, accessibility abuse, reading SMS one-time passwords.", 9)
        r.scroll("#model", 2.5)
        r.say("Tested honestly on apps it never saw: 97% of malware caught, 93% of brand-new families. "
              "But 49% false alarms on newer safe apps, which is why a person decides.", 12)

        # 5. Security Center
        r.caption = "The Security Center turns warning signs into cases: password guessing, insiders copying data, risky apps."
        r.go(f"{BASE_URL}/security", 3)
        r.say(r.caption, 8)
        r.highlight(".insight, .card.dark, .card:has(.insight)")
        r.say("It spots patterns people miss: here one staff account viewed almost every customer record.", 8)
        r.highlight(None)

        # 6. The case, worked by the team
        if iid:
            s.patch(f"{BASE_URL}/api/soc/incidents/{iid}", json={"assignee": "Stacey-Lee", "status": "investigating",
                                                                  "add_tag": "escalate"})
            s.post(f"{BASE_URL}/api/soc/incidents/{iid}/tasks", json={"assignee": "Liso", "text":
                   "Call the customer on the number we hold (not one from the app) and walk them through removing it."})
            s.post(f"{BASE_URL}/api/soc/incidents/{iid}/tasks", json={"assignee": "analyst", "text":
                   "Hold the R38,500 payment and check the new payee against mule lists."})
            s.post(f"{BASE_URL}/api/soc/incidents/{iid}/review", json={"reviewer": "jdoe", "action": "request"})
            bth.join(5)
            if brief.get("summary"):
                src = "a local AI model, fact-checked" if brief.get("generated_by") == "ai" else "the fact-checked template"
                s.post(f"{BASE_URL}/api/soc/incidents/{iid}/notes",
                       json={"text": f"Case brief ({src}): {brief['summary']}"[:2000]})
        r.caption = "BlueWatch's triage playbook routes the case: Stacey-Lee handles it, Liso calls the customer, the payment is held."
        r.go(f"{BASE_URL}/security/incidents#incident-{iid}", 3)
        r.say(r.caption, 9)
        r.scroll(".dsec", 2, box=".drawer-body")
        r.say("A second person must review before it is closed, and nobody can handle or review a case about themselves.", 9)
        r.scroll(".timeline, .dsec:last-child", 2.5, box=".drawer-body")
        r.say("Case briefs come from a local AI model and are fact-checked. If one overstates, BlueWatch uses a plain template.", 9)

        # 7. Close
        r.title("Decision support, not auto-blocking",
                "Real: the model, scores, rules, NVD data · Simulated: the bank, customers, payments", 10,
                "BlueWatch Mobile: catch the app, explain the risk, and let the team act fast, with people in charge.")
    finally:
        busy.set()
        r.stop()

    r.encode(out / "bluewatch_demo.mp4")
    r.write_script(out / "bluewatch_demo.srt", out / "VOICEOVER_SCRIPT.md")
    print(f"video: {out / 'bluewatch_demo.mp4'}  length {r.frames[-1][1]:.0f}s  frames {len(r.frames)}  incident #{iid}")
    shutil.rmtree(frames, ignore_errors=True)


if __name__ == "__main__":
    main()
