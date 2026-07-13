import json
import os
import random

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from . import db
from .seed_data import EVENT_TYPE_POOL
from .glossary import annotate, reference_data

app = FastAPI(title="SOC L1 Drill")
BASE = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
env = Environment(loader=FileSystemLoader(os.path.join(BASE, "templates")),
                  autoescape=True, cache_size=0)


def render(name, **ctx):
    return HTMLResponse(env.get_template(name).render(**ctx))


TIMER_SECONDS = 180

VERDICT_LABELS = {
    "false_positive": "False Positive",
    "benign": "Benign / True Positive (remediated or expected)",
    "malicious": "Malicious",
}
ACTION_LABELS = {"close": "Close", "escalate": "Escalate to L2"}
PIVOT_LABELS = {
    "related": "Related events (±30 min)",
    "asset": "Asset info",
    "user": "User / identity info",
    "reputation": "IP / hash reputation",
}

db.init(per_template=int(os.environ.get("VARIANTS_PER_TEMPLATE", "20")))


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return render("index.html", s=db.stats())


@app.post("/session/start")
def session_start(size: int = Form(20)):
    sid = db.start_session(size)
    return RedirectResponse(f"/session/{sid}/next", status_code=303)


@app.get("/session/{sid}/next", response_class=HTMLResponse)
def next_card(sid: int):
    sess = db.get_session(sid)
    if not sess:
        return RedirectResponse("/", status_code=303)
    if sess["done"] >= sess["size"]:
        return render("summary.html", sess=sess)
    sc = db.pick_scenario(sid)
    # Prefer this template's curated near-miss distractors; top up from the
    # global pool only if the template lists fewer than 3.
    try:
        pool = json.loads(sc.get("event_type_pool") or "[]")
    except (TypeError, ValueError):
        pool = []
    distractors = [e for e in pool if e != sc["event_type"]]
    if len(distractors) < 3:
        seen = set(distractors) | {sc["event_type"]}
        distractors += [e for e in EVENT_TYPE_POOL if e not in seen]
    options = random.sample(distractors, 3) + [sc["event_type"]]
    random.shuffle(options)
    return render("drill.html", sc=sc, sess=sess,
                  pivots=json.loads(sc["pivots"]),
                  pivot_labels=PIVOT_LABELS, type_options=options,
                  verdicts=VERDICT_LABELS, actions=ACTION_LABELS,
                  timer=TIMER_SECONDS, progress=sess["done"] + 1)


@app.post("/session/{sid}/answer/{scenario_id}", response_class=HTMLResponse)
def answer(sid: int, scenario_id: int,
           verdict: str = Form(""), action: str = Form(""),
           event_type: str = Form(""), pivots_used: str = Form(""),
           time_taken: float = Form(0.0), timed_out: int = Form(0)):
    used = [p for p in pivots_used.split(",") if p]
    result = db.record_attempt(scenario_id, sid, verdict, action, event_type,
                               used, time_taken, bool(timed_out))
    sc = db.get_scenario(scenario_id)
    sess = db.get_session(sid)
    return render("debrief.html", sc=sc, sess=sess, r=result,
                  your={"verdict": verdict, "action": action, "event_type": event_type},
                  verdicts=VERDICT_LABELS, actions=ACTION_LABELS,
                  pivot_labels=PIVOT_LABELS,
                  required=json.loads(sc["required_pivots"]),
                  timed_out=bool(timed_out))


@app.get("/stats", response_class=HTMLResponse)
def stats_page():
    return render("stats.html", s=db.stats())


@app.get("/study", response_class=HTMLResponse)
def study(source: str = ""):
    c = db.conn()
    if source:
        row = c.execute("SELECT * FROM scenarios WHERE source=? ORDER BY RANDOM() LIMIT 1",
                        (source,)).fetchone()
    else:
        row = c.execute("SELECT * FROM scenarios ORDER BY RANDOM() LIMIT 1").fetchone()
    c.close()
    if not row:
        return RedirectResponse("/", status_code=303)
    sc = dict(row)
    return render("study.html", sc=sc,
                  pivots=json.loads(sc["pivots"]),
                  required=json.loads(sc["required_pivots"]),
                  notes=annotate(sc["alert"]),
                  pivot_labels=PIVOT_LABELS,
                  verdicts=VERDICT_LABELS, actions=ACTION_LABELS)


@app.get("/reference", response_class=HTMLResponse)
def reference():
    return render("reference.html", sections=reference_data())
