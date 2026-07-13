import sqlite3
import json
import random
import os
from datetime import datetime, date

DB_PATH = os.environ.get("DB_PATH", "/data/drill.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id TEXT, source TEXT, event_type TEXT, mitre TEXT,
    alert TEXT, pivots TEXT, verdict TEXT, action TEXT,
    required_pivots TEXT, what_to_check TEXT, explanation TEXT,
    event_type_pool TEXT DEFAULT '[]',
    weight REAL DEFAULT 1.0, wrong_count INTEGER DEFAULT 0,
    seen_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER, session_id INTEGER,
    ts TEXT, verdict TEXT, action TEXT, event_type_answer TEXT,
    verdict_ok INTEGER, action_ok INTEGER, type_ok INTEGER,
    score REAL, time_taken REAL, pivots_used TEXT, timed_out INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT, size INTEGER, done INTEGER DEFAULT 0, score REAL DEFAULT 0
);
"""


def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init(per_template=20):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = conn()
    c.executescript(SCHEMA)
    n = c.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
    if n == 0:
        from . import seed_data
        rows = seed_data.generate_scenarios(per_template=per_template)
        c.executemany(
            """INSERT INTO scenarios
               (template_id, source, event_type, mitre, alert, pivots, verdict,
                action, required_pivots, what_to_check, explanation, event_type_pool)
               VALUES (:template_id,:source,:event_type,:mitre,:alert,:pivots,
                       :verdict,:action,:required_pivots,:what_to_check,:explanation,
                       :event_type_pool)""",
            rows,
        )
        c.commit()
    c.close()


def start_session(size):
    c = conn()
    cur = c.execute("INSERT INTO sessions (started, size) VALUES (?, ?)",
                    (datetime.now().isoformat(), size))
    c.commit()
    sid = cur.lastrowid
    c.close()
    return sid


def get_session(sid):
    c = conn()
    row = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    c.close()
    return dict(row) if row else None


def pick_scenario(session_id):
    """Spread templates evenly across a session: a template is never served a 2nd
    time until every template has been served once, a 3rd time until all twice, and
    so on. This keeps repeats from clustering in long sessions (>N templates). Within
    the eligible (least-seen-this-session) tier, weight by SRS weight so wrong-answered
    scenarios still surface more."""
    c = conn()
    seen = {r["t"]: r["n"] for r in c.execute(
        """SELECT s.template_id AS t, COUNT(*) AS n FROM attempts a
           JOIN scenarios s ON s.id = a.scenario_id
           WHERE a.session_id=? GROUP BY s.template_id""", (session_id,))}
    rows = c.execute("SELECT id, template_id, weight FROM scenarios").fetchall()
    min_seen = min((seen.get(r["template_id"], 0) for r in rows), default=0)
    pool = [r for r in rows if seen.get(r["template_id"], 0) == min_seen]
    weights = [r["weight"] for r in pool]
    chosen = random.choices(pool, weights=weights, k=1)[0]
    row = c.execute("SELECT * FROM scenarios WHERE id=?", (chosen["id"],)).fetchone()
    c.close()
    return dict(row)


def get_scenario(scenario_id):
    c = conn()
    row = c.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
    c.close()
    return dict(row) if row else None


def record_attempt(scenario_id, session_id, verdict, action, event_type_answer,
                   pivots_used, time_taken, timed_out):
    s = get_scenario(scenario_id)
    required = set(json.loads(s["required_pivots"]))
    used = set(pivots_used)

    verdict_ok = int(verdict == s["verdict"]) if not timed_out else 0
    action_ok = int(action == s["action"]) if not timed_out else 0
    type_ok = int(event_type_answer == s["event_type"]) if not timed_out else 0

    # scoring
    score = 0.0
    if timed_out:
        score = 0.0
    else:
        score += 50 * verdict_ok
        score += 30 * action_ok
        score += 10 * type_ok
        if verdict_ok and required.issubset(used):
            score += 10                       # evidence-backed decision
        elif verdict_ok and not required.issubset(used):
            score -= 15                       # правильный вердикт вслепую
        extra = len(used - required)
        score -= min(extra * 3, 9)            # queue-time penalty for excess pivots
        score = max(score, 0)

    # SRS weight update
    critical_miss = (s["verdict"] == "malicious" and action != "escalate")
    fully_ok = verdict_ok and action_ok and type_ok and required.issubset(used)
    if timed_out or critical_miss:
        w_mult, wrong_inc = 3.0, 1
    elif not (verdict_ok and action_ok):
        w_mult, wrong_inc = 2.0, 1
    elif fully_ok:
        w_mult, wrong_inc = 0.6, 0
    else:
        w_mult, wrong_inc = 1.2, 0

    c = conn()
    c.execute("""UPDATE scenarios SET
                 weight = MIN(MAX(weight * ?, 0.2), 4.0),
                 wrong_count = wrong_count + ?,
                 seen_count = seen_count + 1 WHERE id=?""",
              (w_mult, wrong_inc, scenario_id))
    c.execute("""INSERT INTO attempts
                 (scenario_id, session_id, ts, verdict, action, event_type_answer,
                  verdict_ok, action_ok, type_ok, score, time_taken, pivots_used, timed_out)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (scenario_id, session_id, datetime.now().isoformat(), verdict, action,
               event_type_answer, verdict_ok, action_ok, type_ok, score, time_taken,
               json.dumps(sorted(used)), int(timed_out)))
    c.execute("UPDATE sessions SET done = done + 1, score = score + ? WHERE id=?",
              (score, session_id))
    c.commit()
    c.close()
    return {"verdict_ok": verdict_ok, "action_ok": action_ok, "type_ok": type_ok,
            "score": score, "critical_miss": critical_miss,
            "missing_pivots": sorted(required - used),
            "extra_pivots": sorted(used - required)}


def stats():
    c = conn()
    out = {}
    out["total_attempts"] = c.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
    out["today"] = c.execute(
        "SELECT COUNT(*), COALESCE(AVG(score),0) FROM attempts WHERE ts LIKE ?",
        (date.today().isoformat() + "%",)).fetchone()
    out["overall"] = c.execute(
        """SELECT COALESCE(AVG(verdict_ok)*100,0), COALESCE(AVG(action_ok)*100,0),
                  COALESCE(AVG(score),0), COALESCE(AVG(time_taken),0)
           FROM attempts""").fetchone()
    out["by_source"] = c.execute(
        """SELECT s.source, COUNT(*), AVG(a.verdict_ok)*100, AVG(a.action_ok)*100,
                  AVG(a.time_taken)
           FROM attempts a JOIN scenarios s ON s.id=a.scenario_id
           GROUP BY s.source ORDER BY 3 ASC""").fetchall()
    out["by_mitre"] = c.execute(
        """SELECT s.mitre, COUNT(*), AVG(a.verdict_ok)*100
           FROM attempts a JOIN scenarios s ON s.id=a.scenario_id
           GROUP BY s.mitre ORDER BY 3 ASC LIMIT 12""").fetchall()
    out["critical_misses"] = c.execute(
        """SELECT COUNT(*) FROM attempts a JOIN scenarios s ON s.id=a.scenario_id
           WHERE s.verdict='malicious' AND a.action!='escalate'""").fetchone()[0]
    out["daily"] = c.execute(
        """SELECT substr(ts,1,10) d, COUNT(*), AVG(verdict_ok)*100, AVG(score)
           FROM attempts GROUP BY d ORDER BY d DESC LIMIT 14""").fetchall()
    out["weakest"] = c.execute(
        """SELECT s.template_id, s.event_type, s.source, s.wrong_count, s.weight
           FROM scenarios s WHERE s.wrong_count > 0
           GROUP BY s.template_id ORDER BY SUM(s.wrong_count) DESC LIMIT 8""").fetchall()
    c.close()
    return out
