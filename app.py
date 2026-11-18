from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, random, ipaddress
from collections import Counter

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "security_monitor.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-development-secret-key")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def log_event(conn, event, details, source_ip="system", severity="INFO"):
    conn.execute("""INSERT INTO logs(timestamp,event,source_ip,details,severity)
                    VALUES(?,?,?,?,?)""",
                 (datetime.now().isoformat(timespec="seconds"), event, source_ip, details, severity))

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rules(
          id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT NOT NULL DEFAULT '*',
          destination_ip TEXT NOT NULL DEFAULT '*', port INTEGER NOT NULL DEFAULT 0,
          protocol TEXT NOT NULL DEFAULT 'ANY', action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK')),
          enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS traffic(
          id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
          port INTEGER NOT NULL, protocol TEXT NOT NULL, traffic_type TEXT NOT NULL,
          access_status TEXT NOT NULL, timestamp TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0,
          reason TEXT NOT NULL DEFAULT 'Default policy');
        CREATE TABLE IF NOT EXISTS alerts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT NOT NULL, alert_type TEXT NOT NULL,
          severity TEXT NOT NULL, description TEXT NOT NULL, timestamp TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Open');
        CREATE TABLE IF NOT EXISTS logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event TEXT NOT NULL,
          source_ip TEXT NOT NULL, details TEXT NOT NULL, severity TEXT NOT NULL);
        """)
        if not c.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                      ("admin", generate_password_hash("admin123")))
        if c.execute("SELECT COUNT(*) n FROM rules").fetchone()["n"] == 0:
            defaults = [
              ("*","*",22,"TCP","BLOCK",1), ("*","*",23,"TCP","BLOCK",1),
              ("*","*",80,"TCP","ALLOW",1), ("*","*",443,"TCP","ALLOW",1),
              ("*","*",53,"UDP","ALLOW",1)]
            for s,d,p,proto,act,en in defaults:
                c.execute("INSERT INTO rules(source_ip,destination_ip,port,protocol,action,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
                          (s,d,p,proto,act,en,datetime.now().isoformat(timespec="seconds")))
            log_event(c,"SYSTEM","Default firewall rules initialized")
        if c.execute("SELECT COUNT(*) n FROM traffic").fetchone()["n"] == 0:
            for i in range(36):
                src = random.choice(["192.168.1.10","192.168.1.25","10.0.0.8","203.0.113.45","198.51.100.22"])
                dst = random.choice(["192.168.1.1","10.0.0.20","203.0.113.8"])
                port = random.choice([22,53,80,443,8080,3389,23,5000])
                proto = random.choice(["TCP","TCP","UDP"])
                typ = random.choice(["Incoming","Outgoing"])
                status, reason = evaluate_rules(c,src,dst,port,proto)
                c.execute("""INSERT INTO traffic(source_ip,destination_ip,port,protocol,traffic_type,
                          access_status,timestamp,bytes,reason) VALUES(?,?,?,?,?,?,?,?,?)""",
                          (src,dst,port,proto,typ,status,(datetime.now()-timedelta(minutes=random.randint(1,180))).isoformat(timespec="seconds"),random.randint(400,90000),reason))
            log_event(c,"SYSTEM","Sample simulated network traffic loaded")

def ip_matches(rule_ip, actual):
    if rule_ip == "*": return True
    try:
        return ipaddress.ip_address(actual) in ipaddress.ip_network(rule_ip, strict=False)
    except ValueError:
        return rule_ip == actual

def evaluate_rules(conn, src, dst, port, protocol):
    rules = conn.execute("SELECT * FROM rules WHERE enabled=1 ORDER BY id").fetchall()
    for r in rules:
        if (ip_matches(r["source_ip"],src) and ip_matches(r["destination_ip"],dst)
            and (r["port"] == 0 or r["port"] == port)
            and (r["protocol"] == "ANY" or r["protocol"] == protocol)):
            return ("ALLOWED" if r["action"] == "ALLOW" else "BLOCKED"), f"Matched firewall rule #{r['id']}"
    return "ALLOWED", "Default policy (no matching rule)"

def alert(conn, src, kind, severity, description):
    # Avoid duplicate open alerts of the same type/source in a short period
    recent = conn.execute("""SELECT id FROM alerts WHERE source_ip=? AND alert_type=? AND status='Open'
                             AND timestamp >= ?""",
                          (src,kind,(datetime.now()-timedelta(minutes=10)).isoformat())).fetchone()
    if not recent:
        conn.execute("INSERT INTO alerts(source_ip,alert_type,severity,description,timestamp,status) VALUES(?,?,?,?,?,'Open')",
                     (src,kind,severity,description,datetime.now().isoformat(timespec="seconds")))
        log_event(conn,"SECURITY ALERT",description,src,severity)

def analyze_source(conn, src):
    since = (datetime.now()-timedelta(minutes=2)).isoformat()
    rows = conn.execute("SELECT port,access_status FROM traffic WHERE source_ip=? AND timestamp>=?",(src,since)).fetchall()
    attempts = len(rows)
    failed = sum(1 for r in rows if r["access_status"]=="BLOCKED")
    ports = len(set(r["port"] for r in rows))
    if attempts >= 18:
        alert(conn,src,"Excessive connection requests","CRITICAL",f"{attempts} connection attempts in two minutes; possible DoS activity.")
    elif attempts >= 10:
        alert(conn,src,"High connection rate","HIGH",f"{attempts} connection attempts in two minutes.")
    if ports >= 8:
        alert(conn,src,"Possible port scan","HIGH",f"Contacted {ports} distinct destination ports in two minutes.")
    if failed >= 6:
        alert(conn,src,"Repeated blocked connections","MEDIUM",f"{failed} blocked attempts detected in two minutes.")
    unusual = conn.execute("SELECT 1 FROM traffic WHERE source_ip=? AND port IN (23,3389,4444,31337) AND timestamp>=? LIMIT 1",(src,since)).fetchone()
    if unusual:
        alert(conn,src,"Unusual port activity","MEDIUM","Traffic targeted a port commonly associated with remote administration or suspicious services.")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"): return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with db() as c:
            user = c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if user and check_password_hash(user["password_hash"],password):
            session["user"] = username
            with db() as c: log_event(c,"LOGIN",f"Administrator {username} logged in")
            return redirect(url_for("index"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if session.get("user"):
        with db() as c: log_event(c,"LOGOUT",f"Administrator {session['user']} logged out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session["user"])

@app.get("/api/dashboard")
@login_required
def dashboard():
    with db() as c:
        total = c.execute("SELECT COUNT(*) n FROM traffic").fetchone()["n"]
        allowed = c.execute("SELECT COUNT(*) n FROM traffic WHERE access_status='ALLOWED'").fetchone()["n"]
        blocked = c.execute("SELECT COUNT(*) n FROM traffic WHERE access_status='BLOCKED'").fetchone()["n"]
        suspicious = c.execute("SELECT COUNT(DISTINCT source_ip) n FROM alerts WHERE status='Open'").fetchone()["n"]
        rules = c.execute("SELECT COUNT(*) n FROM rules WHERE enabled=1").fetchone()["n"]
        alerts = c.execute("SELECT COUNT(*) n FROM alerts WHERE status='Open'").fetchone()["n"]
        rows = c.execute("SELECT traffic_type,COUNT(*) n FROM traffic GROUP BY traffic_type").fetchall()
        directions = {r["traffic_type"]:r["n"] for r in rows}
        rows = c.execute("SELECT protocol,COUNT(*) n FROM traffic GROUP BY protocol").fetchall()
        protocols = {r["protocol"]:r["n"] for r in rows}
        history = c.execute("""SELECT substr(timestamp,1,13) hour, COUNT(*) n FROM traffic
                               WHERE timestamp>=? GROUP BY hour ORDER BY hour""",
                            ((datetime.now()-timedelta(hours=12)).isoformat(),)).fetchall()
        return jsonify({"total":total,"allowed":allowed,"blocked":blocked,"suspicious":suspicious,
          "rules":rules,"alerts":alerts,"incoming":directions.get("Incoming",0),"outgoing":directions.get("Outgoing",0),
          "tcp":protocols.get("TCP",0),"udp":protocols.get("UDP",0),
          "history":{"labels":[r["hour"].replace("T"," ") for r in history],"values":[r["n"] for r in history]}})

@app.get("/api/traffic")
@login_required
def traffic():
    q = request.args.get("q","").strip()
    protocol = request.args.get("protocol","")
    status = request.args.get("status","")
    sql = "SELECT * FROM traffic WHERE 1=1"; args=[]
    if q: sql += " AND (source_ip LIKE ? OR destination_ip LIKE ?)"; args += [f"%{q}%",f"%{q}%"]
    if protocol in ("TCP","UDP"): sql += " AND protocol=?"; args.append(protocol)
    if status in ("ALLOWED","BLOCKED"): sql += " AND access_status=?"; args.append(status)
    with db() as c: rows=c.execute(sql+" ORDER BY id DESC LIMIT 500",args).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/rules",methods=["GET","POST"])
@login_required
def rules():
    if request.method=="GET":
        with db() as c: rows=c.execute("SELECT * FROM rules ORDER BY id DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    data=request.get_json(force=True)
    err=validate_rule(data)
    if err: return jsonify(error=err),400
    with db() as c:
        cur=c.execute("""INSERT INTO rules(source_ip,destination_ip,port,protocol,action,enabled,created_at)
                         VALUES(?,?,?,?,?,?,?)""",(data["source_ip"],data["destination_ip"],int(data["port"]),data["protocol"],data["action"],1,datetime.now().isoformat(timespec="seconds")))
        log_event(c,"FIREWALL RULE ADDED",f"Rule #{cur.lastrowid}: {data['action']} {data['protocol']} port {data['port']}")
    return jsonify(ok=True,id=cur.lastrowid)

def validate_rule(d):
    try:
        for key in ("source_ip","destination_ip"):
            value=d.get(key,"*").strip()
            if value!="*": ipaddress.ip_network(value,strict=False)
        port=int(d.get("port",0))
        if not 0<=port<=65535: return "Port must be between 0 and 65535 (0 means any port)."
        if d.get("protocol") not in ("TCP","UDP","ANY"): return "Protocol must be TCP, UDP, or ANY."
        if d.get("action") not in ("ALLOW","BLOCK"): return "Action must be ALLOW or BLOCK."
    except Exception: return "Enter valid IP addresses or CIDR ranges."
    return None

@app.route("/api/rules/<int:rid>",methods=["PUT","DELETE"])
@login_required
def rule_item(rid):
    with db() as c:
        row=c.execute("SELECT * FROM rules WHERE id=?",(rid,)).fetchone()
        if not row: return jsonify(error="Rule not found"),404
        if request.method=="DELETE":
            c.execute("DELETE FROM rules WHERE id=?",(rid,))
            log_event(c,"FIREWALL RULE DELETED",f"Rule #{rid} deleted")
            return jsonify(ok=True)
        d=request.get_json(force=True); err=validate_rule(d)
        if err: return jsonify(error=err),400
        enabled=1 if d.get("enabled",True) else 0
        c.execute("""UPDATE rules SET source_ip=?,destination_ip=?,port=?,protocol=?,action=?,enabled=? WHERE id=?""",
          (d["source_ip"],d["destination_ip"],int(d["port"]),d["protocol"],d["action"],enabled,rid))
        log_event(c,"FIREWALL RULE UPDATED",f"Rule #{rid} updated")
    return jsonify(ok=True)

@app.get("/api/alerts")
@login_required
def alerts():
    with db() as c: rows=c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 300").fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/alerts/<int:aid>/resolve")
@login_required
def resolve_alert(aid):
    with db() as c:
        c.execute("UPDATE alerts SET status='Resolved' WHERE id=?",(aid,))
        log_event(c,"ALERT RESOLVED",f"Alert #{aid} marked resolved")
    return jsonify(ok=True)

@app.get("/api/logs")
@login_required
def logs():
    q=request.args.get("q","").strip()
    with db() as c:
        rows=c.execute("""SELECT * FROM logs WHERE event LIKE ? OR source_ip LIKE ? OR details LIKE ?
                           ORDER BY id DESC LIMIT 500""",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/suspicious")
@login_required
def suspicious():
    with db() as c:
        rows=c.execute("""SELECT source_ip,COUNT(*) attempts,
          SUM(CASE WHEN access_status='BLOCKED' THEN 1 ELSE 0 END) blocked,
          COUNT(DISTINCT port) ports,MAX(timestamp) last_seen
          FROM traffic WHERE timestamp>=? GROUP BY source_ip
          HAVING attempts>=5 OR ports>=4 OR blocked>=3 ORDER BY attempts DESC""",
          ((datetime.now()-timedelta(hours=24)).isoformat(),)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/simulate")
@login_required
def simulate():
    with db() as c:
        src=random.choice(["192.168.1.10","192.168.1.25","10.0.0.8","203.0.113.45","198.51.100.22","198.51.100.77"])
        dst=random.choice(["192.168.1.1","10.0.0.20","203.0.113.8"])
        # Occasionally simulate scanning / bursts to demonstrate detections.
        burst=random.random()<0.16
        port=random.choice([21,22,23,53,80,443,445,3389,4444,8080,9000]) if burst else random.choice([53,80,443,8080,22])
        proto=random.choice(["TCP","UDP"])
        status,reason=evaluate_rules(c,src,dst,port,proto)
        c.execute("""INSERT INTO traffic(source_ip,destination_ip,port,protocol,traffic_type,access_status,timestamp,bytes,reason)
                     VALUES(?,?,?,?,?,?,?,?,?)""",(src,dst,port,proto,random.choice(["Incoming","Outgoing"]),status,datetime.now().isoformat(timespec="seconds"),random.randint(500,120000),reason))
        log_event(c,"TRAFFIC "+status,f"{src} -> {dst}:{port}/{proto} ({reason})",src,"WARNING" if status=="BLOCKED" else "INFO")
        analyze_source(c,src)
    return jsonify(ok=True,source_ip=src,status=status)

@app.post("/api/traffic")
@login_required
def add_traffic():
    d=request.get_json(force=True)
    try:
        src=d["source_ip"]; dst=d["destination_ip"]; port=int(d["port"]); proto=d["protocol"]
        ipaddress.ip_address(src); ipaddress.ip_address(dst)
        if not 1<=port<=65535 or proto not in ("TCP","UDP"): raise ValueError()
    except Exception: return jsonify(error="Provide valid source/destination IPs, port, and TCP/UDP protocol."),400
    with db() as c:
        status,reason=evaluate_rules(c,src,dst,port,proto)
        c.execute("""INSERT INTO traffic(source_ip,destination_ip,port,protocol,traffic_type,access_status,timestamp,bytes,reason)
                     VALUES(?,?,?,?,?,?,?,?,?)""",(src,dst,port,proto,d.get("traffic_type","Incoming"),status,datetime.now().isoformat(timespec="seconds"),int(d.get("bytes",1024)),reason))
        log_event(c,"TRAFFIC "+status,f"{src} -> {dst}:{port}/{proto} ({reason})",src)
        analyze_source(c,src)
    return jsonify(ok=True,status=status,reason=reason)

@app.get("/api/settings")
@login_required
def settings():
    return jsonify({"simulation":"enabled","refresh_seconds":5,"capture":"disabled","note":"Demo uses simulated traffic only. No packet capture or host firewall changes are performed."})

init_db()
if __name__ == "__main__":
    app.run(host="127.0.0.1",port=5000,debug=True)
