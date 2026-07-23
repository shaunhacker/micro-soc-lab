from flask import Flask, request, jsonify, render_template_string
import sqlite3
import requests
import threading
import os
from datetime import datetime

app = Flask(__name__)
DB_FILE = "siem_soar.db"

# --- DATABASE SETUP (SIEM Log Store) ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source TEXT, event_type TEXT, ip TEXT, details TEXT, severity TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS incidents 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, log_id INT, status TEXT, vt_score TEXT, summary TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- SOAR PLAYBOOK (Async Automation Engine) ---
def run_soar_playbook(log_id, ip, event_type):
    """SOAR Engine: Enriches suspicious IP via VirusTotal/AbuseIPDB and outputs triage report"""
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    vt_result = "No Key Provided"
    
    if vt_api_key and ip:
        headers = {"x-apikey": vt_api_key}
        try:
            res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=5)
            if res.status_code == 200:
                stats = res.json()["data"]["attributes"]["last_analysis_stats"]
                vt_result = f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"
        except Exception as e:
            vt_result = f"Lookup Failed: {str(e)}"
    
    # Auto-Triage & Containment Decision Logic
    summary = f"Automated Playbook Executed for [{event_type}]. Threat Intel Result: {vt_result}."
    status = "CONTAINED (IP Blacklisted)" if "Malicious: [1-9]" in vt_result else "INVESTIGATING"

    # Store Incident Report in DB
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO incidents (timestamp, log_id, status, vt_score, summary) VALUES (?, ?, ?, ?, ?)",
              (datetime.utcnow().isoformat(), log_id, status, vt_result, summary))
    conn.commit()
    conn.close()

# --- SIEM DETECTION ENGINE & INGESTION ---
@app.route('/api/ingest', methods=['POST'])
def ingest_log():
    data = request.json or {}
    source = data.get('source', 'Unknown')
    event_type = data.get('event_type', 'Generic Alert')
    ip = data.get('ip', '0.0.0.0')
    details = data.get('details', '')
    
    # Simple SIEM Detection Rule: Flag Brute Force or Malicious Traffic
    severity = "HIGH" if "failed_login" in event_type.lower() or "malware" in event_type.lower() else "LOW"
    timestamp = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, source, event_type, ip, details, severity) VALUES (?, ?, ?, ?, ?, ?)",
              (timestamp, source, event_type, ip, details, severity))
    log_id = c.lastrowid
    conn.commit()
    conn.close()

    # Trigger SOAR Playbook if SIEM severity is HIGH
    if severity == "HIGH":
        threading.Thread(target=run_soar_playbook, args=(log_id, ip, event_type)).start()

    return jsonify({"status": "success", "log_id": log_id, "siem_severity": severity}), 201

# --- SIEM/SOAR DASHBOARD UI ---
@app.route('/')
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 10")
    logs = c.fetchall()
    c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 10")
    incidents = c.fetchall()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Micro SIEM & SOAR SOC Lab</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-900 text-white p-8">
        <h1 class="text-3xl font-bold mb-6 text-indigo-400">🛡️ SOC Lab: SIEM & SOAR Dashboard</h1>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <!-- SIEM Pane -->
            <div class="bg-slate-800 p-6 rounded-lg border border-slate-700">
                <h2 class="text-xl font-semibold mb-4 text-emerald-400">SIEM Ingested Events</h2>
                <div class="space-y-3">
                    {% for log in logs %}
                    <div class="p-3 rounded bg-slate-700 text-sm">
                        <div class="flex justify-between font-mono text-xs text-slate-400">
                            <span>{{ log[1] }}</span>
                            <span class="font-bold {% if log[6] == 'HIGH' %}text-red-400{% else %}text-green-400{% endif %}">{{ log[6] }}</span>
                        </div>
                        <div class="font-semibold text-slate-200 mt-1">{{ log[3] }} (IP: {{ log[4] }})</div>
                        <div class="text-slate-400 text-xs">{{ log[5] }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <!-- SOAR Pane -->
            <div class="bg-slate-800 p-6 rounded-lg border border-slate-700">
                <h2 class="text-xl font-semibold mb-4 text-amber-400">SOAR Playbook Executions</h2>
                <div class="space-y-3">
                    {% for inc in incidents %}
                    <div class="p-3 rounded bg-slate-700 text-sm">
                        <div class="flex justify-between font-mono text-xs text-slate-400">
                            <span>Incident #{{ inc[0] }} - {{ inc[1] }}</span>
                            <span class="font-bold text-amber-400">{{ inc[3] }}</span>
                        </div>
                        <div class="text-slate-300 mt-1">{{ inc[5] }}</div>
                        <div class="text-xs text-indigo-300 mt-1">VT Status: {{ inc[4] }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, logs=logs, incidents=incidents)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
