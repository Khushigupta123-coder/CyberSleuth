
import os
import re
import io
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    redirect,
    url_for,
    session,
)
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-key-change-before-deployment",
)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "cybersleuth.db"


# --------------------------------------------------
# 2. DATABASE AND USER ACCOUNTS
# --------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


# --------------------------------------------------
# 3. MITRE ATT&CK TECHNIQUE LIBRARY
# --------------------------------------------------

TECHNIQUES = [
    {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "explanation": "Attackers may use deceptive links to trick users.",
        "patterns": [
            r"\bphishing\b",
            r"\bspearphishing link\b",
            r"\bmalicious link\b",
        ],
    },
    {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "explanation": "PowerShell may be used to execute commands.",
        "patterns": [
            r"\bpowershell\b",
            r"\bpowershell command\b",
        ],
    },
    {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "explanation": "Scheduled tasks may be abused to run commands automatically.",
        "patterns": [
            r"\bscheduled task\b",
            r"\bcreated a new scheduled task\b",
        ],
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "explanation": "Repeated attempts may be used to guess credentials.",
        "patterns": [
            r"\bbrute force\b",
            r"\brepeated failed login attempts\b",
            r"\brepeated login attempts\b",
        ],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "explanation": "Attackers may misuse legitimate accounts.",
        "patterns": [
            r"\bsuccessful login\b",
            r"\bcompromised credentials\b",
            r"\bunauthorized account access\b",
        ],
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "explanation": "Web protocols may be used to communicate with compromised systems.",
        "patterns": [
            r"\bhttps traffic\b",
            r"\boutbound https\b",
        ],
    },
]


# --------------------------------------------------
# 4. TEXT PROCESSING
# --------------------------------------------------

def clean_text(text):
    """Clean and normalize report text."""
    text = str(text or "")
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_sentences(text):
    """Split text into approximate sentences."""
    return [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text)
        if sentence.strip()
    ]


# --------------------------------------------------
# 5. ENTITY EXTRACTION
# --------------------------------------------------

def extract_entities(text):
    """Extract basic indicators from report text."""

    entities = []

    patterns = {
        "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "URL": r"""https?://[^\s<>"']+""",
        "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "Domain": r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
        "Tool": r"\b(?:PowerShell|cmd\.exe|mimikatz|psexec)\b",
    }

    seen = set()

    for entity_type, pattern in patterns.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(0).rstrip(".,;:!?)\"'")

            if entity_type == "IP Address":
                parts = value.split(".")

                if not all(0 <= int(part) <= 255 for part in parts):
                    continue

            key = (entity_type, value.lower())

            if key not in seen:
                seen.add(key)
                entities.append({
                    "type": entity_type,
                    "value": value,
                })

    return entities


# --------------------------------------------------
# 6. MITRE ATT&CK TECHNIQUE MAPPING
# --------------------------------------------------

def map_techniques(text):
    """Match report text against predefined keyword rules."""

    findings = []
    sentences = split_sentences(text)

    for technique in TECHNIQUES:
        evidence = []

        for pattern in technique["patterns"]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                matched_sentence = next(
                    (
                        sentence
                        for sentence in sentences
                        if match.group(0).lower() in sentence.lower()
                    ),
                    match.group(0),
                )

                if matched_sentence not in evidence:
                    evidence.append(matched_sentence)

        if evidence:
            findings.append({
                "id": technique["id"],
                "name": technique["name"],
                "tactic": technique["tactic"],
                "explanation": technique["explanation"],
                "evidence": evidence[:3],
                "confidence": "Rule match - analyst verification required",
            })

    return findings


# --------------------------------------------------
# 7. MAIN ANALYSIS FUNCTION
# --------------------------------------------------

def analyze(text):
    """Analyze text and return entities, techniques, and statistics."""

    text = clean_text(text)
    entities = extract_entities(text)
    techniques = map_techniques(text)

    return {
        "text": text,
        "entities": entities,
        "techniques": techniques,
        "stats": {
            "words": len(re.findall(r"\b\w+\b", text)),
            "sentences": len(split_sentences(text)),
            "entities": len(entities),
            "techniques": len(techniques),
        },
        "notice": (
            "Rule-based candidate findings only. "
            "Verify results manually."
        ),
    }


SAMPLE_REPORT = """
A phishing email contained a malicious link to http://malicious.example.com/login.
The attacker used PowerShell to execute a suspicious command.
A scheduled task was created to maintain persistence.
Outbound HTTPS traffic was observed from 192.168.1.20.
"""


# --------------------------------------------------
# 8. WELCOME PAGE
# --------------------------------------------------

@app.route("/")
def welcome():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("welcome.html")


# --------------------------------------------------
# 9. REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            error = (
                "Username must be 3–30 characters using "
                "letters, numbers, or underscores."
            )

        elif len(password) < 8 or len(password) > 128:
            error = "Password must be between 8 and 128 characters."

        elif password != confirm_password:
            error = "Passwords do not match."

        else:
            try:
                with get_db() as connection:
                    connection.execute(
                        """
                        INSERT INTO users (username, password_hash)
                        VALUES (?, ?)
                        """,
                        (
                            username,
                            generate_password_hash(password),
                        ),
                    )

                return redirect(url_for("login", registered="1"))

            except sqlite3.IntegrityError:
                error = "That username already exists. Please choose another."

    return render_template("register.html", error=error)


# --------------------------------------------------
# 10. LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    success = (
        "Account created successfully. You can now log in."
        if request.args.get("registered") == "1"
        else None
    )

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error,
        success=success,
    )


# --------------------------------------------------
# 11. LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("welcome"))


# --------------------------------------------------
# 12. DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    demo = analyze(SAMPLE_REPORT)

    return render_template(
        "dashboard.html",
        demo=demo,
        year=2026,
        username=session.get("username"),
    )


# --------------------------------------------------
# 13. REPORT ANALYZER
# --------------------------------------------------

@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyzer():
    report = ""
    result = None
    error = None

    if request.method == "GET" and request.args.get("demo") == "1":
        report = SAMPLE_REPORT
        result = analyze(report)

    if request.method == "POST":
        report = request.form.get("report", "")
        uploaded_file = request.files.get("report_file")

        if uploaded_file and uploaded_file.filename:
            try:
                report = uploaded_file.read().decode("utf-8")
            except UnicodeDecodeError:
                error = "Please upload a UTF-8 encoded text file."

        if not error:
            if report.strip():
                try:
                    result = analyze(report)
                except Exception:
                    app.logger.exception("Report analysis failed")
                    error = "Analysis failed. Please check your input and try again."
            else:
                error = "Please paste a report or choose a text file."

    return render_template(
        "analyze.html",
        report=report,
        result=result,
        error=error,
        year=2026,
    )


# --------------------------------------------------
# 14. MITRE ATT&CK LIBRARY
# --------------------------------------------------

@app.route("/techniques")
@login_required
def techniques_page():
    return render_template(
        "techniques.html",
        techniques=TECHNIQUES,
        year=2026,
    )


# --------------------------------------------------
# 15. METHODOLOGY PAGE
# --------------------------------------------------

@app.route("/methodology", endpoint="methodology_page")
@app.route("/methodology", endpoint="methodology")
@login_required
def methodology_page():
    return render_template("methodology.html", year=2026)


# --------------------------------------------------
# 16. JSON API
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not isinstance(text, str):
        return jsonify({
            "error": "The text field must be a string."
        }), 400

    return jsonify(analyze(text))


# --------------------------------------------------
# 17. HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "application": "CyberSleuth",
    })


# --------------------------------------------------
# 18. DOWNLOAD ANALYSIS REPORT
# --------------------------------------------------

@app.route("/download-report", methods=["POST"])
@login_required
def download_report():
    report_text = request.form.get("text", "")
    results = analyze(report_text)

    output = io.StringIO()

    output.write("CyberSleuth Analysis Report\n")
    output.write("=" * 30 + "\n\n")

    output.write("SUMMARY\n")
    output.write(f'Words: {results["stats"]["words"]}\n')
    output.write(f'Sentences: {results["stats"]["sentences"]}\n')
    output.write(f'Entities: {results["stats"]["entities"]}\n')
    output.write(f'Techniques: {results["stats"]["techniques"]}\n\n')

    output.write("EXTRACTED ENTITIES\n")

    for entity in results["entities"]:
        output.write(f'{entity["type"]}: {entity["value"]}\n')

    output.write("\nCANDIDATE ATT&CK TECHNIQUES\n")

    for technique in results["techniques"]:
        output.write(
            f'{technique["id"]} - {technique["name"]}\n'
        )
        output.write(f'Tactic: {technique["tactic"]}\n')
        output.write(f'Explanation: {technique["explanation"]}\n')

        for evidence in technique["evidence"]:
            output.write(f"Evidence: {evidence}\n")

        output.write("\n")

    output.write("\nNote: All findings require manual verification.\n")

    file_data = io.BytesIO(output.getvalue().encode("utf-8"))
    file_data.seek(0)

    return send_file(
        file_data,
        mimetype="text/plain",
        as_attachment=True,
        download_name="cybersleuth_report.txt",
    )


# --------------------------------------------------
# 19. FRIENDLY FILE SIZE ERROR
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):
    return (
        "The uploaded file is too large. Maximum size is 2 MB.",
        413,
    )


# --------------------------------------------------
# 20. RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
