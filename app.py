from flask import Flask, render_template, request, send_file, redirect, url_for
from datetime import datetime
import pandas as pd
import io


app = Flask(__name__)

# Weak protocols list
WEAK_PROTOCOLS = ["HTTP", "FTP", "TELNET", "RDP", "POP3", "IMAP"]

def classify_rules(df):
    """
    Takes DataFrame from Check Point CSV and classifies rules.
    Expected columns: 'Name', 'Hits', 'Enabled', 'Services'
    """
    results = []

    for _, row in df.iterrows():
        rule = {
            "name": row.get("Name", "Unnamed"),
            "hits": row.get("Hits", 0),
            "status": "Enabled" if str(row.get("Enabled", "True")).lower() == "true" else "Disabled",
            "protocols": row.get("Services", ""),
            "category": ""
        }

        hits = int(rule["hits"]) if str(rule["hits"]).isdigit() else 0

        # Classify
        if hits == 0:
            rule["category"] = "Unused"
        elif rule["status"] == "Disabled":
            rule["category"] = "Disabled"
        elif hits < 1000:
            rule["category"] = "Low Hits"
        elif hits > 1_000_000:
            rule["category"] = "High Hits"

        # Weak protocols check
        for proto in WEAK_PROTOCOLS:
            if proto.lower() in str(rule["protocols"]).lower():
                rule["category"] = "Weak Protocol"
                break

        results.append(rule)

    return results


@app.route("/policy_review", methods=["GET", "POST"])
def policy_review():
    global classified_rules
    classified_rules = None

    if request.method == "POST":
        file = request.files["csv_file"]
        if file and file.filename.endswith(".csv"):
            df = pd.read_csv(file)
            classified_rules = classify_rules(df)

    return render_template("policy_review.html", rules=classified_rules)


@app.route("/download_policy", methods=["POST"])
def download_policy():
    if not classified_rules:
        return redirect(url_for("policy_review"))

    df = pd.DataFrame(classified_rules)

    # Save to memory for download
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="classified_rules.csv")


@app.route('/')
def index():
    return render_template('index.html', current_year=datetime.now().year)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/add_host_api', methods=['GET', 'POST'])
def add_host_api():
    output = ""
    if request.method == 'POST':
        ticket_ref = request.form.get('ticket_ref', '')
        group_name = request.form.get('group_name', '')
        input_data = request.form.get('input_data', '')
        is_sub_domain = 'true' if request.form.get('is_sub_domain') == 'on' else 'false'

        lines = input_data.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue  # skip empty lines
            parts = line.split()
            
            # Host with IP
            if len(parts) == 2:
                name, ip = parts
                output += f'add host name "{name}" ip-address "{ip}" comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'
            
            # Single value: could be IP or domain
            elif len(parts) == 1:
                value = parts[0]
                
                # If it starts with a dot → treat as DNS domain
                if value.startswith('.'):
                    output += f'add dns-domain name "{value}" is-sub-domain {is_sub_domain} comments "Ref:{ticket_ref}"\n'
                    output += f'set group name "{group_name}" members.add "{value}"\n'
                else:
                    # Treat as IP and auto-generate host name
                    name = f'H_{value}'
                    output += f'add host name "{name}" ip-address "{value}" comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'
            
            else:
                output += f"# Skipping invalid line: {line}\n"

    return render_template('add_host_api.html', output=output)