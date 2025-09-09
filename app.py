from flask import Flask, render_template, request, send_file, redirect, url_for
from datetime import datetime
import pandas as pd
import io
import csv


app = Flask(__name__)



#LANDING PAGE
@app.route('/')
def index():
    return render_template('index.html', current_year=datetime.now().year)

#ABOUT PAGE
@app.route('/about')
def about():
    return render_template('about.html', current_year=datetime.now().year)


#POLICY REVIEW TOOL

# Weak protocols list
WEAK_PROTOCOLS = ["HTTP", "FTP", "TELNET", "RDP", "POP3", "IMAP"]

def safe_int(value):
    """Convert CSV hits value to integer safely."""
    try:
        return int(str(value).replace(",", ""))
    except ValueError:
        # Handle textual zero
        if str(value).strip().lower() == "zero":
            return 0
        return 0  # fallback for any other non-numeric value

def classify_rules(df):
    """
    Classifies rules while keeping all original columns.
    Adds a new column 'Category'.
    """
    results = []

    for _, row in df.iterrows():
        rule = row.to_dict()  # keep all original columns

        # Parse hits safely
        hits = safe_int(rule.get("Hits", 0))
        status = "Enabled" if str(rule.get("Enabled", "True")).lower() == "true" else "Disabled"
        services = str(rule.get("Services & Applications", ""))

        # Default category
        category = "Normal"

        # Classify by hits and status
        if hits == 0:
            category = "Unused"
        elif status == "Disabled":
            category = "Disabled"
        elif hits < 1000:
            category = "Low Hits"
        elif hits > 1_000_000:
            category = "High Hits"

        # Weak protocols check (match whole words only)
        for proto in WEAK_PROTOCOLS:
            if f"{proto.lower()}" in [s.strip().lower() for s in services.replace(",", " ").split()]:
                category = "Weak Protocol"
                break

        rule["Category"] = category
        results.append(rule)

    return results

#DOWNLOAD_FUNCTION_FOR_POLICY_REVIEW
# Global store for download
classified_rules = None

@app.route("/checkpoint/policy_review", methods=["GET", "POST"])
def policy_review():
    global classified_rules
    classified_rules = None
    results = None

    if request.method == "POST":
        file = request.files.get("csv_file")
        if file and file.filename.endswith(".csv"):
            df = pd.read_csv(file)
            results = classify_rules(df)
            classified_rules = results  # store for download

    return render_template("/checkpoint/policy_review.html", rules=results)

#Download reviewed rules
@app.route("/download_policy", methods=["POST"])
def download_policy():
    global classified_rules
    if not classified_rules:
        return "No classified rules to download.", 400

    df = pd.DataFrame(classified_rules)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="classified_rules.csv"
    )


#ADD HOST IN BULK TOOL
@app.route('/checkpoint/add_host_api', methods=['GET', 'POST'])
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

    return render_template('/checkpoint/add_host_api.html', output=output)