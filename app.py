from flask import Flask, render_template, request, send_file, redirect, url_for
from datetime import datetime
import pandas as pd
import io



app = Flask(__name__)



#LANDING PAGE
@app.route('/')
def index():
    return render_template('index.html', current_year=datetime.now().year)

#ABOUT PAGE
@app.route('/about')
def about():
    return render_template('about.html', current_year=datetime.now().year)


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


#POLICY REVIEW TOOL ___START___

# Weak protocols list
WEAK_PROTOCOLS = ["HTTP", "FTP", "TELNET", "RDP", "POP3", "IMAP"]

def classify_rules(df):
    """
    Classifies rules into one or more categories:
    - Disabled (Type contains "[Disabled]")
    - Zero Hits
    - Any in Source/Destination
    - Weak Protocol
    Adds a new column 'Categories' (list of tags).
    """
    results = []

    for _, row in df.iterrows():
        rule = row.to_dict()  # keep all original columns
        categories = []

        # Disabled check
        if "[disabled]" in str(row.get("Type", "")).lower():
            categories.append("Disabled")

        # Zero Hits check
        if str(row.get("Hits", "")).strip().lower() == "zero":
            categories.append("Zero Hits")

        # Any in Source or Destination
        if str(row.get("Source", "")).strip().lower() == "any" or str(row.get("Destination", "")).strip().lower() == "any":
            categories.append("Any in Source/Destination")

        # Weak Protocols (split by ;)
        services = str(row.get("Services & Applications", ""))
        service_tokens = [s.strip().lower() for s in services.split(";")]
        for proto in WEAK_PROTOCOLS:
            if proto.lower() in service_tokens:
                categories.append("Weak Protocol")
                break


        # If nothing matched → Normal
        if not categories:
            categories = ["Normal"]

        # Store as comma-separated string for HTML/CSV
        rule["Categories"] = ", ".join(categories)
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

    # Convert list of dicts to DataFrame
    df = pd.DataFrame(classified_rules)

    # Create in-memory CSV
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Get current date/time for filename
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"classified_rules_{date_str}.csv"
    )
#POLICY REVIEW TOOL ___END___

