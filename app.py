from flask import Flask, render_template, request
from datetime import datetime
import os

app = Flask(__name__)

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