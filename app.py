from flask import Flask, render_template, request
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_host_api', methods=['GET', 'POST'])
def add_host_api():
    output = ""
    if request.method == 'POST':
        ticket_ref = request.form.get('ticket_ref', '')
        group_name = request.form.get('group_name', '')
        input_data = request.form.get('input_data', '')

        lines = input_data.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue  # skip empty lines
            parts = line.split()
            if len(parts) == 2:
                name, ip = parts
                output += f'add host name "{name}" ip-address "{ip}" comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'
            elif len(parts) == 1:
                ip = parts[0]
                name = f'H_{ip}'
                output += f'add host name "{name}" ip-address "{ip}" comments "Ref:{ticket_ref}" groups.1 "{group_name}"\n'
            else:
                output += f"# Skipping invalid line: {line}\n"

    return render_template('add_host_api.html', output=output)