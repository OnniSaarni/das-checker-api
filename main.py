import socket
from flask import Flask, request, jsonify
import time
import threading
from dotenv import load_dotenv
import os
import xml.etree.ElementTree as ET
from waitress import serve
from flask_cors import CORS

load_dotenv()
allowedSites = os.getenv('ALLOWED_SITES').split(',')

app = Flask(__name__)
CORS(app, origins=allowedSites, headers=['Content-Type'])

user_last_request_time = {} # Dictionary to store the last request time for each user
cleanup_interval = 60  # Interval in seconds to run the cleanup
entry_lifetime = 5  # Lifetime in seconds for each entry


def xml_encode(string):
    return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;").replace('"', "&quot;")

def query_domain_availability(domain):
    query = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<iris1:request xmlns:iris1="urn:ietf:params:xml:ns:iris1">'
             '<iris1:searchSet>'
             f'<iris1:lookupEntity registryType="dchk1" entityClass="domain-name" entityName="{xml_encode(domain)}"/>'
             '</iris1:searchSet>'
             '</iris1:request>')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(query.encode(), ('das.domain.fi', 715))
            response, _ = sock.recvfrom(4096)
            return(parse_status_from_xml(response.decode()))
    except Exception as e:
        return None

def parse_status_from_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
        status_element = root.find('.//status')
        if status_element is not None:
            if status_element.find('available') is not None:
                return "available"
            elif status_element.find('active') is not None:
                return "taken"
            elif status_element.find('invalid') is not None:
                return "invalid-query"
        return "unknown-domain-status"
    except ET.ParseError:
        return "failed"

@app.route('/')
def index():
    return "<h3>Verkkotunnushakupyynnöt vain sivuston kautta.</h3>"

@app.route('/check-domain')
def checkDomain():
    global user_last_request_time
    
    user_agent = request.headers.get('User-Agent')
    user_ip = request.remote_addr
    user_key = f"{user_ip}:{user_agent}"

    current_time = time.time()
    last_request_time = user_last_request_time.get(user_key, 0)

    if current_time - last_request_time < 2:
        return jsonify({"status": "cooldown"}), 429

    user_last_request_time[user_key] = current_time

    domain = request.args.get('domain')
    if not domain:
        return jsonify({"status": "invalid-query"}), 400

    result = query_domain_availability(domain)
    if result:
        return jsonify({"status": result}), 200
    else:
        return jsonify({"status": "failed"}), 500


def cleanup_old_entries():
    global user_last_request_time

    while True:
        current_time = time.time()
        keys_to_delete = [key for key, last_time in user_last_request_time.items() if current_time - last_time > entry_lifetime]
        for key in keys_to_delete:
            del user_last_request_time[key]
        time.sleep(cleanup_interval)

if __name__ == '__main__':
    cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
    cleanup_thread.start()
    
    serve(app, host="0.0.0.0", port=5000)