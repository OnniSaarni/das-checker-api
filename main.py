import socket
from flask import Flask, request, jsonify
import time
import threading
from dotenv import load_dotenv
import os
from waitress import serve
from flask_cors import CORS
import whois

load_dotenv()
allowedSites = os.getenv('ALLOWED_SITES').split(',')

app = Flask(__name__)
CORS(app, origins=allowedSites, headers=['Content-Type'])

das_dictionary = {} # Dictionary to store the last request time for each user for das
whois_dictionary = {} # Dictionary to store the last request time for each user for whois
cleanup_interval = 60  # Interval in seconds to run the cleanup
entry_lifetime = 5  # Lifetime in seconds for each entry

def manual_whois(domain):
    try:
        result = whois.whois(domain)
    except whois.parser.PywhoisError:
        return "available"
    except:
        return "failed"

    if result:
        try:
            dummy = result.domain_name

            if dummy is None:
                return "available"
            else:
                return "taken"
        except:
            return "available"
        
    else:
        return "failed"

@app.route('/')
def index():
    return "<h3>Verkkotunnushakupyynnöt vain sivuston kautta.</h3>"

@app.route('/check-domain')
def checkDomain():
    global das_dictionary
    
    user_agent = request.headers.get('User-Agent')
    user_ip = request.remote_addr
    user_key = f"{user_ip}:{user_agent}"

    current_time = time.time()
    last_request_time = das_dictionary.get(user_key, 0)

    if current_time - last_request_time < 2:
        return jsonify({"status": "cooldown"}), 429

    das_dictionary[user_key] = current_time

    domain = request.args.get('domain')

    if not domain:
        return jsonify({"status": "invalid-query"}), 400

    if "," in domain:
        returnList = []

        domainList = domain.split(",")
        for dom in domainList:
            if not "." in dom:
                returnList.append({"domain": dom, "status": "invalid-query"})
                continue
            result = manual_whois(dom)
            if result:
                returnList.append({"domain": dom, "status": result})
            else:
                returnList.append({"domain": dom, "status": "failed"})

        return jsonify({"domains": returnList}), 200

    else:
        if not "." in domain:
            return jsonify({"domain": domain, "status": "invalid-query"}), 400
        result = manual_whois(domain)
        if result:
            return jsonify({"domain": domain, "status": result}), 200
        else:
            return jsonify({"domain": domain, "status": "failed"}), 500

@app.route('/whois')
def whoisSearch():
    global whois_dictionary
    
    user_agent = request.headers.get('User-Agent')
    user_ip = request.remote_addr
    user_key = f"{user_ip}:{user_agent}"

    current_time = time.time()
    last_request_time = whois_dictionary.get(user_key, 0)

    if current_time - last_request_time < 2:
        return jsonify({"status": "cooldown"}), 429

    whois_dictionary[user_key] = current_time

    domain = request.args.get('domain')
    if not domain or not "." in domain:
        return jsonify({"status": "invalid-query"}), 400

    try:
        result = whois.whois(domain)
    except whois.parser.PywhoisError:
        return jsonify({"status": "success", "whois_data": "Domain not found"}), 200
    except:
        return jsonify({"status": "failed"}), 500

    if result:
        return jsonify({"status": "success", "whois_data": result}), 200
    else:
        return jsonify({"status": "failed"}), 500

def cleanup_old_entries():
    global whois_dictionary
    global das_dictionary

    while True:
        current_time = time.time()
        keys_to_delete1 = [key for key, last_time in whois_dictionary.items() if current_time - last_time > entry_lifetime]
        keys_to_delete2 = [key for key, last_time in das_dictionary.items() if current_time - last_time > entry_lifetime]
        for key in keys_to_delete1:
            del whois_dictionary[key]
        for key in keys_to_delete2:
            del das_dictionary[key]
        time.sleep(cleanup_interval)

if __name__ == '__main__':
    cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
    cleanup_thread.start()
    
    serve(app, host="0.0.0.0", port=5000)