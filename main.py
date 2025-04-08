from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os
from waitress import serve
from flask_cors import CORS
import whois

load_dotenv()
allowedSites = os.getenv('ALLOWED_SITES').split(',')

app = Flask(__name__)
CORS(app, origins=allowedSites, headers=['Content-Type'])

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

    domain = request.args.get('domain')

    if not domain:
        return jsonify({"status": "invalid-query"}), 400

    returnList = []
    if "," in domain:
        domainList = domain.split(",")
    else:
        domainList = [domain]
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

@app.route('/whois')
def whoisSearch():

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

if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=5000)