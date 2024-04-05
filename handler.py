import json
import os
import random
import http.client
import datetime
from urllib.parse import urlencode, urlparse

# Moesif Constants
MOESIF_CONFIG_URL = "https://api.moesif.net/v1/config"
MOESIF_CONFIG_CACHE_FILE = "/tmp/moesif_config_cache.json"
MOESIF_APPLICATION_ID = os.environ.get("MOESIF_APPLICATION_ID")


# TODO this should be extracted from token or your auth server and validated first. 
# For purpose of this example, the user is hardcoded
USER_ID_TO_CHECK = "user1234"

def load_moesif_config_from_cache():
    if os.path.exists(MOESIF_CONFIG_CACHE_FILE):
        with open(MOESIF_CONFIG_CACHE_FILE, "r") as f:
            conf = json.load(f)
            print('load_moesif_config_from_cache ')
            print(conf)
            return conf
    return None

def is_expired(timestamp):
    expiration_time = datetime.datetime.now() - datetime.timedelta(minutes=1)  # Config expires after 1 minute
    return timestamp < expiration_time.timestamp()


def fetch_and_cache_moesif_config():
    parsed_url = urlparse(MOESIF_CONFIG_URL)
    conn = http.client.HTTPSConnection(parsed_url.netloc)
    
    headers = {
        "X-Moesif-Application-Id": MOESIF_APPLICATION_ID
    }
    
    conn.request("GET", parsed_url.path, headers=headers)
    response = conn.getresponse()
    if response.status == 200:
        data = response.read()
        moesif_config = json.loads(data)
        
        moesif_config["timestamp"] = datetime.datetime.now().timestamp()
        with open(MOESIF_CONFIG_CACHE_FILE, "w") as f:
            json.dump(moesif_config, f)
        conn.close()
        return moesif_config
    else:
        print("fetch_and_cache_moesif_config Failed to fetch Moesif config")
        print(response.status)
        print(response.read())
        conn.close()
        return None

def generate_deny_policy(event, userId):
    return {
        "principalId": userId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": event['methodArn']
                }
            ]
        },
        "context": {
            "reason": "User has exceeded the quota",
        }
    }

def generate_allow_policy(event, userId):
    query_string = urlencode(event.get('queryStringParameters', {}))
    print(query_string)
    
    return {
        "principalId": userId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event['methodArn']
                }
            ]
        },
        "context": {
            "query_string": query_string,
            "operation_name": event['requestContext'].get('operationName', None),
             "x_forwarded_for": event['headers'].get('X-Forwarded-For', None),
             "xforwardedfor": event['headers'].get('X-Forwarded-For', None),
             "X-Forwarded-For": event['headers'].get('X-Forwarded-For', None), 
             "X_Forwarded_For": event['headers'].get('X-Forwarded-For', None), 
             "content_type": event['headers'].get('Content-Type', None)
        }
    }
    
def lambda_handler(event, context):
    print('hello world')

    # Check if cached copy of Moesif config exists and not expired
    moesif_config = load_moesif_config_from_cache()
    if not moesif_config or is_expired(moesif_config["timestamp"]):
        moesif_config = fetch_and_cache_moesif_config()
    
    # Check if user id is in the response.user_rules json object
    rule = {}
    if moesif_config:
        rule = moesif_config.get("user_rules", {})
        print(json.dumps(rule))
        
    if USER_ID_TO_CHECK in rule:
        
        # Return deny policy
        return generate_deny_policy(event, USER_ID_TO_CHECK)
    else:
        return generate_allow_policy(event, USER_ID_TO_CHECK)
