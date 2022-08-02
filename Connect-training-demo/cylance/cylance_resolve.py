import jwt  # PyJWT version 1.6.1 as of the time of authoring
import uuid
import json
import urllib.request
import time
from time import gmtime, strftime, sleep
from datetime import datetime, timedelta


# Mapping between Cylance API response fields to CounterACT properties
cylance_to_ct_props_map = {
    "state": "framework_cylance_state",
    "last_logged_in_user": "framework_cylance_last_logged_in_user",
    "mac_addresses": "framework_cylance_mac_addresses",
    "is_safe": "framework_cylance_is_safe",
    "id": "framework_cylance_id"
}

# CONFIGURATION
url = params["framework_cylance_url"] # Server URL
tenant = params["framework_cylance_tenant_id"]  # Tenant ID
app = params["framework_cylance_application_id"]  # Application ID
secret = params["framework_cylance_application_secret"]  # Application Secret

# ***** START - AUTH API CONFIGURATION ***** #
timeout = 1800  # 30 minutes from now
now = datetime.utcnow()
timeout_datetime = now + timedelta(seconds=timeout)
epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
jti_val = str(uuid.uuid4())
claims = {
    "exp": epoch_timeout,
    "iat": epoch_time,
    "iss": "http://cylance.com",
    "sub": app,
    "tid": tenant,
    "jti": jti_val,
    # The following is optional and is being noted here as an example on how one can restrict
    # the list of scopes being requested
    # "scp": "policy:create, policy:list, policy:read, policy:update"
    # "scp": "device:read"
}

encoded = jwt.encode(claims, secret, algorithm='HS256')
payload = {"auth_token": encoded.decode("utf-8")}
headers = {"Content-Type": "application/json; charset=utf-8"}

# Making an API call to get the JWT token
request = urllib.request.Request(
    f"{url}/auth/v2/token",
    headers=headers,
    data=bytes(json.dumps(payload), encoding="utf-8"),
)


# To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
resp = urllib.request.urlopen(request, context=ssl_context)

jwt_token = json.loads(resp.read())['access_token']  # access_token to be passed to GET request
if mac_addr := params["mac"]:
    macinput = "-".join(mac_addr[i:i+2] for i in range(0,12,2))
else:
    macinput = ""

# ***** PART 2 - QUERY MAC ADDRESS  ***** #
GETMAC_URL = f"{url}/devices/v2/macaddress/{macinput}"
device_headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Authorization": f"Bearer {str(jwt_token)}",
}


# Get MAC data
request = urllib.request.Request(GETMAC_URL, headers=device_headers)
r = urllib.request.urlopen(request, context=ssl_context)
request_response = json.loads(r.read())

properties = {}
if request_response:
    return_values = request_response[0]
    for key, value in return_values.items():
        if key in cylance_to_ct_props_map:
            properties[cylance_to_ct_props_map[key]] = value

response = {"properties": properties}
