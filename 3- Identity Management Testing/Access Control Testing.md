# Methodology Outline
To test access control, we must first build a map of what each application role is intended to be able to do. Then attack vectors can be used to test bypasses for these limitations. The difference between broken access control and privilege escalation is broken access control is the ability to perform an action in the context of a user who was not intended to be able to perform that action. Privilege escalation is the ability to gain access to the application as a different user to the one you began with.

---
# Identification Of Role Privileges
Run through each functionality within the application and note which roles have the ability to perform specific actions. Keep note of which roles are allowed to perform specific actions and which are not. Record this information in a table.

# Attack Vectors
The goal of an attack vector is to perform an action in the context of a user who was not intended to be able to perform that action.
## Parameter Tampering
### Blindly Trusted Parameters
- [**User role controlled by request parameter**](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)
- [**User role can be modified in user profile**](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)
- [**User ID controlled by request parameter**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)
- [**User ID controlled by request parameter, with unpredictable user IDs**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)
- [**User ID controlled by request parameter with data leakage in redirect**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)
- [**User ID controlled by request parameter with password disclosure**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)
- [**URL-based access control can be circumvented**](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented) **[X-Original-URL:] or other headers that backend handle it to give access**
- [**Method-based access control can be circumvented**](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented) **[ Changing the method of the request ]**
- [**Multi-step process with no access control on one step**](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step) **[ Do a need-privilege action with non-privilege user even if there is confirmation step ]**
- [**Referer-based access control**](https://portswigger.net/web-security/access-control/lab-referer-based-access-control) **[ backend depends on referrer header to access the user to do sensitive actions ]**
### Parameter Removal
- Remove entire request body
- Remove parts of json
- Remove entire json
- remove parts of xml
- remove entire xml
### Parameter Tamering
- Inject JSON array in URL, body, json, or xml (`[]`)
- Inject JSON dictionary in URL, body, json, or xml (`{}`)
- Prepend, append, and inject empty string (`""`, `''`)
- Prepend, append, and inject semicolon (`;`)
- Prepend, append, and inject null byte (`%00`)
- Prepend append, and inject weird URL encoded special characters. Use `--path-as-is`
### Parameter Pollution
- URL parameter pollution
- Body parameter pollution
- JSON parameter pollution
- XML parameter pollution
### Mass Assignment
- **Enumerate object properties:**
	- API documentation
	- Exercise data retrieval endpoints -> `watch-out for ?include=user.addresses,user.cards-like parameters`
	- Guessing, based on API context
	- Reverse engineering available API clients
	- Use param-miner tool OR [Arjun](https://github.com/s0md3v/Arjun) to guess parameters
- Uncover hidden properties
- Do some Parameters-Values Tampers [[JSON Tests Cheat Sheet]]

---
## Privilege Check Bypass
- Use account-A's Cookie/ Authorization-token to access account-B's Resources/Objects
- SQL Injection
- Use the newsletter unsubscribe Session to Access any Victim's PII
- Use The non-confirmed email session to access any of resources that demands Confirmed user
- Can a regular user access administrative endpoints?
- Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH) will allow level escalation?
- Enumerate/Bruteforce endpoints for getting unauthorized requests
- Check for Forbidden Features for low privilege user and try to use this features
- Unprotected admin panel [in source code or robots.txt]
Request with different HTTP versions:
Request different http versions
```
curl --http0.9 https://target.xyz
curl --http1.0 https://target.xyz
curl --http1.1 https://target.xyz
curl --http2 https://target.xyz
curl --http2-prior-knowledge https://target.xyz
curl --http3 https://target.xyz
```
Request with different HTTP methods:
```
curl -X POST
```

## Parameter Tampering
- Understand the pattern [ Sequential | Encoded | UUID (aka GUID) | Timestamp | Hash | Other]
- Change -> Next/Previous value -> Compute/Predict -> Data Type [string->number] -> Method [GET/POST]
- Duplicate -> `?id=1&id=2`
- Add as an array -> `?id[]=1&id[]=2`
- Wildcard -> `GET /users/id -> GET /users/*`
- Cross-deployments IDs -> Identify other deployments (hosts) of your target API
- UUID Hacking -> [tool](https://gist.github.com/DanaEpp/8c6803e542f094da5c4079622f9b4d18) [read more](https://danaepp.com/attacking-predictable-guids-when-hacking-apis)
-  Try decode the ID, if the ID encoded using md5,base64,etc
```html
GET /GetUser/dmljdGltQG1haWwuY29t
[...]
```
- change HTTP method
```shell
GET /users/delete/victim_id  ->403
POST /users/delete/victim_id ->200
```
## Excessive Data Exposure
- Check if the API returns full data objects from database with sensitive data
- Compare client data with the API response to check if the filtering is done by client side
- Sniff the traffic to check for sensitive data returned by the API
- `exif_geo`: When a user uploads an image in [example.com](http://example.com/), the uploaded image’s EXIF Geolocation Data does not gets stripped. As a result, anyone can get sensitive information of [example.com](http://example.com/) users like their Geolocation, their Device information like Device Name, Version, Software & Software version used etc.


## Improper Assets Management
- Check for the API documentation
- Hosts inventory is missing or outdated
- Integrated services inventory, either first- or third-party, is missing or outdated
- Old or previous API versions are running unpatched

## IDOR
Check basic IDOR with predictable UUIDs, hashes, timestamps,  numeric identifiers, composite keys.
Find and Replace 10s in `urls`, headers and body: /users/01 → /users/02
Try Parameter Pollution: users-01 `users=01&users=02`
- Special Characters: `/users/01` of `/users/*` → Disclosure of every single user
- Try Older versions of `api` endpoints: `/api/v3/users/01` → `/api/v1/users/02`
- Add extension: `/users/01` → `/users/82.json`
- Change Request Methods: `POST /users/81` → `GET, PUT, PATCH, DELETE` etc
Check if `Referer` or some other `Headers` are used to validate the `IDs`:  
    `GET /users/02` → `403 Forbidden Referer: [example.com/users/01](<http://example.com/users/01>) GET /users/82` → `200 OK Referer: [example.com/users/02](<http://example.com/users/02>)`
- Encrypted IDs: If application is using encrypted IDs, try to decrypt using [hashes.com](http://hashes.com/) or other tools.
- Swap GUID with Numeric ID or email:  
    `/users/1b84c196-89f4-4260-b18b-ed85924ce283` or `/users/82` or `/users/agb.com`
- Try GUIDs such as:  
    `00000000-0000-0000-0000-000000000000` and `11111111-1111-1111-1111-111111111111`
- GUID Enumeration: Try to disclose GUIDs using `Google Dorks`, `Github`, `Wayback`, `Burp history`
- If none of the GUID Enumeration methods work then try: `Signup`, `Reset Password`, Other endpoints within application and analyze response. These endpoints mostly disclose user's GUID.
- `403/401` Bypass: If server responds back with a `403/401` then try to use burp intruder and  
    send `50-100` requests having different IDs: Example: from `/users/01` to `/users/100`
- if server responds with a `403/401`, double check the function within the application.  
    Sometime `403/401` is thrown but the action is performed. This can also be potentially bypassed by using different request methods and headers.
- Blind IDORS: Sometimes information is not directly disclosed. Lookout for endpoints and  
    features that may disclose information such as `export files`, `emails` or `message alerts`.
- Chain `IDOR` with `XSS` for `Account Takeovers`.
- Bruteforce Hidden HTTP parameters
- send wildcard instead of an id
- Missing Function Level Acess Control
- Bypass object level authorization Add parameter onto the endpoit if not present by defualt
```
GET /api_v1/messages ->200GET /api_v1/messages?user_id=victim_uuid ->200
```
- HTTP Parameter pollution give multiple value for same parameter:
```
GET /api_v1/messages?user_id=attacker_id&user_id=victim_idGET /api_v1/messages?user_id=victim_id&user_id=attacker_id
```
- change file type:
```
GET /user_data/2341        -> 401GET /user_data/2341.json   -> 200GET /user_data/2341.xml    -> 200GET /user_data/2341.config -> 200GET /user_data/2341.txt    -> 200
```
- json parameter pollution:
```
{"userid":1234,"userid":2542}
```
- Wrap the ID with an array in the body:
```
{"userid":123} ->401{"userid":[123]} ->200
```
- wrap the id with a json object:
```
{"userid":123} ->401{"userid":{"userid":123}} ->200
```
- Test an outdata API version:
```
GET /v3/users_data/1234 ->401GET /v1/users_data/1234 ->200
```
If the website using graphql, try to find IDOR using graphql:
```shell
GET /graphql
[...]
```

```html
GET /graphql.php?query=
[...]
```

- Try replacing parameter names:
```shell
Instead of this:
GET /api/albums?album_id=<album id>

Try This:
GET /api/albums?account_id=<account id>

Tip: There is a Burp extension called Paramalyzer which will help with this by remembering all the parameters you have passed to a host.
```
- Path Traversal:
```shell
POST /users/delete/victim_id          ->403
POST /users/delete/my_id/..victim_id  ->200
```
- change request content-type:
```shell
Content-Type: application/xml ->
Content-Type: application/json
```
- swap non-numeric with numeric id:
```shell
GET /file?id=90djbkdbkdbd29dd
GET /file?id=302
```
- Missing Function Level Acess Control
```shell
GET /admin/profile ->401
GET /Admin/profile ->200
GET /ADMIN/profile ->200
GET /aDmin/profile ->200
GET /adMin/profile ->200
GET /admIn/profile ->200
GET /admiN/profile ->200
```
- send wildcard instead of an id
```shell
GET /api/users/user_id ->
GET /api/users/*
```
- Never ignore encoded/hashed ID
```shell
for hashed ID ,create multiple accounts and understand the pattern application users to allot an iD
```
- Google Dorking/public form
```shell
search all the endpoints having ID which the search engine may have already indexed
```
- Bruteforce Hidden HTTP parameters
```shell
use tools like arjun , paramminer 
```
- Bypass object level authorization Add parameter onto the endpoit if not present by defualt:
```shell
GET /api_v1/messages ->200
GET /api_v1/messages?user_id=victim_uuid ->200
```
- HTTP Parameter pollution give multiple value for same parameter:
```shell
GET /api_v1/messages?user_id=attacker_id&user_id=victim_id
GET /api_v1/messages?user_id=victim_id&user_id=attacker_id
```
- change file type:
```shell
GET /user_data/2341        -> 401
GET /user_data/2341.json   -> 200
GET /user_data/2341.xml    -> 200
GET /user_data/2341.config -> 200
GET /user_data/2341.txt    -> 200
```
- json parameter pollution:
```shell
{"userid":1234,"userid":2542}
```
- Wrap the ID with an array in the body:
```shell
{"userid":123} ->401
{"userid":[123]} ->200
```
- wrap the id with a json object:
```shell
{"userid":123} ->401
{"userid":{"userid":123}} ->200
```
- Test an outdata API version:
```shell
GET /v3/users_data/1234 ->401
GET /v1/users_data/1234 ->200
```










---
# Automation
## Nuclei

## Autorize
