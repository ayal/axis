# Running and Testing

Server code is at server.ts (and compiled to server.js)

Clone this repo and run:
```
npm install
```

To compile and run main server (port 8080) use:

```
npm run start
```

Run HTTP test server (port 3001)
```
node desthttp.js
```

Run TCP test server (port 3002)
```
node desttcp.js
```
Then you can test from the browser with:

##HTTP:

From browser, test with:

http://localhost:8080/get?host=localhost&port=3001&path=wonder

http://localhost:8080/get?host=localhost&port=3001&path=wonder

The HTTP test server returns status 201 on puprpose to test status is received correctly on original request

If you use HTTP GET/POST option with the test TCP server endpoint (port 3002) the connection fails, there is a code to identify this after an error is returned

When testing from browser, you might see a failed favicon request in logs, decided not to specifically handle that

##TCP:

From browser, test with:

http://localhost:8080/connect?host=localhost&port=3002

The TCP data will take a while to show on the browser, depends on browser buffering

You can either wait, kill the TCP server, or look at the logs to see the action

Currently if you use the TCP "connect" option with the test HTTP server endpoint (port 3001) the connection works but no data is sent


# Auth
Using [http-auth](https://github.com/http-auth/http-auth) library

User file is users.htpasswd, some passwords are plain text some are hashed with either bcrypt or MD5

Gil's password: gnu (MD5)

Shuky's password: demo (bcrypt)

# Policy
Policy file is policy.json

The format is such that for eacch rule you need to supply all fields with a specific value or a wildcard *

DestinationPort field is of type string so it can be a wildcard

SourceIP field currently has localhost IPv6 values (::1)

In original task it's specificed that destination host field can be host or IP - currently I did not resolve host to ip, so a "block" rule should exist for both to make sure destination host is really blocked

If the policy file would only contain destination IPs (and no hostnames) the following code can ensure the policy is enforced as expected
```
const destIP:string = await resolveDNS(queryhost);
```
Otherwise - i.e if policy must be able to include hostnames (like written in original task) - then a DNS resolve should be done for every policy rule, not currently implemented

# Code
Decided to go with "vanilla" node code (no express)

Sanitizing and policy could have been implemented like "middlewares" passed to createServer (like auth is implemented) but didn't get there
