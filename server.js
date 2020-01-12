"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var net = require('net');
var dns = require("dns");
var http = require("http");
var url = require('url');
var fs = require('fs');
var _ = require('lodash');
var auth = require('http-auth');
var Buffer = require('buffer');
var PORT = 8080;
// not in use, see README
var resolveDNS = (function (host) { return __awaiter(void 0, void 0, void 0, function () {
    return __generator(this, function (_a) {
        return [2 /*return*/, new Promise(function (resolve, reject) {
                dns.lookup(host, { "hints": dns.ADDRCONFIG | dns.V4MAPPED }, function (err, ip, addressType) {
                    if (err)
                        reject(err);
                    resolve(ip);
                });
            })];
    });
}); });
var Access;
(function (Access) {
    Access["ALLOW"] = "allow";
    Access["BLOCK"] = "block";
})(Access || (Access = {}));
// auth library:
var basicAuth = auth.basic({ file: __dirname + "/users.htpasswd" });
// helper for logging
var reqParamsToString = (function (req, params) {
    return req.user + " | " + (req.headers['x-forwarded-for'] || req.socket.remoteAddress) + " | " + params.host + " | " + params.port + " | " + params.method;
});
// helper for matching policy rules to current request
var matchRule = (function (req, params, rule) {
    if (req.user !== rule.sourceUser && rule.sourceUser !== '*') {
        return false;
    }
    if ((req.headers['x-forwarded-for'] || req.socket.remoteAddress) !== rule.sourceIP && rule.sourceIP !== '*') {
        return false;
    }
    // do i need dns lookup here? if not should explicitly add block rule for host AND ip if we want to be on the safe side
    if (params.host !== rule.destinationHost && rule.destinationHost !== '*') {
        return false;
    }
    if (params.port.toString() !== rule.destinationPort && rule.destinationPort !== '*') {
        return false;
    }
    if (params.method !== rule.destinationMethod && rule.destinationMethod !== '*') {
        return false;
    }
    return true;
});
// helper for sanity checks
var errorResponse = function (res, status, message) {
    console.log(message);
    res.writeHead(status);
    res.end(message);
};
var sanitizeRequest = function (allowedMethods, pathname, method, query) {
    if (pathname.indexOf('/favicon') === 0) {
        throw new Error("unsupported pathname " + pathname);
    }
    if (allowedMethods.indexOf(method) === -1) {
        throw new Error("unsupported method " + method);
    }
    if (!query) {
        throw new Error('no query params');
    }
    if (!query.host) {
        throw new Error('no host in query params');
    }
    if (!query.port) {
        throw new Error('no port in query params');
    }
};
// helper for enforcing policy rules
var enforcePolicy = function (req, remoteRequestParams) {
    // reading file here, for each request (and not once) so policy can be changed in file while server is running
    // and server acts accordingly without restart. less efficient but more convenient for testing
    var policyJSON = JSON.parse(fs.readFileSync('policy.json'));
    console.log('trying to match policy with', reqParamsToString(req, remoteRequestParams));
    // find first match in policy
    var match = _.find(policyJSON, function (x) { return matchRule(req, remoteRequestParams, x); });
    if (match) {
        if (match.action === Access.ALLOW) {
            console.log('allowed by rule', Object.values(match).join('|'));
            return true;
        }
        if (match.action === Access.BLOCK) {
            console.log('blocked by rule', Object.values(match).join('|'));
            return false;
        }
    }
    else {
        console.log('no policy match');
    }
    return false;
};
// helper for issuing GET/POST request to destination and piping it back
var doGetPost = function (req, res, remoteRequestParams) {
    console.log('creating http pipe');
    // http proxy pipe
    var newReq = http.request(remoteRequestParams, (function (newRes) {
        res.writeHead(newRes.statusCode, newRes.headers);
        newRes.pipe(res);
        // manual listen for logging
        newRes.on('data', function (data) {
            console.log('Received HTTP data >>>', data.toString('utf8'));
        });
    }));
    // for logging
    newReq.on('close', function (e) {
        console.log('HTTP request closed');
    });
    // for logging
    newReq.on('error', function (e) {
        // identify error of trying to connect HTTP to TCP endpoint
        if (e.code === 'HPE_INVALID_CONSTANT') {
            errorResponse(res, 500, "HTTP request error, malformed response, maybe tried to connect HTTP to TCP endpoint?\n" + e + " " + JSON.stringify(e));
        }
        else {
            errorResponse(res, 500, "HTTP request error: " + e + " " + JSON.stringify(e));
        }
    });
    // pipe request to request
    req.pipe(newReq);
};
// helper for creating TCP connection to destination and piping it back
var doConnect = function (req, res, remoteRequestParams) {
    console.log('creating TCP pipe');
    // TCP proxy pipe
    var client = new net.Socket();
    client.connect(remoteRequestParams.port, remoteRequestParams.host, function () {
        console.log('TCP Connected, piping...');
        res.writeHead(200);
        // pipe TCP client to response
        client.pipe(res);
    });
    // logging and making sure to destory TCP client on error
    client.on('error', function (e) {
        errorResponse(res, 500, "TCP error: " + e);
        client.destroy();
    });
    // manual listen for logging, pipe does the actual data transfer
    client.on('data', function (data) {
        console.log('Received TCP data, writing back to http >', data.toString('utf8'));
    });
    client.on('close', function () {
        console.log('TCP Connection closed');
    });
    // pipe HTTP request to TCP client (don't end prematurely)
    req.pipe(client, { end: false });
    req.on('close', function () {
        console.log('HTTP Connection closed, closing TCP connection');
        client.destroy();
    });
};
// main server
var proxy = http.createServer(basicAuth, function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, pathname, query, querymethod, remoteRequestParams, policyOK;
    return __generator(this, function (_b) {
        _a = url.parse(req.url, true), pathname = _a.pathname, query = _a.query;
        console.log("\n\n>>>> REQUEST >>>>", query, pathname, req.connection.remoteAddress, req.user);
        querymethod = pathname.replace('/', '').toUpperCase();
        // sanity:
        try {
            sanitizeRequest(['CONNECT', 'GET', 'POST'], pathname, querymethod, query);
        }
        catch (sanityEx) {
            errorResponse(res, 500, sanityEx.message);
            return [2 /*return*/];
        }
        remoteRequestParams = {
            host: query.host,
            port: parseInt(query.port),
            path: "/" + (query.path || ''),
            method: querymethod,
            headers: req.headers
        };
        policyOK = enforcePolicy(req, remoteRequestParams);
        if (!policyOK) {
            errorResponse(res, 401, 'Rejected by policy');
            return [2 /*return*/];
        }
        console.log('Policy OK!');
        // Proxy method routing to destination:
        if (querymethod === 'GET' || querymethod === 'POST') {
            doGetPost(req, res, remoteRequestParams);
        }
        else if (querymethod === 'CONNECT') {
            doConnect(req, res, remoteRequestParams);
        }
        else {
            // shouldn't happen
            errorResponse(res, 500, 'bad method');
            return [2 /*return*/];
        }
        return [2 /*return*/];
    });
}); });
console.log("PROXY LISTENING ON " + PORT + ", WAITING...");
proxy.listen(PORT);
process.on('uncaughtException', function (err) {
    console.error(err.stack);
});
