const net = require('net');
const dns = require("dns");
import * as http from 'http';
const url = require('url');
const fs = require('fs');
const _ = require('lodash');
const auth = require('http-auth');
const Buffer = require('buffer');

const PORT:number = 8080;

// not in use, see README
const resolveDNS = (async (host:string):Promise<string> => {
    return new Promise((resolve, reject) => {
	dns.lookup(host, {"hints":dns.ADDRCONFIG | dns.V4MAPPED}, (err:Error, ip:string, addressType:number) => {
	     if(err) reject(err);
             resolve(ip);
	 })
     });
});

// TypeScript definitions
interface IncomingMessageWithUser extends http.IncomingMessage {
    user: string; 
}

interface NodeError extends Error {
  code?: string;
}

enum Access {
    ALLOW = "allow",
    BLOCK = "block"
}

// port is string and not a number both here and in policy file so it can also be a wildcard *
type PolicyRule = {
    sourceUser:string,
    sourceIP:string,
    destinationHost:string,
    destinationPort:string,
    destinationMethod:string,
    action:Access
}

// auth library:
var basicAuth = auth.basic({ file: __dirname + "/users.htpasswd" });

// helper for logging
const reqParamsToString = ((req: IncomingMessageWithUser, params: http.RequestOptions) => {
     return `${req.user} | ${req.headers['x-forwarded-for'] || req.socket.remoteAddress} | ${params.host} | ${params.port} | ${params.method}`;
});

// helper for matching policy rules to current request
const matchRule = ((req: IncomingMessageWithUser, params:http.RequestOptions, rule:PolicyRule) => {
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
const errorResponse = (res:http.ServerResponse, status:number, message:string) => {
    console.log(message);
    res.writeHead(status);
    res.end(message);    
};

const sanitizeRequest = (allowedMethods:string[], pathname:string, method:string, query:any) => {
    if (pathname.indexOf('/favicon') === 0) {
	throw new Error(`unsupported pathname ${pathname}`);
    }
    if (allowedMethods.indexOf(method) === -1) {
	throw new Error(`unsupported method ${method}`);
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
const enforcePolicy = (req, remoteRequestParams) => {
    // reading file here, for each request (and not once) so policy can be changed in file while server is running
    // and server acts accordingly without restart. less efficient but more convenient for testing
    const policyJSON:PolicyRule[] = JSON.parse(fs.readFileSync('policy.json'));
    
    console.log('trying to match policy with', reqParamsToString(req, remoteRequestParams));

    // find first match in policy
    const match = _.find(policyJSON, x=>matchRule(req, remoteRequestParams, x));
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
const doGetPost = (req:http.IncomingMessage, res:http.ServerResponse, remoteRequestParams: http.RequestOptions) => {
    console.log('creating http pipe');
    // http proxy pipe
    const newReq:http.ClientRequest = http.request(remoteRequestParams, ((newRes:http.IncomingMessage) => {
	res.writeHead(newRes.statusCode, newRes.headers);
	newRes.pipe(res);
	
	// manual listen for logging
	newRes.on('data', (data)=>{
	    console.log('Received HTTP data >>>', data.toString('utf8'));
	})
    }));

    // for logging
    newReq.on('close', (e)=>{
	console.log('HTTP request closed');
    })

    
    // for logging
    newReq.on('error', (e:NodeError)=>{
	// identify error of trying to connect HTTP to TCP endpoint
	if (e.code === 'HPE_INVALID_CONSTANT') {
	    errorResponse(res, 500, `HTTP request error, malformed response, maybe tried to connect HTTP to TCP endpoint?\n${e} ${JSON.stringify(e)}`);   
	}
	else {
	    errorResponse(res, 500, `HTTP request error: ${e} ${JSON.stringify(e)}`);
	}
    })

    // pipe request to request
    req.pipe(newReq);
};

// helper for creating TCP connection to destination and piping it back
const doConnect = (req:http.IncomingMessage, res:http.ServerResponse, remoteRequestParams: http.RequestOptions) => {
    console.log('creating TCP pipe');
    // TCP proxy pipe
    var client = new net.Socket();
    client.connect(remoteRequestParams.port, remoteRequestParams.host, () => {
	console.log('TCP Connected, piping...');
	res.writeHead(200);
	// pipe TCP client to response
	client.pipe(res);
    });

    // logging and making sure to destory TCP client on error
    client.on('error', (e:Error) => {
	errorResponse(res, 500, `TCP error: ${e}`);
	client.destroy();
    });
    // manual listen for logging, pipe does the actual data transfer
    client.on('data', (data:Buffer) => {
	console.log('Received TCP data, writing back to http >', data.toString('utf8'));
    });
    
    client.on('close', () => {
	console.log('TCP Connection closed');
    });
    
    // pipe HTTP request to TCP client (don't end prematurely)
    req.pipe(client, {end:false});

    req.on('close', ()=>{
	console.log('HTTP Connection closed, closing TCP connection');
	client.destroy();
    })
}

// main server
const proxy = http.createServer(basicAuth, async (req: IncomingMessageWithUser, res: http.ServerResponse) => {
    const {pathname, query} = url.parse(req.url, true);

    console.log(`\n\n>>>> REQUEST >>>>`, query, pathname, req.connection.remoteAddress, req.user);

    const querymethod:string = pathname.replace('/', '').toUpperCase();
    
    // sanity:
    try {
	sanitizeRequest(['CONNECT', 'GET', 'POST'], pathname, querymethod, query);
    }
    catch (sanityEx) {
	errorResponse(res, 500, sanityEx.message);
	return;
    }

    // params for the destination request
    const remoteRequestParams:http.RequestOptions = {
	host:    query.host,
	port:    parseInt(query.port),
	path:    `/${(query.path || '')}`,
	method: querymethod,
	headers: req.headers
    };
    
    const policyOK:boolean = enforcePolicy(req, remoteRequestParams);
    if (!policyOK) {
	errorResponse(res, 401, 'Rejected by policy');
	return;
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
	return;
    }
});

console.log(`PROXY LISTENING ON ${PORT}, WAITING...`);
proxy.listen(PORT);
process.on('uncaughtException', (err:Error)=> {
    console.error(err.stack);
});
