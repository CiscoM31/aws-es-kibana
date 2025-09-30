#!/usr/bin/env node

const { fromNodeProviderChain, fromIni, fromInstanceMetadata, fromContainerMetadata } = require('@aws-sdk/credential-providers');
const { STSClient } = require('@aws-sdk/client-sts');
const { HttpRequest } = require('@aws-sdk/protocol-http');
const { Sha256 } = require('@aws-crypto/sha256-js');
const { SignatureV4 } = require('@aws-sdk/signature-v4');
var http = require('http');
var httpProxy = require('http-proxy');
var express = require('express');
var bodyParser = require('body-parser');
var stream = require('stream');
var figlet = require('figlet');
var basicAuth = require('express-basic-auth');
var compress = require('compression');
const fs = require('fs');
const homedir = require('os').homedir();

var yargs = require('yargs')
    .usage('usage: $0 [options] <aws-es-cluster-endpoint>')
    .option('b', {
        alias: 'bind-address',
        default: process.env.BIND_ADDRESS || '127.0.0.1',
        demand: false,
        describe: 'the ip address to bind to',
        type: 'string'
    })
    .option('p', {
        alias: 'port',
        default: process.env.PORT || 9200,
        demand: false,
        describe: 'the port to bind to',
        type: 'number'
    })
    .option('r', {
        alias: 'region',
        default: process.env.REGION,
        demand: false,
        describe: 'the region of the Elasticsearch cluster',
        type: 'string'
    })
    .option('u', {
      alias: 'user',
      default: process.env.AUTH_USER ||process.env.USER,
      demand: false,
      describe: 'the username to access the proxy'
    })
    .option('a', {
      alias: 'password',
      default: process.env.AUTH_PASSWORD || process.env.PASSWORD,
      demand: false,
      describe: 'the password to access the proxy'
    })
    .option('s', {
      alias: 'silent',
      default: false,
      demand: false,
      describe: 'remove figlet banner'
    })
    .option('H', {
        alias: 'health-path',
        default: process.env.HEALTH_PATH,
        demand: false,
        describe: 'URI path for health check',
        type: 'string'
    })
    .option('l', {
      alias: 'limit',
      default: process.env.LIMIT || '10000kb',
      demand: false,
      describe: 'request limit'
    })
    .option('c', {
        alias: 'cert',
        default: process.env.CERT || 'yes',
        demand: false,
        describe: 'server cert validation',
        type: 'string'
    })
    .help()
    .version()
    .strict();
var argv = yargs.argv;

var ENDPOINT = process.env.ENDPOINT || argv._[0];

if (!ENDPOINT) {
    yargs.showHelp();
    process.exit(1);
}

// Try to infer the region if it is not provided as an argument.
var REGION = argv.r;
if (!REGION) {
    var m = ENDPOINT.match(/\.([^.]+)\.es\.amazonaws\.com\.?(?=.*$)/);
    if (m) {
        REGION = m[1];
    } else {
        console.error('region cannot be parsed from endpoint address, either the endpoint must end ' +
                      'in .<region>.es.amazonaws.com or --region should be provided as an argument');
        yargs.showHelp();
        process.exit(1);
    }
}

var TARGET = process.env.ENDPOINT || argv._[0];

var BIND_ADDRESS = argv.b;
var PORT = argv.p;
var REQ_LIMIT = argv.l;

var credentialProvider;

var PROFILE = process.env.AWS_PROFILE;

if (!PROFILE) {
    credentialProvider = fromNodeProviderChain({
        timeout: 5000, // 5 second timeout
        maxRetries: 3
    });
} else {
    credentialProvider = fromIni({ profile: PROFILE });
}

// Validate credentials at startup
async function validateCredentials() {
    try {
        const credentials = await credentialProvider();
        return credentials;
    } catch (error) {
        console.error('Failed to load AWS credentials:', error.message);
        throw error;
    }
}

async function getCredentials(req, res, next) {
    try {
        req.credentials = await credentialProvider();
        return next();
    } catch (err) {
        console.error('Credential fetch failed in middleware:', err.message);
        return next(err);
    }
}

var options = {
    changeOrigin: true,
    secure: true
};

var CERT=argv.c;

var SERVER_CA_CERT_PATH = process.env.SERVER_CA_CERT_PATH;

if (CERT == 'yes') {
    if (SERVER_CA_CERT_PATH !== undefined) {
     options.target = {
        host: TARGET,
        protocol: 'https:',
        ca: fs.readFileSync(SERVER_CA_CERT_PATH, 'utf8')
     };
     }else {
       console.error('Server certificate needs to be set in the Environment Variable as SERVER_CA_CERT_PATH');
       yargs.showHelp();
       process.exit(1);
 }
 } else {
     options.target = {
        host: TARGET,
        protocol: 'https:'
     };
 
 }

var proxy = httpProxy.createProxyServer(options);

var app = express();
app.use(compress());
app.use(bodyParser.raw({limit: REQ_LIMIT, type: function() { return true; }}));
app.use(getCredentials);

if (argv.H) {
    app.get(argv.H, function (req, res) {
        res.setHeader('Content-Type', 'text/plain');
        res.send('ok');
    });
}

if (argv.u && argv.a) {
  var users = {};
  var user = process.env.USER || process.env.AUTH_USER;
  var pass = process.env.PASSWORD || process.env.AUTH_PASSWORD;

  users[user] = pass;

  app.use(basicAuth({
    users: users,
    challenge: true
  }));
}

app.use(async function (req, res) {
    try {
        const credentials = await credentialProvider();
        
        // Validate credentials are properly loaded
        if (!credentials || !credentials.accessKeyId || !credentials.secretAccessKey) {
            console.error('Invalid AWS credentials received');
            return res.status(500).json({ error: 'AWS credentials not properly configured' });
        }
        
        // Parse the URL to get the hostname
        const fullUrl = ENDPOINT.startsWith('http') ? ENDPOINT : `https://${ENDPOINT}`;
        const url = new URL(fullUrl);
        const hostname = url.hostname;
        
        // Handle Kibana Dev Tools proxy requests
        let actualMethod = req.method;
        let actualPath = req.url;
        let actualBody = undefined; // Start with undefined instead of empty buffer
        
        // Properly handle request body
        if (Buffer.isBuffer(req.body) && req.body.length > 0) {
            actualBody = req.body;
        } else if (req.body && typeof req.body === 'string' && req.body.length > 0) {
            actualBody = Buffer.from(req.body, 'utf8');
        }
        
        // Check if this is a Kibana Dev Tools request
        if (req.url.startsWith('/_dashboards/api/console/proxy')) {
            const urlObj = new URL(req.url, 'http://localhost');
            const method = urlObj.searchParams.get('method');
            const path = urlObj.searchParams.get('path');
            
            if (method && path) {
                actualMethod = method;
                actualPath = '/' + decodeURIComponent(path);
                // For GET/HEAD requests, clear the body
                if (method === 'GET' || method === 'HEAD') {
                    actualBody = undefined;
                }
                // For POST/PUT/etc., keep the original body which contains the ES request
            }
        }

        // Create headers for AWS request
        const awsHeaders = {
            'host': hostname
        };
        
        // Add content-type for requests with body
        if (actualBody && actualMethod !== 'GET' && actualMethod !== 'HEAD') {
            awsHeaders['content-type'] = 'application/json';
        }
        
        const awsRequest = new HttpRequest({
            method: actualMethod,
            hostname: hostname,
            path: actualPath,
            protocol: 'https:',
            headers: awsHeaders,
            body: actualBody // This will be undefined for GET requests, proper Buffer for POST
        });

        // Create the signer using proper AWS SDK classes
        const signer = new SignatureV4({
            service: 'es',
            region: REGION,
            credentials: credentials,
            sha256: Sha256
        });

        // Sign the request
        let signedRequest;
        try {
            // Debug logging
            console.log('Signing request:', {
                method: actualMethod,
                path: actualPath,
                hasBody: !!actualBody,
                bodyLength: actualBody ? actualBody.length : 0,
                headers: Object.keys(awsHeaders)
            });
            
            signedRequest = await signer.sign(awsRequest);
            
        } catch (signingError) {
            // Log failed requests to help debug Kibana index discovery issues
            console.error('AWS request signing failed:', signingError.message);
            console.error('Failed request details:', {
                method: actualMethod,
                path: actualPath,
                hasBody: actualBody.length > 0
            });
            throw signingError;
        }

        // Copy AWS headers to the request
        for (const [headerName, headerValue] of Object.entries(signedRequest.headers)) {
            req.headers[headerName] = headerValue;
        }

        // For Kibana Dev Tools requests, rewrite the request URL and method before proxying
        if (req.url.startsWith('/_dashboards/api/console/proxy')) {
            req.method = actualMethod;
            req.url = actualPath;
            // For requests with body content, ensure the body is properly set
            if (actualBody) {
                req.body = actualBody;
            }
        }

        var bufferStream;
        if (actualBody && actualBody.length > 0) {
            var bufferStream = new stream.PassThrough();
            await bufferStream.end(actualBody);
        }
        proxy.web(req, res, {buffer: bufferStream});
    } catch (error) {
        console.error('Error signing request:', error);
        res.status(500).send('Error signing request');
    }
});



proxy.on('proxyRes', function (proxyReq, req, res) {
    if (req.url.match(/\.(css|js|img|font)/)) {
        res.setHeader('Cache-Control', 'public, max-age=86400');
    }
});

proxy.on('error', function (err, req, res) {
    console.error('Proxy error:', err.message);
    console.error('Request details:', {
        method: req.method,
        url: req.url,
        headers: req.headers
    });
    res.writeHead(500, {
        'Content-Type': 'text/plain'
    });
    res.end('Proxy error: ' + err.message);
});

// Validate credentials before starting server
validateCredentials().then(() => {
    http.createServer(app).listen(PORT, BIND_ADDRESS);
    
    if(!argv.s) {
        console.log(figlet.textSync('AWS ES Proxy!', {
            font: 'Speed',
            horizontalLayout: 'default',
            verticalLayout: 'default'
        }));
    }
    
    console.log('AWS ES cluster available at http://' + BIND_ADDRESS + ':' + PORT);
    console.log('Kibana available at http://' + BIND_ADDRESS + ':' + PORT + '/_plugin/kibana/');
    if (argv.H) {
        console.log('Health endpoint enabled at http://' + BIND_ADDRESS + ':' + PORT + argv.H);
    }
}).catch((error) => {
    console.error('Startup failed - cannot load AWS credentials:', error.message);
    process.exit(1);
});

fs.watch(`${homedir}/.aws/credentials`, (eventType, filename) => {
    if (PROFILE) {
        credentialProvider = fromIni({ profile: PROFILE });
    } else {
        credentialProvider = fromNodeProviderChain();
    }
});
