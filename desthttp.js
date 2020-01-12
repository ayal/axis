const http = require('http');
const port = 3001;

const requestHandler = (request, response) => {
  console.log("Got http request >", request.url, request.method);

  // 201 on purpose to check if status is passed correctly to proxy and client
  response.writeHead(201, { 
    'Content-Type': 'text/plain',
    'Custom': 'xxx'
  });
  
  response.flushHeaders();

  response.write(`hello from http destination.\ntime: ${new Date()} \nurl: ${request.url} \nport: ${port} \nmethod: ${request.method} \nwill send more...\n`);
  setTimeout(()=>{
    response.end('done');
  },3000);
};

const server = http.createServer(requestHandler);

server.listen(port, () => {
  console.log(`destination test server is listening on ${port}`);
});
