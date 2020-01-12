var net = require('net');

var server = net.createServer(function(socket) {

  let handle = setInterval(()=>{
    const data  = (new Date()).toString() + '\n';
    console.log('writing ', data);
    socket.write(data);
  }, 3000);
  
  socket.on('data', (data) => {
    console.log('got data', data);
  });

  socket.on('end', ()=>{
    console.log('socket closed');
    clearInterval(handle);
  });

});

console.log('TCP server listens on 3002');
server.listen(3002, '127.0.0.1');
