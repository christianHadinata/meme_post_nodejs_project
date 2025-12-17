import https from 'https';
import http from 'http';
import fs from 'fs';

//config
const proxyPort = 443; // HTTPS Default
const targetHost = 'localhost';
const targetPort = 3000; // port app.js (di-hardcode karena reverse proxy ini hanya digunakan untuk server tersebut. Kecuali reverse proxy ini akan menjadi virtual host)

//ssl certificates
//harus digenerate menggunakan: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

const proxy = https.createServer(options);

proxy.on('request', (clientReq, clientRes) => {

  //memparse dan format Forwarded header RFC 7239
  //mengambil IP client
  const remoteAddress = clientReq.socket.remoteAddress;
  //jika IP berbentuk IPv6, akan diberikan format "[xxxx:xxxx::xx]" karena terdapat colon yang juga merupakan separator pada RFC 7239
  const clientIp = remoteAddress.includes(':') ? `"[${remoteAddress}]"` : remoteAddress;
  
  //membuat forwardedHeader dengan format for {sumber request}; protocol = https (agar sesuai dengan permintaan); host {port proxy}
  const forwardedHeader = `for=${clientIp};proto=https;host=${clientReq.headers.host}`;

  //mengambil header yang sudah ada pada request
  const proxyHeaders = { ...clientReq.headers};

  //menambahkan header RFC 7239 (jika sudah ada, append saja)
  const existingForwarded = clientReq.headers['forwarded'];
  proxyHeaders['Forwarded'] = existingForwarded ? `${existingForwarded}, ${forwardedHeader}` : forwardedHeader;

  //menambahkan header sebagaimana standar IETF
  proxyHeaders['X-Forwarded-For'] = (clientReq.headers['x-forwarded-for'] ? clientReq.headers['x-forwarded-for'] + ', ' : '') + remoteAddress;

  //protocol yang digunakan client adalah https
  proxyHeaders['X-Forwarded-Proto'] = 'https';
  //meneruskan host yang digunakan oleh client
  proxyHeaders['X-Forwarded-Host'] = clientReq.headers.host;

  //membuat request baru untuk server asil
  const serverReq = http.request({
    host: targetHost,
    port: targetPort,
    method: clientReq.method,
    path: clientReq.url,
    headers: proxyHeaders
  });

  //mengirim request body dari client ke server asli
  clientReq.pipe(serverReq);

  //handle respose dari server asli
  serverReq.on('response', (serverRes) => {
    
    //mengirim isi dari response ke client
    clientRes.writeHead(serverRes.statusCode, serverRes.headers);
    serverRes.pipe(clientRes);
  });

  //error handling
  serverReq.on('error', (err) => {
    console.error('Proxy Error:', err.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
      clientRes.end('Bad Gateway: Main Application is Offline');
    }
  });
});

//mulai reverse proxy dengan port yang sudah ditentukan
proxy.listen(proxyPort, () => {
  console.log(`Secure Proxy running on https://localhost:${proxyPort}`);
  console.log(`Forwarding to http://${targetHost}:${targetPort}`);
});