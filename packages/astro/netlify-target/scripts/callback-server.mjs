import http from 'node:http';

const port = Number(process.env.PORT ?? 9909);
const requests = [];

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    const entry = {
      at: new Date().toISOString(),
      method: req.method,
      url: req.url,
      headers: req.headers,
      body,
    };
    requests.push(entry);
    console.log(JSON.stringify(entry, null, 2));

    res.writeHead(200, {
      'content-type': 'text/plain',
      'x-wulf-callback': 'seen',
    });
    res.end('callback seen\n');
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`callback listening on http://127.0.0.1:${port}`);
});

process.on('SIGINT', () => {
  console.log(JSON.stringify({ total_requests: requests.length }, null, 2));
  server.close(() => process.exit(0));
});
