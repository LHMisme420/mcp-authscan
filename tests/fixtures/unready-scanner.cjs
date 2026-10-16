// Never imports the real scanner or writes data. Used only by the startup fixture.
require('node:http').createServer((_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ status: 'starting' }));
}).listen(Number(process.env.VATA_SCANNER_PORT), '127.0.0.1');
