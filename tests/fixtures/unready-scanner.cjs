// Never imports the real scanner or writes data. Used only by the startup fixture.
const readyAt = process.env.VATA_FIXTURE_SCANNER_READY_AFTER_MS
  ? Date.now() + Number(process.env.VATA_FIXTURE_SCANNER_READY_AFTER_MS)
  : Infinity;
require('node:http').createServer((_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ status: Date.now() >= readyAt ? 'ok' : 'starting' }));
}).listen(Number(process.env.VATA_SCANNER_PORT), '127.0.0.1');
