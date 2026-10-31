// The receiver for scripts/crash.sh. It records every delivery and never answers the first one, so
// the flush is held mid-request with its lease committed while the server gets killed.
//
//   node tests/crash-receiver.mjs <port file> <hits file>
import { createServer } from 'node:http';
import { appendFileSync, writeFileSync } from 'node:fs';

const [portFile, hitsFile] = process.argv.slice(2);
let count = 0;
const server = createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    count++;
    appendFileSync(hitsFile, `${req.headers['webhook-id']}\n`);
    if (count > 1) res.writeHead(200).end();
  });
});
server.listen(0, '127.0.0.1', () => writeFileSync(portFile, String(server.address().port)));
