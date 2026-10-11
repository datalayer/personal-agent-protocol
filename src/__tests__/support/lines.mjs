// JSON lines between a node process and the Python test that spawned it.
import { createInterface } from "node:readline";

export function channel() {
  const waiting = [];
  const queued = [];
  const input = createInterface({ input: process.stdin });
  input.on("line", (line) => {
    if (!line.trim()) return;
    const message = JSON.parse(line);
    const next = waiting.shift();
    if (next) next(message);
    else queued.push(message);
  });
  const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const receive = () =>
    queued.length ? Promise.resolve(queued.shift()) : new Promise((resolve) => waiting.push(resolve));
  return {
    send,
    receive,
    /** Ask the other side and wait for its one answer. */
    async ask(message) {
      send(message);
      return receive();
    },
    close: () => input.close(),
  };
}
