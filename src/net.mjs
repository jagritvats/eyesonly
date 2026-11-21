// fetch with a few retries for idempotent requests.
//
// A keep-alive socket the server already closed (or a proxy hiccup) surfaces as
// ECONNRESET / UND_ERR_SOCKET on the next request. For a GET that's safe to repeat,
// and failing instead can make mode detection guess wrong. HTTP error statuses are
// answers, not network failures, so they are returned as-is and never retried.

const RETRY_CODES = new Set(['ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ETIMEDOUT', 'UND_ERR_SOCKET', 'UND_ERR_CLOSED']);

const transient = (e) => e?.name !== 'AbortError' && e?.name !== 'TimeoutError' && RETRY_CODES.has(e?.cause?.code ?? e?.code);

export async function fetchRetry(url, opts = {}, { tries = 3, delayMs = 200 } = {}) {
  for (let i = 1; ; i++) {
    try {
      return await fetch(url, opts);
    } catch (e) {
      if (i >= tries || !transient(e)) throw e;
      await new Promise((r) => setTimeout(r, delayMs * i));
    }
  }
}
