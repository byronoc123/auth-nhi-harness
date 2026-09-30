// HTTP execution adapter — for API-style targets. Injects SecondSign assertion
// headers into the request; first-party/authorized targets only.
import type { Record_ } from "./types.js";

export async function httpExec(
  targetUrl: string,
  actionPayload: Record_,
  headers: Record<string, string>,
): Promise<Record_> {
  const method = (actionPayload.method as string) ?? "GET";
  const body = actionPayload.body as Record_ | undefined;
  const response = await fetch(targetUrl, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  return {
    status: response.status,
    ok: response.ok,
    url: response.url,
    headers_received: Object.fromEntries(response.headers.entries()),
    body_snippet: text.slice(0, 600),
  };
}