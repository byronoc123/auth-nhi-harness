import { loadGuardrailConfig, assertTargetAllowed, assertReplayPermitted, GuardrailError } from "../dist/policy/guardrails.js";

const cfg = loadGuardrailConfig({ SECONDSIGN_ALLOWLIST: "example.com" });

assertTargetAllowed("https://example.com/x", cfg);
assertTargetAllowed("https://api.example.com/x", cfg);
console.log("allowlist ok");

try {
  assertTargetAllowed("https://evil.io/x", cfg);
  console.error("FAIL: non-allowlisted host was not blocked");
  process.exit(1);
} catch (e) {
  if (!(e instanceof GuardrailError)) throw e;
  console.log("block ok");
}

try {
  assertReplayPermitted(cfg);
  console.error("FAIL: replay should be blocked by default");
  process.exit(1);
} catch (e) {
  if (e.code !== "LEGAL_BLOCKED") throw e;
  console.log("replay-gate ok");
}

console.log("guardrail smoke passed");
