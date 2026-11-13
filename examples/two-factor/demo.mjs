import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import console from "node:console";
import { createDemoAccount } from "./flow.mjs";

const terminal = createInterface({ input: stdin, output: stdout });
const account = createDemoAccount();
const messages = {
  "already-enrolled": "This demo account already has two-factor enabled.",
  "not-started": "Start enrollment first.",
  "not-enrolled": "Confirm enrollment before trying the sign-in challenge.",
  "enrollment-expired": "Enrollment expired after five minutes. Start enrollment again.",
  "invalid-code": "Code rejected: invalid, outside the time window, or already used.",
};

function show(result, success) {
  if (result.ok) console.log(success);
  else if (result.reason === "locked") console.log(`Too many failures. Try again in ${result.retryAfter}s.`);
  else console.log(messages[result.reason]);
}

console.log("otpkit — local two-factor demo (one temporary account)");
console.log("This demonstrates the SECOND factor only; it is not a complete login system.");
console.log("Use a new authenticator entry for this demo. Do not enter real account secrets.");
console.log("State stays in memory and disappears on exit. Codes you type are visible in this terminal.\n");

try {
  while (true) {
    const choice = await terminal.question(
      "1 Enroll · 2 Confirm enrollment · 3 Sign-in challenge · 4 Exit\n> ",
    );
    if (choice.trim() === "4") break;
    if (choice.trim() === "1") {
      const result = account.enroll();
      if (result.ok) {
        console.log("Add an authenticator entry: account local-demo, issuer otpkit example.");
        console.log("Type: time-based (TOTP), SHA1, 6 digits, 30 seconds.");
        console.log(`Manual setup key: ${result.manualKey}`);
        console.log(`Enrollment URI (contains the same secret): ${result.uri}`);
        console.log(
          "Keep these private. Choose 2 and enter the code from your authenticator within five minutes.",
        );
      } else show(result);
    } else if (choice.trim() === "2") {
      const code = (await terminal.question("Authenticator code: ")).trim();
      show(
        account.confirm(code),
        "Two-factor enabled. Wait for a NEW code before trying the sign-in challenge.",
      );
    } else if (choice.trim() === "3") {
      const code = (await terminal.question("Authenticator code: ")).trim();
      show(account.signIn(code), "Second-factor challenge passed. That code cannot be accepted again.");
    } else console.log("Choose 1, 2, 3, or 4.");
    console.log();
  }
} catch (error) {
  // Ctrl-D closes readline; treat it as a normal local exit.
  if (error.code !== "ERR_USE_AFTER_CLOSE") throw error;
} finally {
  terminal.close();
}
