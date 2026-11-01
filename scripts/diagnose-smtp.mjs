/**
 * scripts/diagnose-smtp.mjs
 *
 * Safe diagnostic for SMTP connection without logging passwords or secrets.
 */
import fs from "node:fs";
import { validateSmtpConfig, createSmtpMailer } from "../src/tools/email/smtp-mailer.ts";

// Load .env.local without exposing secrets
if (fs.existsSync(".env.local")) {
  const lines = fs.readFileSync(".env.local", "utf8").split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith("#") && trimmed.includes("=")) {
      const idx = trimmed.indexOf("=");
      const k = trimmed.slice(0, idx).trim();
      const v = trimmed.slice(idx + 1).trim();
      process.env[k] = v;
    }
  }
}

console.log("=== SMTP DIAGNOSTIC (CREDENTIAL SAFE) ===");
const val = validateSmtpConfig(process.env);
console.log("Config Valid :", val.valid);
if (!val.valid) {
  console.log("Config Issues:", val.issues);
  process.exit(1);
}

console.log("Host         :", val.config.host);
console.log("Port         :", val.config.port);
console.log("Secure (465) :", val.config.secure);
console.log("STARTTLS(587):", val.config.requireTLS);
console.log("User Config  :", val.config.user ? val.config.user.replace(/(?<=^.).*(?=@)/, "***") : "missing");
console.log("From Config  :", val.config.from ? val.config.from.replace(/(?<=<.).*(?=@)/, "***") : "missing");
console.log("Pass Length  :", val.config.pass?.length ?? 0);

try {
  console.log("\nAttempting connection & auth verification to " + val.config.host + ":" + val.config.port + "...");
  const mailer = await createSmtpMailer(val.config);
  const result = await mailer.verifyConnection();
  console.log("\n>>> Verification Result OK :", result.ok);
  if (!result.ok) {
    console.log(">>> Sanitized Error Detail:", result.error);
  } else {
    console.log(">>> SMTP SERVER ACCEPTED CREDENTIALS AND IS READY TO TRANSMIT EMAILS! <<<");
  }
} catch (err) {
  console.log(">>> Diagnostic Exception:", err.message);
}

