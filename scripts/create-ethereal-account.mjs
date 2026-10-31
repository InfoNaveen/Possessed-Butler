/**
 * scripts/create-ethereal-account.mjs
 *
 * Creates a disposable Ethereal email account for testing SMTP delivery.
 * Run: node scripts/create-ethereal-account.mjs
 *
 * Ethereal catches all sent emails — nothing actually reaches the internet.
 * Use these credentials in .env.local to test the full SMTP flow.
 * For the judge demo, replace with real Gmail/SMTP credentials.
 */
import nodemailer from "nodemailer";

const account = await nodemailer.createTestAccount();

console.log("\n✅ Ethereal test account created:");
console.log("   Preview URL: https://ethereal.email/messages");
console.log("\nCopy these into your .env.local:\n");
console.log(`SMTP_HOST=smtp.ethereal.email`);
console.log(`SMTP_PORT=587`);
console.log(`SMTP_USER=${account.user}`);
console.log(`SMTP_PASS=${account.pass}`);
console.log(`EMAIL_FROM=The Possessed Butler <${account.user}>`);
console.log(`\nLogin at: https://ethereal.email`);
console.log(`  User: ${account.user}`);
console.log(`  Pass: ${account.pass}`);
console.log("\nAfter adding to .env.local, restart the dev server (Ctrl+C then npm run dev).");
console.log("Then send a test email — it will appear at https://ethereal.email/messages\n");
