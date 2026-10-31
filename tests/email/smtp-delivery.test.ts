import { describe, expect, it } from "vitest";
import {
  validateSmtpConfig,
  smtpConfigFromEnv,
  sanitizeSmtpError,
  createMockMailer,
  createSmtpMailer,
} from "@/tools/email/smtp-mailer";

describe("SMTP Configuration & Connection Verification", () => {
  it("1. Validates SMTP configuration successfully with all required variables", () => {
    const env = {
      SMTP_HOST: "smtp.gmail.com",
      SMTP_PORT: "587",
      SMTP_USER: "test@gmail.com",
      SMTP_PASS: "supersecretpass123",
      EMAIL_FROM: "The Possessed Butler <test@gmail.com>",
    };

    const res = validateSmtpConfig(env);
    expect(res.valid).toBe(true);
    expect(res.issues).toHaveLength(0);
    expect(res.config).toMatchObject({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      requireTLS: true,
      user: "test@gmail.com",
      from: "The Possessed Butler <test@gmail.com>",
    });
    // Ensure helper returns config
    expect(smtpConfigFromEnv(env)).not.toBeNull();
  });

  it("1b. Fails validation when required variables are missing without exposing secret values", () => {
    const env = {
      SMTP_HOST: "",
      SMTP_PORT: "not-a-number",
      SMTP_USER: "test@gmail.com",
      SMTP_PASS: "",
      // EMAIL_FROM missing
    };

    const res = validateSmtpConfig(env);
    expect(res.valid).toBe(false);
    expect(res.config).toBeNull();
    expect(res.issues).toEqual(
      expect.arrayContaining([
        "SMTP_HOST is required",
        "SMTP_PASS is required",
        "EMAIL_FROM is required",
        expect.stringContaining("SMTP_PORT must be a valid port number"),
      ]),
    );

    // Verify secret values are not leaked into issue messages
    const issueText = res.issues.join("; ");
    expect(issueText).not.toContain("supersecret");
    expect(smtpConfigFromEnv(env)).toBeNull();
  });

  it("2. Verifies SMTP connection through controlled mock mailer", async () => {
    const mockMailer = createMockMailer();
    const result = await mockMailer.verifyConnection();
    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("3. Sends email successfully through controlled test provider", async () => {
    const mockMailer = createMockMailer();
    const result = await mockMailer.send({
      to: ["recipient@example.com"],
      subject: "Test Subject",
      body: "Hello from Possessed Butler",
    });

    expect(result.accepted).toContain("recipient@example.com");
    expect(result.rejected).toHaveLength(0);
    expect(result.messageId).toContain("@possessed-butler.local");

    const sent = mockMailer.sent();
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toEqual(["recipient@example.com"]);
    expect(sent[0].subject).toBe("Test Subject");
    expect(sent[0].body).toBe("Hello from Possessed Butler");
  });

  it("4. Handles provider recipient rejection properly", async () => {
    const mockMailer = createMockMailer();
    mockMailer.failNext(new Error("550 5.1.1 User unknown"));

    await expect(
      mockMailer.send({
        to: ["invalid-recipient@nonexistent.domain"],
        subject: "Test",
        body: "Test",
      }),
    ).rejects.toThrow("User unknown");
  });

  it("5. Handles SMTP authentication failure and sanitizes passwords", async () => {
    const secretPass = "my-ultra-secret-password-xyz";
    const authError = new Error(`535-5.7.8 Username and Password not accepted with pass ${secretPass}`);
    (authError as unknown as Record<string, unknown>)["code"] = "EAUTH";

    const sanitized = sanitizeSmtpError(authError, secretPass, "test@gmail.com");
    expect(sanitized).not.toContain(secretPass);
    expect(sanitized).toContain("SMTP authentication failed");

    // Also verify mock mailer reporting connection verification failure
    const mockMailer = createMockMailer();
    mockMailer.setVerifyFailure(authError);
    const verifyRes = await mockMailer.verifyConnection();
    expect(verifyRes.ok).toBe(false);
    expect(verifyRes.error).not.toContain(secretPass);
    expect(verifyRes.error).toContain("SMTP authentication failed");
  });

  it("6. Handles SMTP connection failure / timeout cleanly without leaking credentials", async () => {
    const secretPass = "secret123";
    const timeoutError = new Error(`Connection timeout after 10000ms sending auth with ${secretPass}`);
    (timeoutError as unknown as Record<string, unknown>)["code"] = "ETIMEDOUT";

    const sanitized = sanitizeSmtpError(timeoutError, secretPass);
    expect(sanitized).not.toContain(secretPass);
    expect(sanitized).toContain("SMTP connection timed out");

    const refusedError = new Error(`connect ECONNREFUSED 127.0.0.1:587 for ${secretPass}`);
    (refusedError as unknown as Record<string, unknown>)["code"] = "ECONNREFUSED";
    const sanitizedRefused = sanitizeSmtpError(refusedError, secretPass);
    expect(sanitizedRefused).not.toContain(secretPass);
    expect(sanitizedRefused).toContain("SMTP connection refused");
  });
});
