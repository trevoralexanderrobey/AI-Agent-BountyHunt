const test = require("node:test");
const assert = require("node:assert/strict");

const { createSecretManager } = require("../../security/secret-manager.js");

test("secret manager prepares per-execution secrets and hashes sensitive key names", () => {
  const manager = createSecretManager();
  const prepared = manager.prepareExecutionSecrets(
    {
      API_TOKEN: "super-secret-value",
      GH_TOKEN: "ghp_test_token_value",
    },
    {
      toolSlug: "nmap",
      principalHash: "abcdef0123456789",
    },
  );

  assert.equal(typeof prepared.env.API_TOKEN, "string");
  assert.equal(prepared.secretValues.includes("super-secret-value"), true);

  const logEnv = manager.redactEnvForLogs(prepared.env);
  assert.equal(Object.prototype.hasOwnProperty.call(logEnv, "API_TOKEN"), false);
  assert.equal(Object.keys(logEnv).every((key) => key.startsWith("secret_")), true);
});

test("secret manager blocks filesystem artifact writes containing secrets", () => {
  const manager = createSecretManager();

  assert.throws(
    () =>
      manager.assertNoFilesystemSecretArtifacts(
        [
          {
            kind: "inlineText",
            contents: "token=super-secret-value",
            targetPath: "/scratch/request.json",
          },
        ],
        ["super-secret-value"],
      ),
    (error) => {
      assert.equal(error.code, "SECRET_FILESYSTEM_WRITE_FORBIDDEN");
      return true;
    },
  );
});

test("secret manager redacts accidental secret echo from tool output", () => {
  const manager = createSecretManager();
  const result = manager.redactToolOutput(
    {
      output: "token=super-secret-value",
    },
    ["super-secret-value"],
    {
      toolSlug: "nmap",
      requestId: "req-1",
    },
  );

  assert.equal(result.redacted, true);
  assert.equal(JSON.stringify(result.payload).includes("super-secret-value"), false);
});
