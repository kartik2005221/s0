/**
 * Test driver: expose site/verify/verify.js's structural validator to pytest.
 *
 * The browser verifier is a UMD module, so `require()` gives us the same object a
 * browser gets on `window.S0Verifier`. This script reads one certificate from
 * stdin and prints `{"errors": [...]}` so the Python test can compare it against
 * `s0.certificate.validate()` directly.
 *
 * Parity between the two is the property under test. The type-confusion bug
 * shipped in both implementations independently, which is exactly what a
 * "reference implementation" should never do.
 */
const path = require("path");

let verifier;
try {
  verifier = require(path.join(__dirname, "..", "..", "site", "verify", "verify.js"));
} catch (err) {
  process.stderr.write("cannot load verify.js: " + err.message + "\n");
  process.exit(2);
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { raw += chunk; });
process.stdin.on("end", () => {
  let cert;
  try {
    cert = JSON.parse(raw);
  } catch (err) {
    process.stderr.write("driver received non-JSON input: " + err.message + "\n");
    process.exit(3);
  }

  if (typeof verifier.validate !== "function") {
    process.stderr.write("verify.js does not export validate()\n");
    process.exit(4);
  }

  let errors;
  try {
    // requireSignature:true matches how verifyCertificate() calls it, so a
    // certificate with no signature reports the signature error and we can see
    // whether the *sections* also produce errors.
    errors = verifier.validate(cert, { requireSignature: true });
  } catch (err) {
    errors = ["validator threw: " + err.message];
  }

  process.stdout.write(JSON.stringify({ errors: errors || [] }));
});