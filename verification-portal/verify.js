/**
 * TrustWipe Verification Engine (JavaScript Reference Implementation)
 *
 * Implements:
 *  1. TrustWipe Canonical JSON v1 (core/CANONICAL_JSON.md)
 *  2. Schema v1.0.0 validator (mirroring core/cert_schema.json and core/python/certificate.py)
 *  3. Ed25519 cryptographic signature verifier against pinned issuer keys
 *
 * Zero external dependencies. Works in browsers, Web Workers, and Node.js.
 */
(function(root, factory) {
  if (typeof define === "function" && define.amd) {
    define(["./vendor/crypto-bundle"], factory);
  } else if (typeof module === "object" && module.exports) {
    var crypto = require("./vendor/crypto-bundle");
    module.exports = factory(crypto);
  } else {
    root.TrustWipeVerifier = factory(root.TrustWipeCrypto);
  }
}(typeof self !== "undefined" ? self : this, function(Crypto) {
  "use strict";

  if (!Crypto) {
    throw new Error("TrustWipeCrypto bundle is required before loading verify.js");
  }

  var SCHEMA_VERSION = "1.0.0";

  var WIPE_METHODS = [
    "OVERWRITE_ZERO_1PASS",
    "SHRED_RANDOM_NPASS",
    "BLKDISCARD",
    "ATA_SECURE_ERASE",
    "ATA_SECURE_ERASE_ENHANCED",
    "NVME_FORMAT_USER_DATA_ERASE",
    "NVME_FORMAT_CRYPTO_ERASE",
    "NVME_SANITIZE_BLOCK_ERASE",
    "NVME_SANITIZE_CRYPTO_ERASE",
    "WINDOWS_CLEAN_ALL",
    "WINDOWS_CIPHER_W",
    "WINDOWS_SED_KEY_DESTROY",
    "ANDROID_FACTORY_RESET_FBE",
    "ANDROID_USER_SPACE_OVERWRITE"
  ];

  var NIST_CATEGORIES = ["Clear", "Purge", "Destroy"];
  var PATTERNS = ["zero", "random", "firmware", "key_destruction"];
  var STATUSES = ["success", "failure", "partial", "reset_triggered"];
  var DEVICE_TYPES = ["internal_disk", "removable_disk", "image_file", "phone"];
  var STORAGE_TYPES = ["HDD", "SSD", "NVMe", "eMMC", "UFS", "SDCARD", "IMAGE_FILE", "UNKNOWN"];
  var PLATFORMS = ["linux", "windows", "android"];

  var METHOD_TIERS = {
    "OVERWRITE_ZERO_1PASS": ["Clear"],
    "SHRED_RANDOM_NPASS": ["Clear"],
    "BLKDISCARD": ["Clear", "Purge"],
    "ATA_SECURE_ERASE": ["Purge"],
    "ATA_SECURE_ERASE_ENHANCED": ["Purge"],
    "NVME_FORMAT_USER_DATA_ERASE": ["Purge"],
    "NVME_FORMAT_CRYPTO_ERASE": ["Purge"],
    "NVME_SANITIZE_BLOCK_ERASE": ["Purge"],
    "NVME_SANITIZE_CRYPTO_ERASE": ["Purge"],
    "WINDOWS_CLEAN_ALL": ["Clear"],
    "WINDOWS_CIPHER_W": ["Clear"],
    "WINDOWS_SED_KEY_DESTROY": ["Purge"],
    "ANDROID_FACTORY_RESET_FBE": ["Purge"],
    "ANDROID_USER_SPACE_OVERWRITE": ["Clear"]
  };

  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  var DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  var FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;
  var B64URL_RE = /^[A-Za-z0-9_-]+$/;

  // -------------------------------------------------------------------------
  // Canonical JSON v1
  // -------------------------------------------------------------------------
  function compareCodePoints(a, b) {
    var cpA = Array.from(a).map(function(c) { return c.codePointAt(0); });
    var cpB = Array.from(b).map(function(c) { return c.codePointAt(0); });
    var minLen = Math.min(cpA.length, cpB.length);
    for (var i = 0; i < minLen; i++) {
      if (cpA[i] !== cpB[i]) return cpA[i] - cpB[i];
    }
    return cpA.length - cpB.length;
  }

  function escapeJsonString(str) {
    var res = '"';
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      var code = str.charCodeAt(i);
      if (ch === '"') res += '\\"';
      else if (ch === "\\") res += "\\\\";
      else if (ch === "\b") res += "\\b";
      else if (ch === "\f") res += "\\f";
      else if (ch === "\n") res += "\\n";
      else if (ch === "\r") res += "\\r";
      else if (ch === "\t") res += "\\t";
      else if (code < 0x20) {
        res += "\\u00" + (code < 16 ? "0" : "") + code.toString(16).toLowerCase();
      } else {
        res += ch;
      }
    }
    res += '"';
    return res;
  }

  function canonicalizeValue(val, out) {
    if (typeof val === "boolean") {
      out.push(val ? "true" : "false");
    } else if (val === null) {
      out.push("null");
    } else if (typeof val === "number") {
      if (!Number.isInteger(val) || !Number.isFinite(val)) {
        throw new Error("float values are not representable in TrustWipe Canonical JSON v1");
      }
      out.push(val.toString(10));
    } else if (typeof val === "bigint") {
      out.push(val.toString(10));
    } else if (typeof val === "string") {
      out.push(escapeJsonString(val));
    } else if (Array.isArray(val)) {
      out.push("[");
      for (var i = 0; i < val.length; i++) {
        if (i > 0) out.push(",");
        canonicalizeValue(val[i], out);
      }
      out.push("]");
    } else if (typeof val === "object") {
      var keys = Object.keys(val);
      keys.sort(compareCodePoints);
      out.push("{");
      for (var j = 0; j < keys.length; j++) {
        if (j > 0) out.push(",");
        var k = keys[j];
        out.push(escapeJsonString(k));
        out.push(":");
        canonicalizeValue(val[k], out);
      }
      out.push("}");
    } else {
      throw new Error("type not representable in canonical JSON: " + typeof val);
    }
  }

  function canonicalizeStr(val) {
    var out = [];
    canonicalizeValue(val, out);
    return out.join("");
  }

  function canonicalize(val) {
    return Crypto.utf8ToBytes(canonicalizeStr(val));
  }

  function payloadOf(cert) {
    var p = {};
    for (var k in cert) {
      if (Object.prototype.hasOwnProperty.call(cert, k) && k !== "signature") {
        p[k] = cert[k];
      }
    }
    return p;
  }

  // -------------------------------------------------------------------------
  // Schema & Structural Validation
  // -------------------------------------------------------------------------
  function walkFloats(node, path, errs) {
    if (typeof node === "boolean" || node === null || node === undefined) return;
    if (typeof node === "number" && !Number.isInteger(node)) {
      errs.push(path + ": float values are forbidden in schema v1");
    } else if (Array.isArray(node)) {
      for (var i = 0; i < node.length; i++) {
        walkFloats(node[i], path + "[" + i + "]", errs);
      }
    } else if (typeof node === "object") {
      for (var k in node) {
        if (Object.prototype.hasOwnProperty.call(node, k)) {
          walkFloats(node[k], path + "." + k, errs);
        }
      }
    }
  }

  function validate(cert, options) {
    var requireSignature = (options && options.requireSignature !== undefined) ? options.requireSignature : true;
    var errs = [];

    function need(cond, msg) {
      if (!cond) errs.push(msg);
    }

    function checkObj(obj, name, required, allowed) {
      var keys = Object.keys(obj);
      for (var i = 0; i < required.length; i++) {
        if (keys.indexOf(required[i]) === -1) {
          errs.push((name ? name + ": " : "") + "missing required field '" + required[i] + "'");
        }
      }
      for (var j = 0; j < keys.length; j++) {
        if (allowed.indexOf(keys[j]) === -1) {
          errs.push((name ? name + ": " : "") + "unexpected field '" + keys[j] + "'");
        }
      }
    }

    if (!cert || typeof cert !== "object" || Array.isArray(cert)) {
      return ["certificate must be a JSON object"];
    }

    checkObj(cert, "",
      ["schema_version", "cert_uuid", "issued_at", "issuer", "tool", "device", "wipe", "result"],
      ["schema_version", "cert_uuid", "issued_at", "issuer", "tool", "device", "wipe", "result", "notes", "signature"]
    );

    need(cert.schema_version === SCHEMA_VERSION, "schema_version must be " + JSON.stringify(SCHEMA_VERSION));
    need(UUID_RE.test(String(cert.cert_uuid || "")), "cert_uuid: not a lowercase UUID");
    need(DATETIME_RE.test(String(cert.issued_at || "")), "issued_at: must be ISO 8601 UTC 'YYYY-MM-DDTHH:MM:SSZ'");

    var issuer = cert.issuer || {};
    if (typeof issuer === "object" && !Array.isArray(issuer)) {
      checkObj(issuer, "issuer", ["organization", "operator_id"], ["organization", "operator_id"]);
      need(typeof issuer.organization === "string" && issuer.organization.length > 0, "issuer.organization: non-empty string required");
      need(typeof issuer.operator_id === "string" && issuer.operator_id.length > 0, "issuer.operator_id: non-empty string required");
    }

    var tool = cert.tool || {};
    if (typeof tool === "object" && !Array.isArray(tool)) {
      checkObj(tool, "tool", ["name", "version", "platform"], ["name", "version", "platform", "os_kernel"]);
      need(PLATFORMS.indexOf(tool.platform) !== -1, "tool.platform: invalid");
    }

    var device = cert.device || {};
    if (typeof device === "object" && !Array.isArray(device)) {
      checkObj(device, "device",
        ["device_id", "device_type", "storage_type", "capacity_bytes"],
        ["device_id", "device_type", "storage_type", "model", "serial_number", "capacity_bytes", "sector_size"]
      );
      need(DEVICE_TYPES.indexOf(device.device_type) !== -1, "device.device_type: invalid");
      need(STORAGE_TYPES.indexOf(device.storage_type) !== -1, "device.storage_type: invalid");
      if (device.capacity_bytes !== undefined) {
        need(Number.isInteger(device.capacity_bytes) && device.capacity_bytes >= 0, "device.capacity_bytes: non-negative integer required");
      }
      if (device.sector_size !== undefined && device.sector_size !== null) {
        need(Number.isInteger(device.sector_size) && device.sector_size >= 0, "device.sector_size: non-negative integer required");
      }
    }

    var wipe = cert.wipe || {};
    if (typeof wipe === "object" && !Array.isArray(wipe)) {
      checkObj(wipe, "wipe",
        ["method", "nist_category", "start_time", "end_time", "bytes_processed"],
        ["method", "nist_category", "passes", "pattern", "start_time", "end_time", "bytes_processed"]
      );
      need(WIPE_METHODS.indexOf(wipe.method) !== -1, "wipe.method: invalid");
      need(NIST_CATEGORIES.indexOf(wipe.nist_category) !== -1, "wipe.nist_category: invalid");
      if (WIPE_METHODS.indexOf(wipe.method) !== -1 && NIST_CATEGORIES.indexOf(wipe.nist_category) !== -1) {
        var permittedTiers = METHOD_TIERS[wipe.method] || [];
        need(permittedTiers.indexOf(wipe.nist_category) !== -1,
          "wipe.nist_category '" + wipe.nist_category + "' exceeds permitted tier for method '" + wipe.method + "'");
        if (wipe.method === "BLKDISCARD" && wipe.nist_category === "Purge") {
          var notesText = (cert.notes || []).join(" ").toLowerCase();
          need(notesText.indexOf("deterministic") !== -1 || notesText.indexOf("drat") !== -1 || notesText.indexOf("rzat") !== -1,
            "BLKDISCARD claiming Purge requires documented deterministic-read-after-discard justification in notes");
        }
      }
      if (wipe.pattern !== undefined && wipe.pattern !== null) {
        need(PATTERNS.indexOf(wipe.pattern) !== -1, "wipe.pattern: invalid");
      }
      if (wipe.passes !== undefined && wipe.passes !== null) {
        need(Number.isInteger(wipe.passes) && wipe.passes >= 1, "wipe.passes: integer >= 1 required");
      }
      need(DATETIME_RE.test(String(wipe.start_time || "")), "wipe.start_time: must be 'YYYY-MM-DDTHH:MM:SSZ'");
      need(DATETIME_RE.test(String(wipe.end_time || "")), "wipe.end_time: must be 'YYYY-MM-DDTHH:MM:SSZ'");
      need(Number.isInteger(wipe.bytes_processed) && wipe.bytes_processed >= 0, "wipe.bytes_processed: non-negative integer required");
    }

    var result = cert.result || {};
    if (typeof result === "object" && !Array.isArray(result)) {
      checkObj(result, "result", ["status"], ["status", "errors", "verification"]);
      need(STATUSES.indexOf(result.status) !== -1, "result.status: invalid");
      if (result.errors !== undefined && result.errors !== null) {
        need(Array.isArray(result.errors) && result.errors.every(function(e) { return typeof e === "string"; }), "result.errors: array of strings");
      }
      if (result.verification !== undefined && result.verification !== null) {
        if (typeof result.verification !== "object" || Array.isArray(result.verification)) {
          errs.push("result.verification: must be an object");
        } else {
          checkObj(result.verification, "result.verification", [],
            ["method", "samples_checked", "sample_bytes_each", "all_samples_match_wipe_pattern", "planted_pattern_hits_after", "pre_wipe_sample_hash"]
          );
        }
      }
    }

    if (cert.notes !== undefined && cert.notes !== null) {
      need(Array.isArray(cert.notes) && cert.notes.every(function(n) { return typeof n === "string"; }), "notes: array of strings");
    }

    var sig = cert.signature;
    if (requireSignature) {
      need(sig && typeof sig === "object" && !Array.isArray(sig), "signature: required object");
      if (sig && typeof sig === "object") {
        checkObj(sig, "signature",
          ["algorithm", "public_key_fingerprint", "signature_base64url"],
          ["algorithm", "public_key_fingerprint", "signature_base64url", "signed_payload_hash"]
        );
        need(sig.algorithm === "Ed25519", "signature.algorithm: only Ed25519 supported");
        need(FINGERPRINT_RE.test(String(sig.public_key_fingerprint || "")), "signature.public_key_fingerprint: must match sha256:<64 hex>");
        need(B64URL_RE.test(String(sig.signature_base64url || "").replace(/=+$/, "")) && String(sig.signature_base64url || "").length >= 80,
          "signature.signature_base64url: not a plausible base64url signature");
        if (sig.signed_payload_hash !== undefined && sig.signed_payload_hash !== null) {
          need(FINGERPRINT_RE.test(String(sig.signed_payload_hash)), "signature.signed_payload_hash: must match sha256:<64 hex>");
        }
      }
    }

    walkFloats(payloadOf(cert), "$", errs);
    return errs;
  }

  // -------------------------------------------------------------------------
  // Certificate Verification
  // -------------------------------------------------------------------------
  function verifyCertificate(cert, trustedKeys) {
    if (!trustedKeys || (Array.isArray(trustedKeys) && trustedKeys.length === 0)) {
      return {
        ok: false,
        status: "NO_TRUSTED_KEYS",
        reason: "No trusted public keys supplied to verifier",
        errors: ["no trusted public keys provided"]
      };
    }

    var keysList = Array.isArray(trustedKeys) ? trustedKeys : [trustedKeys];
    var normKeys = [];

    for (var i = 0; i < keysList.length; i++) {
      var k = keysList[i];
      if (typeof k === "string") {
        if (k.indexOf("-----BEGIN") !== -1) {
          try {
            normKeys.push(Crypto.parseSpkiPem(k));
          } catch (e) {
            // ignore invalid PEM format
          }
        } else if (k.length === 64) {
          try {
            normKeys.push(Crypto.rawPublicKeyToSpki(Crypto.hexToBytes(k)));
          } catch (e) {}
        }
      } else if (typeof k === "object" && k !== null) {
        if (k.public_key_spki_pem) {
          try {
            var parsed = Crypto.parseSpkiPem(k.public_key_spki_pem);
            parsed.issuer = k.issuer || "Unknown Issuer";
            normKeys.push(parsed);
          } catch (e) {}
        } else if (k.rawPublicKeyBytes && k.fingerprint) {
          normKeys.push(k);
        } else if (k.public_key_raw_hex) {
          try {
            var pRaw = Crypto.rawPublicKeyToSpki(Crypto.hexToBytes(k.public_key_raw_hex));
            pRaw.issuer = k.issuer || "Unknown Issuer";
            normKeys.push(pRaw);
          } catch (e) {}
        }
      }
    }

    if (normKeys.length === 0) {
      return {
        ok: false,
        status: "INVALID_KEY_FORMAT",
        reason: "Failed to parse any trusted public key",
        errors: ["none of the provided trusted keys could be parsed"]
      };
    }

    var schemaErrors = validate(cert, { requireSignature: true });
    if (schemaErrors.length > 0) {
      return {
        ok: false,
        status: "SCHEMA_INVALID",
        reason: "Certificate structure failed validation: " + schemaErrors.join("; "),
        errors: schemaErrors
      };
    }

    var payloadStr;
    var payloadBytes;
    var computedHash;

    try {
      var payloadObj = payloadOf(cert);
      payloadStr = canonicalizeStr(payloadObj);
      payloadBytes = Crypto.utf8ToBytes(payloadStr);
      computedHash = "sha256:" + Crypto.sha256Hex(payloadBytes);
    } catch (exc) {
      return {
        ok: false,
        status: "CANONICALIZATION_FAILED",
        reason: "Cannot compute canonical payload: " + (exc.message || exc),
        errors: [exc.message || String(exc)]
      };
    }

    var claimedFp = cert.signature.public_key_fingerprint;
    var sigB64 = cert.signature.signature_base64url;
    var sigBytes;
    try {
      sigBytes = Crypto.base64UrlToBytes(sigB64);
    } catch (e) {
      return {
        ok: false,
        status: "SIGNATURE_DECODE_FAILED",
        reason: "Signature base64url decoding failed",
        errors: ["invalid base64url signature encoding"]
      };
    }

    var matchingKeys = normKeys.filter(function(k) {
      return k.fingerprint === claimedFp;
    });

    if (matchingKeys.length === 0) {
      return {
        ok: false,
        status: "UNTRUSTED_ISSUER",
        reason: "Unknown issuer key fingerprint " + claimedFp + " — certificate was not issued by any pinned authority",
        computedPayloadHash: computedHash,
        claimedFingerprint: claimedFp,
        canonicalPayload: payloadStr,
        errors: ["claimed key fingerprint not present in pinned trust store"]
      };
    }

    for (var j = 0; j < matchingKeys.length; j++) {
      var keyObj = matchingKeys[j];
      var isValid = Crypto.ed25519Verify(payloadBytes, sigBytes, keyObj.rawPublicKeyBytes);
      if (isValid) {
        return {
          ok: true,
          status: "AUTHENTIC",
          reason: "Valid Ed25519 signature from pinned key " + claimedFp + "; payload sha256 " + computedHash,
          issuer: keyObj.issuer || cert.issuer.organization,
          fingerprint: claimedFp,
          computedPayloadHash: computedHash,
          claimedPayloadHash: cert.signature.signed_payload_hash,
          canonicalPayload: payloadStr
        };
      }
    }

    return {
      ok: false,
      status: "TAMPERED_OR_CORRUPT",
      reason: "Signature does NOT match payload — the certificate content has been modified after signing, or the signature is corrupt",
      fingerprint: claimedFp,
      computedPayloadHash: computedHash,
      claimedPayloadHash: cert.signature.signed_payload_hash,
      canonicalPayload: payloadStr,
      errors: ["Ed25519 signature verification failed"]
    };
  }

  return {
    SCHEMA_VERSION: SCHEMA_VERSION,
    WIPE_METHODS: WIPE_METHODS,
    NIST_CATEGORIES: NIST_CATEGORIES,
    METHOD_TIERS: METHOD_TIERS,
    canonicalizeStr: canonicalizeStr,
    canonicalize: canonicalize,
    payloadOf: payloadOf,
    validate: validate,
    verifyCertificate: verifyCertificate
  };
}));
