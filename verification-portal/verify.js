/**
 * s0 Verification Engine (JavaScript Reference Implementation)
 *
 * Implements:
 *  1. s0 Canonical JSON v1 (core/CANONICAL_JSON.md)
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
    root.S0Verifier = factory(root.S0Crypto);
  }
}(typeof self !== "undefined" ? self : this, function(Crypto) {
  "use strict";

  if (!Crypto) {
    throw new Error("S0Crypto bundle is required before loading verify.js");
  }

  var SCHEMA_VERSION = "1.0.0";

  var WIPE_METHODS = [
      "ANDROID_FACTORY_RESET_FBE",
      "ANDROID_USER_SPACE_OVERWRITE",
      "ATA_SANITIZE_BLOCK_ERASE",
      "ATA_SANITIZE_CRYPTO_SCRAMBLE",
      "ATA_SANITIZE_OVERWRITE",
      "ATA_SECURE_ERASE",
      "ATA_SECURE_ERASE_ENHANCED",
      "BLKDISCARD",
      "FDE_KEY_DESTROY",
      "FORENSIC_CARVING",
      "FORENSIC_CLONING",
      "FORENSIC_IMAGING",
      "LUKS_KEYSLOT_ERASE",
      "NVME_FORMAT_CRYPTO_ERASE",
      "NVME_FORMAT_USER_DATA_ERASE",
      "NVME_SANITIZE_BLOCK_ERASE",
      "NVME_SANITIZE_CRYPTO_ERASE",
      "NVME_SANITIZE_OVERWRITE",
      "NVME_SANITIZE_PURGE_REQUIRED",
      "OPAL_CRYPTO_ERASE",
      "OVERWRITE_ZERO_1PASS",
      "RAID_CONTROLLER_PASSTHROUGH_SANITIZE",
      "SCSI_SANITIZE_BLOCK_ERASE",
      "SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE",
      "SCSI_SANITIZE_OVERWRITE",
      "SCSI_UNMAP",
      "SHRED_RANDOM_NPASS",
      "VENDOR_SECURE_ERASE",
      "WINDOWS_CIPHER_W",
      "WINDOWS_CLEAN_ALL",
      "WINDOWS_SED_KEY_DESTROY"
    ];

  var NIST_CATEGORIES = ["Clear", "Purge", "Destroy", "N/A"];
  var PATTERNS = [
      "carving",
      "cloning",
      "firmware",
      "imaging",
      "key_destruction",
      "not_applicable",
      "random",
      "zero"
    ];
  var STATUSES = ["success", "failure", "partial", "reset_triggered"];
  var DEVICE_TYPES = [
      "cloud_volume",
      "file",
      "file_set",
      "folder",
      "folder_tree",
      "image_file",
      "internal_disk",
      "logical_volume",
      "phone",
      "raid_logical_volume",
      "removable_disk",
      "virtual_disk"
    ];
  var STORAGE_TYPES = [
      "CLOUD_BLOCK",
      "HDD",
      "IMAGE_FILE",
      "LOGICAL_VOLUME",
      "NVMe",
      "RAID_LOGICAL_VOLUME",
      "SDCARD",
      "SSD",
      "UFS",
      "UNKNOWN",
      "VIRTUAL_DISK",
      "eMMC",
      "file",
      "folder_tree"
    ];
  var PLATFORMS = ["linux", "windows", "macos", "android"];

  var METHOD_TIERS = {
      "ANDROID_FACTORY_RESET_FBE": ["Purge"],
      "ANDROID_USER_SPACE_OVERWRITE": ["Clear"],
      "ATA_SANITIZE_BLOCK_ERASE": ["Purge"],
      "ATA_SANITIZE_CRYPTO_SCRAMBLE": ["Purge"],
      "ATA_SANITIZE_OVERWRITE": ["Purge"],
      "ATA_SECURE_ERASE": ["Purge"],
      "ATA_SECURE_ERASE_ENHANCED": ["Purge"],
      "BLKDISCARD": ["Clear", "Purge"],
      "FDE_KEY_DESTROY": ["Purge"],
      "FORENSIC_CARVING": ["N/A"],
      "FORENSIC_CLONING": ["N/A"],
      "FORENSIC_IMAGING": ["N/A"],
      "LUKS_KEYSLOT_ERASE": ["Purge"],
      "NVME_FORMAT_CRYPTO_ERASE": ["Purge"],
      "NVME_FORMAT_USER_DATA_ERASE": ["Purge"],
      "NVME_SANITIZE_BLOCK_ERASE": ["Purge"],
      "NVME_SANITIZE_CRYPTO_ERASE": ["Purge"],
      "NVME_SANITIZE_OVERWRITE": ["Purge"],
      "NVME_SANITIZE_PURGE_REQUIRED": ["Purge"],
      "OPAL_CRYPTO_ERASE": ["Purge"],
      "OVERWRITE_ZERO_1PASS": ["Clear"],
      "RAID_CONTROLLER_PASSTHROUGH_SANITIZE": ["Purge"],
      "SCSI_SANITIZE_BLOCK_ERASE": ["Purge"],
      "SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE": ["Purge"],
      "SCSI_SANITIZE_OVERWRITE": ["Purge"],
      "SCSI_UNMAP": ["Clear"],
      "SHRED_RANDOM_NPASS": ["Clear"],
      "VENDOR_SECURE_ERASE": ["Purge"],
      "WINDOWS_CIPHER_W": ["Clear"],
      "WINDOWS_CLEAN_ALL": ["Clear"],
      "WINDOWS_SED_KEY_DESTROY": ["Purge"],
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
        throw new Error("float values are not representable in s0 Canonical JSON v1");
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

  function detectRawFloatsInJson(rawStr) {
    if (typeof rawStr !== "string") return [];
    var errs = [];
    var inString = false;
    var escaped = false;
    var token = "";
    var depth = 0;
    var keyStack = [{}];
    var lastKey = null;

    for (var i = 0; i < rawStr.length; i++) {
      var ch = rawStr[i];
      if (inString) {
        if (escaped) {
          token += ch;
          escaped = false;
        } else if (ch === "\\") {
          escaped = true;
          token += ch;
        } else if (ch === '"') {
          inString = false;
          var j = i + 1;
          while (j < rawStr.length && (rawStr[j] === ' ' || rawStr[j] === '\t' || rawStr[j] === '\r' || rawStr[j] === '\n')) {
            j++;
          }
          if (j < rawStr.length && rawStr[j] === ':') {
            lastKey = token;
            if (keyStack[depth]) {
              if (keyStack[depth][lastKey]) {
                errs.push("duplicate key '" + lastKey + "' in JSON object");
              } else {
                keyStack[depth][lastKey] = true;
              }
            }
          }
          token = "";
        } else {
          token += ch;
        }
      } else {
        if (ch === '"') {
          inString = true;
          token = "";
        } else if (ch === '{') {
          depth++;
          keyStack[depth] = {};
        } else if (ch === '}') {
          if (depth > 0) {
            delete keyStack[depth];
            depth--;
          }
        } else if (ch === '-' || (ch >= '0' && ch <= '9')) {
          var numToken = ch;
          var k = i + 1;
          while (k < rawStr.length) {
            var c = rawStr[k];
            if ((c >= '0' && c <= '9') || c === '.' || c === 'e' || c === 'E' || c === '+' || c === '-') {
              numToken += c;
              k++;
            } else {
              break;
            }
          }
          i = k - 1;
          if (numToken.indexOf('.') !== -1 || numToken.indexOf('e') !== -1 || numToken.indexOf('E') !== -1) {
            errs.push("float values are forbidden in schema v1: found '" + numToken + "'");
          }
        }
      }
    }
    return errs;
  }

  function validate(cert, options) {
    var requireSignature = (options && options.requireSignature !== undefined) ? options.requireSignature : true;
    var rawJson = (options && options.rawJson) ? options.rawJson : (typeof cert === "string" ? cert : null);
    var errs = [];

    if (rawJson) {
      var rawErrs = detectRawFloatsInJson(rawJson);
      for (var r = 0; r < rawErrs.length; r++) {
        errs.push(rawErrs[r]);
      }
    }

    var targetCert = cert;
    if (typeof cert === "string") {
      try {
        targetCert = JSON.parse(cert);
      } catch (pe) {
        return ["certificate must be valid JSON: " + (pe.message || pe)];
      }
    }
    cert = targetCert;

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
        need(Number.isInteger(device.sector_size) && device.sector_size >= 1, "device.sector_size: must be a positive integer (minimum 1)");
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
            ["method", "samples_checked", "sample_bytes_each", "all_samples_match_wipe_pattern",
               "planted_pattern_hits_after", "pre_wipe_sample_hash", "sample_strategy",
               "population_blocks", "confidence_percent", "residual_fraction_upper_bound_ppm",
               "attestation", "smart_delta"]
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
  function verifyCertificate(cert, trustedKeys, options) {
    if (!trustedKeys || (Array.isArray(trustedKeys) && trustedKeys.length === 0)) {
      return {
        ok: false,
        status: "NO_TRUSTED_KEYS",
        reason: "No trusted public keys supplied to verifier",
        errors: ["no trusted public keys provided"]
      };
    }

    var rawJson = (options && options.rawJson) ? options.rawJson : (typeof cert === "string" ? cert : null);
    var certObj = cert;
    if (typeof cert === "string") {
      try {
        certObj = JSON.parse(cert);
      } catch (parseErr) {
        return {
          ok: false,
          status: "JSON_PARSE_ERROR",
          reason: "Invalid JSON format: " + (parseErr.message || parseErr),
          errors: ["invalid JSON format: " + (parseErr.message || parseErr)]
        };
      }
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
        } else if (k.rawPublicKeyBytes) {
          try {
            var pRawBytes = Crypto.rawPublicKeyToSpki(k.rawPublicKeyBytes);
            pRawBytes.issuer = k.issuer || "Unknown Issuer";
            normKeys.push(pRawBytes);
          } catch (e) {}
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

    var schemaErrors = validate(certObj, { requireSignature: true, rawJson: rawJson });
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
      var payloadObj = payloadOf(certObj);
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

    var claimedFp = certObj.signature.public_key_fingerprint;
    var sigB64 = certObj.signature.signature_base64url;
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
        if (certObj.signature && certObj.signature.signed_payload_hash && certObj.signature.signed_payload_hash !== computedHash) {
          return {
            ok: false,
            status: "PAYLOAD_HASH_MISMATCH",
            reason: "signed_payload_hash mismatch: certificate claims " + certObj.signature.signed_payload_hash + " but recomputed payload hash is " + computedHash,
            errors: ["signature.signed_payload_hash does not match recomputed canonical payload hash"]
          };
        }
        var isDemoKey = (claimedFp === "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06") ||
          (keyObj.issuer && (keyObj.issuer.toLowerCase().indexOf("unaccredited") !== -1 || keyObj.issuer.toLowerCase().indexOf("demo") !== -1));
        var keyLabel = keyObj.issuer || ("pinned key " + claimedFp);
        var reasonText = isDemoKey
          ? "Valid Ed25519 signature from UNACCREDITED demo key (" + keyLabel + "); payload sha256 " + computedHash
          : "Valid Ed25519 signature from pinned key " + claimedFp + "; payload sha256 " + computedHash;

        return {
          ok: true,
          status: "AUTHENTIC",
          isDemoKey: isDemoKey,
          matchedKey: keyObj,
          reason: reasonText,
          issuer: keyObj.issuer || (certObj.issuer ? certObj.issuer.organization : "Unknown"),
          fingerprint: claimedFp,
          computedPayloadHash: computedHash,
          claimedPayloadHash: certObj.signature ? certObj.signature.signed_payload_hash : null,
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
      claimedPayloadHash: certObj.signature ? certObj.signature.signed_payload_hash : null,
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
    verifyCertificate: verifyCertificate,
    detectRawFloatsInJson: detectRawFloatsInJson
  };
}));
