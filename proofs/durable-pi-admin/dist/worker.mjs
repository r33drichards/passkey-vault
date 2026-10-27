// node_modules/jose/dist/webapi/lib/buffer_utils.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var strictDecoder = new TextDecoder("utf-8", { fatal: true });
var UINT32_RANGE = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0), buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers)
    buf.set(buffer, i), i += buffer.length;
  return buf;
}
var NON_ASCII = /[^\x00-\x7f]/;
function encode(string) {
  if (typeof string == "string" && string.length >= 128) {
    if (NON_ASCII.test(string))
      throw new TypeError("non-ASCII string encountered in encode()");
    return encoder.encode(string);
  }
  const bytes = new Uint8Array(string.length);
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i);
    if (code > 127)
      throw new TypeError("non-ASCII string encountered in encode()");
    bytes[i] = code;
  }
  return bytes;
}
function decodeBase64(encoded, url = false) {
  if (Uint8Array.fromBase64)
    return Uint8Array.fromBase64(encoded, { alphabet: url ? "base64url" : "base64" });
  if (url) {
    if (encoded.includes("+") || encoded.includes("/"))
      throw new TypeError("Invalid base64url");
    encoded = encoded.replace(/-/g, "+").replace(/_/g, "/");
  }
  const binary = atob(encoded), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// node_modules/jose/dist/webapi/util/errors.js
var JOSEError = class extends Error {
  static code = "ERR_JOSE_GENERIC";
  code = "ERR_JOSE_GENERIC";
  constructor(message2, options) {
    super(message2, options), this.name = this.constructor.name, Error.captureStackTrace?.(this, this.constructor);
  }
};
var JWTClaimValidationFailed = class extends JOSEError {
  static code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, { cause: { claim, reason, payload } }), this.claim = claim, this.reason = reason, this.payload = payload;
  }
};
var JWTExpired = class extends JOSEError {
  static code = "ERR_JWT_EXPIRED";
  code = "ERR_JWT_EXPIRED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, { cause: { claim, reason, payload } }), this.claim = claim, this.reason = reason, this.payload = payload;
  }
};
var JOSEAlgNotAllowed = class extends JOSEError {
  static code = "ERR_JOSE_ALG_NOT_ALLOWED";
  code = "ERR_JOSE_ALG_NOT_ALLOWED";
};
var JOSENotSupported = class extends JOSEError {
  static code = "ERR_JOSE_NOT_SUPPORTED";
  code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWSInvalid = class extends JOSEError {
  static code = "ERR_JWS_INVALID";
  code = "ERR_JWS_INVALID";
};
var JWTInvalid = class extends JOSEError {
  static code = "ERR_JWT_INVALID";
  code = "ERR_JWT_INVALID";
};
var JWKSInvalid = class extends JOSEError {
  static code = "ERR_JWKS_INVALID";
  code = "ERR_JWKS_INVALID";
};
var JWKSNoMatchingKey = class extends JOSEError {
  static code = "ERR_JWKS_NO_MATCHING_KEY";
  code = "ERR_JWKS_NO_MATCHING_KEY";
  constructor(message2 = "no applicable key found in the JSON Web Key Set", options) {
    super(message2, options);
  }
};
var JWKSMultipleMatchingKeys = class extends JOSEError {
  [Symbol.asyncIterator] = async function* () {
  };
  static code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
  constructor(message2 = "multiple matching keys found in the JSON Web Key Set", options) {
    super(message2, options);
  }
};
var JWSSignatureVerificationFailed = class extends JOSEError {
  static code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  constructor(message2 = "signature verification failed", options) {
    super(message2, options);
  }
};

// node_modules/jose/dist/webapi/util/base64url.js
var invalid = "The input to be decoded is not correctly encoded.";
function decode(input) {
  try {
    return decodeBase64(typeof input == "string" ? input : decoder.decode(input), true);
  } catch (cause) {
    throw new TypeError(invalid, { cause });
  }
}

// node_modules/jose/dist/webapi/lib/validate.js
function isObject(input) {
  if (typeof input != "object" || input === null || Object.prototype.toString.call(input) !== "[object Object]")
    return false;
  const prototype = Object.getPrototypeOf(input);
  return prototype === null || Object.getPrototypeOf(prototype) === null;
}
function isJwkSet(input) {
  return isObject(input) && Array.isArray(input.keys) && Array.from(input.keys).every(isObject);
}
function isDisjoint(...headers) {
  const parameters = /* @__PURE__ */ new Set();
  for (const header of headers)
    if (header)
      for (const parameter of Object.keys(header)) {
        if (parameters.has(parameter))
          return false;
        parameters.add(parameter);
      }
  return true;
}
function decodeBase64url(value, label, ErrorClass) {
  try {
    return decode(value);
  } catch (cause) {
    throw new ErrorClass(`Failed to base64url decode the ${label}`, { cause });
  }
}
function encodeAsciiMember(value, label, ErrorClass) {
  try {
    return encode(value);
  } catch (cause) {
    throw new ErrorClass(`The ${label} is not a valid base64url string`, { cause });
  }
}
function parseJoseHeader(encodedProtectedHeader, ErrorClass, message2) {
  let parsed;
  try {
    parsed = JSON.parse(strictDecoder.decode(decode(encodedProtectedHeader)));
  } catch (cause) {
    throw new ErrorClass(message2, { cause });
  }
  if (!isObject(parsed))
    throw new ErrorClass(message2);
  return parsed;
}
var JWS_RECOGNIZED = { __proto__: null, b64: true };
function validateAlgorithms(option, algorithms) {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s != "string")))
    throw new TypeError(`"${option}" option must be an array of strings`);
  return algorithms === void 0 ? void 0 : new Set(algorithms);
}
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0)
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  if (!protectedHeader || protectedHeader.crit === void 0)
    return [];
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input != "string" || input.length === 0))
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  const recognized = recognizedOption === void 0 ? recognizedDefault : { __proto__: null, ...recognizedOption, ...recognizedDefault };
  for (const parameter of protectedHeader.crit) {
    if (!(parameter in recognized))
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    if (!Object.hasOwn(joseHeader, parameter) || joseHeader[parameter] === void 0)
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    if (recognized[parameter] && (!Object.hasOwn(protectedHeader, parameter) || protectedHeader[parameter] === void 0))
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
  }
  return protectedHeader.crit;
}
function validateB64(protectedHeader, extensions) {
  if (extensions.includes("b64")) {
    const b642 = protectedHeader.b64;
    if (typeof b642 != "boolean")
      throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
    return b642;
  }
  return true;
}

// node_modules/jose/dist/webapi/lib/key.js
var tag = (key) => key[Symbol.toStringTag];
var jwkMatchesOp = (entry, key, usage) => {
  const { alg } = entry;
  if (key.use !== void 0) {
    const expected = usage === "sign" || usage === "verify" ? "sig" : "enc";
    if (key.use !== expected)
      throw new TypeError(`Invalid key for this operation, its "use" must be "${expected}" when present`);
  }
  if (key.alg !== void 0 && key.alg !== alg)
    throw new TypeError(`Invalid key for this operation, its "alg" must be "${alg}" when present`);
  if (Array.isArray(key.key_ops)) {
    const expectedKeyOp = usage === "encrypt" || usage === "decrypt" ? entry.ops?.[usage === "encrypt" ? 0 : 1] : usage;
    if (expectedKeyOp && !key.key_ops.includes(expectedKeyOp))
      throw new TypeError(`Invalid key for this operation, its "key_ops" must include "${expectedKeyOp}" when present`);
  }
};
async function prepareKey(entry, key, usage) {
  const { alg, secret } = entry, requiresPrivateKey = usage === "decrypt" || usage === "sign";
  if (secret && key instanceof Uint8Array)
    return key;
  let normalized, keyObject;
  if (isObject(key)) {
    if (normalized = normalizeJwk(key), typeof normalized.kty != "string")
      throw invalidKeyType(alg, key, secret);
    if (!(secret ? normalized.kty === "oct" && typeof normalized.k == "string" : normalized.kty !== "oct" && (requiresPrivateKey ? normalized.kty === "AKP" && typeof normalized.priv == "string" || typeof normalized.d == "string" : normalized.d === void 0 && normalized.priv === void 0)))
      throw new TypeError(secret ? 'JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present' : `JSON Web Key for this operation must be a ${requiresPrivateKey ? "private" : "public"} JWK`);
    if (jwkMatchesOp(entry, normalized, usage), normalized.kty === "oct")
      return decode(normalized.k);
    if (!Object.isFrozen(key)) {
      const { key_ops } = key;
      Array.isArray(key_ops) && Object.freeze(key_ops), Object.freeze(key);
    }
  } else {
    if (!isKeyLike(key))
      throw invalidKeyType(alg, key, secret);
    const expectedType = secret ? "secret" : requiresPrivateKey ? "private" : "public";
    if (key.type !== expectedType && (secret || ["secret", "public", "private"].includes(key.type)))
      throw new TypeError(`${tag(key)} instances must be of type "${expectedType}" for the ${alg} algorithm`);
    if (isCryptoKey(key))
      return key;
    if (keyObject = key, keyObject.type === "secret")
      return keyObject.export();
  }
  cache ||= /* @__PURE__ */ new WeakMap();
  const cacheKey = key;
  let cached = cache.get(cacheKey);
  if (cached?.[alg])
    return cached[alg];
  if (cached || cache.set(cacheKey, cached = {}), keyObject && typeof keyObject.toCryptoKey == "function") {
    const isPublic = keyObject.type === "public", crv = nist[keyObject.asymmetricKeyDetails?.namedCurve], params = entry.resolve?.({ crv, asymmetricKeyType: keyObject.asymmetricKeyType }) ?? entry.subtle;
    return cached[alg] = keyObject.toCryptoKey(params, isPublic, entry.usages[isPublic ? 0 : 1]);
  }
  return normalized ??= keyObject.export({ format: "jwk" }), normalized.alg = alg, cached[alg] = await jwkToKey(entry, normalized);
}
var cache;
var nist = {
  __proto__: null,
  prime256v1: "P-256",
  secp384r1: "P-384",
  secp521r1: "P-521"
};
var isCryptoKey = (key) => {
  if (key?.[Symbol.toStringTag] === "CryptoKey")
    return true;
  try {
    return key instanceof CryptoKey;
  } catch {
    return false;
  }
};
var isKeyObject = (key) => key?.[Symbol.toStringTag] === "KeyObject";
var isKeyLike = (key) => isCryptoKey(key) || isKeyObject(key);
function message(msg, actual, ...types) {
  if (types.length > 2) {
    const last = types.pop();
    msg += `one of type ${types.join(", ")}, or ${last}.`;
  } else types.length === 2 ? msg += `one of type ${types[0]} or ${types[1]}.` : msg += `of type ${types[0]}.`;
  return actual == null ? msg += ` Received ${actual}` : typeof actual == "function" && actual.name ? msg += ` Received function ${actual.name}` : typeof actual == "object" && actual != null && actual.constructor?.name && (msg += ` Received an instance of ${actual.constructor.name}`), msg;
}
function invalidKeyType(alg, actual, secret) {
  const types = ["CryptoKey", "KeyObject", "JSON Web Key"];
  return secret && types.push("Uint8Array"), new TypeError(message(`Key for the ${alg} algorithm must be `, actual, ...types));
}
var unusable = (name, prop = "algorithm.name") => new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
function checkUsage(key, usage) {
  if (usage && !key.usages.includes(usage))
    throw new TypeError(`CryptoKey does not support this operation, its usages must include ${usage}.`);
}
function checkModulusLength(alg, key) {
  const { modulusLength } = key.algorithm;
  if (typeof modulusLength != "number" || modulusLength < 2048)
    throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
}
function checkCryptoKey(key, expected, usage) {
  const algorithm = key.algorithm;
  if (algorithm.name !== expected.name)
    throw unusable(expected.name);
  if (expected.hash && algorithm.hash?.name !== expected.hash)
    throw unusable(expected.hash, "algorithm.hash");
  if (expected.namedCurve && algorithm.namedCurve !== expected.namedCurve)
    throw unusable(expected.namedCurve, "algorithm.namedCurve");
  if (expected.length !== void 0 && algorithm.length !== expected.length)
    throw unusable(expected.length, "algorithm.length");
  checkUsage(key, usage);
}
function snapshotJwk(jwk) {
  return { __proto__: null, ...jwk };
}
function normalizeJwk(jwk) {
  const normalized = snapshotJwk(jwk);
  if (normalized.ext !== void 0 && typeof normalized.ext != "boolean")
    throw new TypeError('"ext" (Extractable) Parameter must be a boolean');
  if (normalized.key_ops !== void 0) {
    const value = normalized.key_ops, keyOps = Array.isArray(value) ? [...value] : void 0;
    if (!keyOps || keyOps.some((operation) => typeof operation != "string") || new Set(keyOps).size !== keyOps.length)
      throw new TypeError('"key_ops" (Key Operations) Parameter must be an array of unique strings');
    normalized.key_ops = keyOps;
  }
  return normalized;
}
async function jwkToKey(entry, jwk, extractable) {
  if (!entry.kty.includes(jwk.kty))
    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
  const algorithm = entry.resolve?.({ kty: jwk.kty, crv: jwk.crv }) ?? entry.subtle, isPrivate = !!(jwk.d || jwk.priv), keyData = { ...jwk, ext: extractable ?? jwk.ext };
  return keyData.kty !== "AKP" && delete keyData.alg, delete keyData.use, crypto.subtle.importKey("jwk", keyData, algorithm, keyData.ext ?? !isPrivate, jwk.key_ops ?? entry.usages[isPrivate ? 1 : 0]);
}
async function rawKey(key, expected, usage, extractable = false) {
  return key instanceof Uint8Array && (key = await crypto.subtle.importKey("raw", key, expected, extractable, [usage])), checkCryptoKey(key, expected, usage), key;
}

// node_modules/jose/dist/webapi/lib/key_descriptor.js
function table(entries) {
  const out = { __proto__: null };
  for (const alg in entries)
    out[alg] = { ...entries[alg], alg };
  return out;
}

// node_modules/jose/dist/webapi/lib/jws_algorithms.js
var sig = [["verify"], ["sign"]];
function hmac(bits) {
  const subtle = { name: "HMAC", hash: `SHA-${bits}` };
  return { kty: ["oct"], secret: true, subtle, signing: subtle, usages: sig };
}
function rsa(bits, saltLength) {
  const subtle = { name: saltLength ? "RSA-PSS" : "RSASSA-PKCS1-v1_5", hash: `SHA-${bits}` };
  return {
    kty: ["RSA"],
    subtle,
    signing: saltLength ? { ...subtle, saltLength } : subtle,
    usages: sig,
    minRsaBits: 2048
  };
}
function ecdsa(crv, bits) {
  return {
    kty: ["EC"],
    crv,
    subtle: { name: "ECDSA", namedCurve: crv },
    signing: { name: "ECDSA", hash: `SHA-${bits}` },
    usages: sig
  };
}
function eddsa() {
  const subtle = { name: "Ed25519" };
  return {
    kty: ["OKP"],
    crv: "Ed25519",
    subtle,
    signing: subtle,
    usages: sig
  };
}
function mldsa(parameterSet) {
  const subtle = { name: `ML-DSA-${parameterSet}` };
  return {
    kty: ["AKP"],
    subtle,
    signing: subtle,
    usages: sig
  };
}
var JWS = table({
  HS256: hmac(256),
  HS384: hmac(384),
  HS512: hmac(512),
  RS256: rsa(256),
  RS384: rsa(384),
  RS512: rsa(512),
  PS256: rsa(256, 32),
  PS384: rsa(384, 48),
  PS512: rsa(512, 64),
  ES256: ecdsa("P-256", 256),
  ES384: ecdsa("P-384", 384),
  ES512: ecdsa("P-521", 512),
  EdDSA: eddsa(),
  Ed25519: eddsa(),
  "ML-DSA-44": mldsa(44),
  "ML-DSA-65": mldsa(65),
  "ML-DSA-87": mldsa(87)
});
function jwsAlgorithm(alg) {
  const entry = typeof alg == "string" ? JWS[alg] : void 0;
  if (!entry)
    throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  return entry;
}

// node_modules/jose/dist/webapi/lib/jws_verify.js
function prepareVerify(options) {
  return [options && validateAlgorithms("algorithms", options.algorithms), options?.crit];
}
function parseProtectedHeader(encodedProtectedHeader) {
  return encodedProtectedHeader === void 0 ? {} : parseJoseHeader(encodedProtectedHeader, JWSInvalid, "JWS Protected Header is invalid");
}
function encodeCompactUnencodedPayload(payload) {
  try {
    return encode(payload);
  } catch (cause) {
    throw new JWSInvalid("JWS Compact Serialization payload must use only ASCII characters", {
      cause
    });
  }
}
async function verifySignature(jws, shared, key, encodeUnencodedPayload, parsedProtected) {
  const { protected: encodedProtectedHeader, header, payload: inputPayload } = jws, protectedHeader = parsedProtected ?? parseProtectedHeader(encodedProtectedHeader);
  if (!isDisjoint(protectedHeader, header))
    throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
  const joseHeader = { ...protectedHeader, ...header }, b642 = validateB64(protectedHeader, validateCrit(JWSInvalid, JWS_RECOGNIZED, shared[1], protectedHeader, joseHeader)), { alg } = joseHeader;
  if (typeof alg != "string" || !alg)
    throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  if (shared[0] && !shared[0].has(alg))
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  if (b642) {
    if (typeof inputPayload != "string")
      throw new JWSInvalid("JWS Payload must be a string");
  } else if (typeof inputPayload != "string" && !(inputPayload instanceof Uint8Array))
    throw new JWSInvalid("JWS Payload must be a string or an Uint8Array instance");
  const signingPayload = b642 || typeof inputPayload != "string" ? inputPayload : encodeUnencodedPayload(inputPayload);
  let resolvedKey = false;
  typeof key == "function" && (key = await key(protectedHeader, jws), resolvedKey = true);
  const entry = jwsAlgorithm(alg), signingInput = concat(encodedProtectedHeader !== void 0 ? encode(encodedProtectedHeader) : new Uint8Array(), encode("."), typeof signingPayload == "string" ? shared[2] ??= encodeAsciiMember(signingPayload, "payload", JWSInvalid) : signingPayload), signature = decodeBase64url(jws.signature, "signature", JWSInvalid), verificationKey = await prepareKey(entry, key, "verify"), cryptoKey = await rawKey(verificationKey, entry.subtle, "verify");
  entry.minRsaBits && checkModulusLength(entry.alg, cryptoKey);
  let verified = false;
  try {
    verified = await crypto.subtle.verify(entry.signing, cryptoKey, signature, signingInput);
  } catch (cause) {
    throw new JWSSignatureVerificationFailed(void 0, { cause });
  }
  if (!verified)
    throw new JWSSignatureVerificationFailed();
  const result = { payload: typeof signingPayload == "string" ? decodeBase64url(signingPayload, "payload", JWSInvalid) : signingPayload };
  return encodedProtectedHeader !== void 0 && (result.protectedHeader = protectedHeader), header !== void 0 && (result.unprotectedHeader = header), resolvedKey ? [{ ...result, key: verificationKey }, b642] : [result, b642];
}
async function verifyCompact(jws, shared, key) {
  if (jws instanceof Uint8Array && (jws = decoder.decode(jws)), typeof jws != "string")
    throw new JWSInvalid("Compact JWS must be a string or Uint8Array");
  const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split(".");
  if (length !== 3)
    throw new JWSInvalid("Invalid Compact JWS");
  return verifySignature({ payload, protected: protectedHeader, signature }, shared, key, encodeCompactUnencodedPayload);
}

// node_modules/jose/dist/webapi/lib/jwt_claims_set.js
var epoch = (date) => Math.floor(date.getTime() / 1e3);
var multipliers = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
  y: 31557600
};
var REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
var checkFailed = "check_failed";
function invalidDuration() {
  throw new TypeError("Invalid time period format");
}
function secs(str) {
  typeof str != "string" && invalidDuration();
  const matched = REGEX.exec(str);
  (!matched || matched[4] && matched[1]) && invalidDuration();
  const value = parseFloat(matched[2]), durationSeconds = Math.round(value * multipliers[matched[3][0].toLowerCase()]);
  return Number.isFinite(durationSeconds) || invalidDuration(), matched[1] === "-" || matched[4] === "ago" ? -durationSeconds : durationSeconds;
}
function validateInput(label, input) {
  if (!Number.isFinite(input))
    throw new TypeError(`Invalid ${label} input`);
  return input;
}
var normalizeTyp = (value) => {
  const normalized = value.toLowerCase();
  return value.includes("/") ? normalized : `application/${normalized}`;
};
var checkAudiencePresence = (audPayload, audOption) => typeof audPayload == "string" ? audOption.includes(audPayload) : Array.isArray(audPayload) ? audOption.some((aud) => audPayload.includes(aud)) : false;
function validateNumericDate(claimsSet, claim, required = false) {
  const value = claimsSet[claim];
  if (!(value === void 0 && !required)) {
    if (typeof value != "number")
      throw new JWTClaimValidationFailed(`"${claim}" claim must be a number`, claimsSet, claim, "invalid");
    return value;
  }
}
function unexpectedClaim(claimsSet, claim) {
  throw new JWTClaimValidationFailed(`unexpected "${claim}" claim value`, claimsSet, claim, checkFailed);
}
function validateClaimsSet(protectedHeader, claimsSetBytes, options = {}) {
  let claimsSet;
  try {
    claimsSet = JSON.parse(strictDecoder.decode(claimsSetBytes));
  } catch (cause) {
    throw new JWTInvalid("JWT Claims Set must be a top-level JSON object", { cause });
  }
  if (!isObject(claimsSet))
    throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
  const { typ } = options;
  if (typ !== void 0 && (typeof protectedHeader.typ != "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ)))
    throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', claimsSet, "typ", checkFailed);
  const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options, presenceCheck = [...requiredClaims];
  maxTokenAge !== void 0 && presenceCheck.push("iat"), audience !== void 0 && presenceCheck.push("aud"), subject !== void 0 && presenceCheck.push("sub"), issuer !== void 0 && presenceCheck.push("iss");
  for (const claim of new Set(presenceCheck.reverse()))
    if (!Object.hasOwn(claimsSet, claim))
      throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, claimsSet, claim, "missing");
  issuer !== void 0 && !(Array.isArray(issuer) ? issuer : [issuer]).includes(claimsSet.iss) && unexpectedClaim(claimsSet, "iss"), subject !== void 0 && claimsSet.sub !== subject && unexpectedClaim(claimsSet, "sub"), audience !== void 0 && !checkAudiencePresence(claimsSet.aud, typeof audience == "string" ? [audience] : audience) && unexpectedClaim(claimsSet, "aud");
  const { clockTolerance } = options;
  let tolerance = 0;
  if (typeof clockTolerance == "string")
    tolerance = secs(clockTolerance);
  else if (clockTolerance !== void 0) {
    if (typeof clockTolerance != "number")
      throw new TypeError("Invalid clockTolerance option type");
    tolerance = clockTolerance;
  }
  validateInput("clockTolerance option", tolerance);
  const { currentDate } = options, now = validateInput("currentDate option", epoch(currentDate === void 0 ? /* @__PURE__ */ new Date() : currentDate)), iat = validateNumericDate(claimsSet, "iat", maxTokenAge !== void 0), nbf = validateNumericDate(claimsSet, "nbf");
  if (nbf !== void 0 && nbf > now + tolerance)
    throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', claimsSet, "nbf", checkFailed);
  const exp = validateNumericDate(claimsSet, "exp");
  if (exp !== void 0 && exp <= now - tolerance)
    throw new JWTExpired('"exp" claim timestamp check failed', claimsSet, "exp", checkFailed);
  if (maxTokenAge !== void 0) {
    const age = now - iat, max = validateInput("maxTokenAge option", typeof maxTokenAge == "number" ? maxTokenAge : secs(maxTokenAge));
    if (age - tolerance > max)
      throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', claimsSet, "iat", checkFailed);
    if (age < -tolerance)
      throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', claimsSet, "iat", checkFailed);
  }
  return claimsSet;
}

// node_modules/jose/dist/webapi/jwt/verify.js
async function jwtVerify(jwt, key, options) {
  const [verified, b642] = await verifyCompact(jwt, prepareVerify(options), key);
  if (!b642)
    throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
  const payload = validateClaimsSet(verified.protectedHeader, verified.payload, options);
  return { ...verified, payload };
}

// node_modules/jose/dist/webapi/jwks/local.js
function isUsableJWK(jwk, entry, alg, kid) {
  const { kty, key_ops: keyOps, ext, kid: jwkKid, alg: jwkAlg, use, crv } = jwk;
  return (ext === void 0 || typeof ext == "boolean") && (keyOps === void 0 || Array.isArray(keyOps) && keyOps.every((operation, index) => typeof operation == "string" && keyOps.indexOf(operation) === index) && keyOps.includes("verify")) && entry.kty.includes(kty) && (kid === void 0 || typeof kid == "string" && kid === jwkKid) && (jwkAlg === void 0 ? kty !== "AKP" : alg === jwkAlg) && (use === void 0 || use === "sig") && (!entry.crv || crv === entry.crv);
}
async function importWithAlgCache(cache2, jwk, entry) {
  const cached = cache2.get(jwk) || cache2.set(jwk, {}).get(jwk), { alg } = entry;
  if (cached[alg] === void 0) {
    const pending = jwkToKey(entry, jwk, true).then((key) => {
      if (key.type !== "public")
        throw new JWKSInvalid("JSON Web Key Set members must be public keys");
      return cached[alg] = key, key;
    }).catch((error) => {
      throw cached[alg] === pending && delete cached[alg], error;
    });
    cached[alg] = pending;
  }
  return cached[alg];
}
function createLocalJWKSet(jwks) {
  let snapshot;
  try {
    snapshot = structuredClone(jwks);
  } catch (cause) {
    throw new JWKSInvalid("JSON Web Key Set malformed", { cause });
  }
  if (!isJwkSet(snapshot))
    throw new JWKSInvalid("JSON Web Key Set malformed");
  const metadata = snapshot.keys.map((jwk) => {
    const normalized = snapshotJwk(jwk);
    return Array.isArray(normalized.key_ops) && (normalized.key_ops = [...normalized.key_ops]), normalized;
  }), cached = /* @__PURE__ */ new WeakMap();
  return Object.defineProperty(async (protectedHeader, token) => {
    const { alg, kid } = { ...protectedHeader, ...token?.header }, entry = typeof alg == "string" ? JWS[alg] : void 0;
    if (!entry || entry.secret)
      throw new JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
    const candidates = snapshot.keys.filter((_, index) => isUsableJWK(metadata[index], entry, alg, kid)), { 0: jwk, length } = candidates;
    if (!length)
      throw new JWKSNoMatchingKey();
    if (length !== 1) {
      const error = new JWKSMultipleMatchingKeys();
      throw error[Symbol.asyncIterator] = async function* () {
        for (const jwk2 of candidates)
          try {
            yield await importWithAlgCache(cached, jwk2, entry);
          } catch {
          }
      }, error;
    }
    return importWithAlgCache(cached, jwk, entry);
  }, "jwks", {
    value: () => structuredClone(snapshot)
  });
}

// src/worker.mjs
var enc = new TextEncoder();
var dec = new TextDecoder();
var TEN_MINUTES = 6e5;
var SESSION_MS = 8 * 60 * 6e4;
var OPENAI_ISSUER = "https://auth.openai.com";
var TOKEN_URL = OPENAI_ISSUER + "/api/accounts/oauth/token";
var RESOURCE = "https://api.openai.com/v1";
var CALLBACK = "http://127.0.0.1:1455/auth/callback";
var SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
var b64 = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
var unb64 = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
var random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
var hash = async (text) => b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text))));
var escape = (text) => String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
var fail = (message2, status = 400) => {
  throw Object.assign(new Error(message2), { safe: true, status });
};
var HEADERS = {
  "Cache-Control": "no-store, private",
  "Referrer-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://github.com; base-uri 'none'; frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
};
function page(body, status = 200, extra = {}) {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Durable Pi \xB7 Admin</title><style>
  :root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1120;color:#e2e8f0}body{max-width:680px;margin:8vh auto;padding:24px;line-height:1.6}h1{font-size:2.2rem;letter-spacing:-.04em}h2{font-size:1.2rem}section{background:#141e32;border:1px solid #2a3852;border-radius:16px;padding:24px;margin:24px 0}a{color:#93c5fd}button,.button{display:inline-block;background:#93c5fd;color:#0b1120;padding:12px 20px;border:0;border-radius:8px;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}button.secondary{background:#26354c;color:#e2e8f0}input{width:100%;box-sizing:border-box;background:#0b1120;color:#fff;border:1px solid #526079;border-radius:8px;padding:12px;margin:8px 0 16px;font:inherit}.muted{color:#a4b2c8}.eyebrow{font-size:.8rem;letter-spacing:.12em;text-transform:uppercase;color:#93c5fd}code{overflow-wrap:anywhere}form{margin:12px 0}footer{font-size:.9rem;color:#a4b2c8}</style></head><body><div class="eyebrow">Durable Pi + Modal</div><h1>Your agent, your account.</h1>${body}<footer>Owner-only administration \xB7 Credentials stay server-side.</footer></body></html>`, {
    status,
    headers: { ...HEADERS, "Content-Type": "text/html; charset=utf-8", ...extra }
  });
}
function redirect(path, cookies = []) {
  const headers = new Headers({ ...HEADERS, Location: path });
  for (const cookie2 of cookies) headers.append("Set-Cookie", cookie2);
  return new Response(null, { status: 303, headers });
}
var cookie = (name, value, seconds) => `__Host-${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`;
var csrfInput = (session) => `<input type="hidden" name="csrf" value="${escape(session.csrf)}">`;
function form(session, action, label, secondary = false) {
  return `<form method="post" action="${action}">${csrfInput(session)}<button${secondary ? ' class="secondary"' : ""}>${label}</button></form>`;
}
async function limitedText(body, limit) {
  if (!body) return "";
  const reader = body.getReader();
  let size = 0;
  const chunks = [];
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      fail("Response or form is too large.", 413);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.length;
  }
  return dec.decode(all);
}
var ROUTES = /* @__PURE__ */ new Set([
  "/admin",
  "/setup/callback",
  "/auth/github",
  "/auth/github/callback",
  "/admin/chatgpt/start",
  "/admin/chatgpt",
  "/admin/chatgpt/complete",
  "/admin/chatgpt/disconnect",
  "/admin/logout"
]);
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.origin !== env.PUBLIC_ORIGIN) return new Response("Wrong host", { status: 421, headers: HEADERS });
    if (url.pathname === "/health" && request.method === "GET") return Response.json({ service: "durable-pi-modal", admin: "deployed", webhook: "not-enabled" }, { headers: HEADERS });
    if (url.pathname === "/") return redirect("/admin");
    if (!ROUTES.has(url.pathname)) return new Response("Not found", { status: 404, headers: HEADERS });
    return env.AUTH.get(env.AUTH.idFromName("owner")).fetch(request);
  }
};
var OwnerAuthority = class {
  constructor(state, env) {
    this.storage = state.storage;
    this.env = env;
    this.chain = Promise.resolve();
    this.fetcher = (...args) => fetch(...args);
    this.now = () => Date.now();
  }
  serial(fn) {
    const next = this.chain.then(fn);
    this.chain = next.catch(() => {
    });
    return next;
  }
  async key() {
    if (!this.keyPromise) this.keyPromise = (async () => {
      const raw = unb64(this.env.VAULT_KEY || "");
      if (raw.length !== 32) fail("Secure storage is not configured.", 503);
      return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    })();
    return this.keyPromise;
  }
  async seal(purpose, value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(purpose) }, await this.key(), enc.encode(JSON.stringify(value)));
    return b64(iv) + "." + b64(new Uint8Array(cipher));
  }
  async open(purpose, value) {
    const parts = String(value).split(".");
    if (parts.length !== 2) throw Error("invalid_cipher");
    return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(parts[0]), additionalData: enc.encode(purpose) }, await this.key(), unb64(parts[1]))));
  }
  async read(name) {
    const raw = await this.storage.get(name);
    return raw ? this.open(name, raw) : void 0;
  }
  async save(name, value) {
    await this.storage.put(name, await this.seal(name, value));
  }
  async readCookie(request, name) {
    const raw = (request.headers.get("Cookie") || "").split(";").map((s) => s.trim()).find((s) => s.startsWith(`__Host-${name}=`))?.slice(name.length + 8);
    if (!raw || raw.length > 8192) return;
    try {
      const value = await this.open("cookie:" + name, raw);
      if (value.expires > this.now()) return value;
    } catch {
    }
  }
  async setCookie(name, value, seconds) {
    return cookie(name, await this.seal("cookie:" + name, { ...value, expires: this.now() + seconds * 1e3 }), seconds);
  }
  async session(request) {
    const s = await this.readCookie(request, "session");
    if (s?.owner !== this.env.GITHUB_OWNER_ID || !s.sid || !s.csrf) return;
    if (s.epoch !== (await this.storage.get("epoch") || 0)) return;
    return s;
  }
  async json(url, options = {}) {
    const response = await this.fetcher(url, { ...options, redirect: "error", signal: AbortSignal.timeout(15e3), headers: { Accept: "application/json", "User-Agent": "durable-pi-modal", ...options.headers } });
    if (!response.ok) {
      await response.body?.cancel();
      fail("The sign-in provider could not complete this request. Start a fresh sign-in.", 502);
    }
    try {
      return JSON.parse(await limitedText(response.body, 128 * 1024));
    } catch (e) {
      if (e.safe) throw e;
      fail("Invalid provider response.", 502);
    }
  }
  async consume(state) {
    const key = await hash(state), now = this.now();
    const used = await this.storage.get("used-flows") || {};
    for (const [k, v] of Object.entries(used)) if (v < now) delete used[k];
    if (used[key]) fail("This sign-in was already submitted. Start again.", 409);
    if (Object.keys(used).length >= 64) fail("Too many sign-in attempts. Try again later.", 429);
    used[key] = now + TEN_MINUTES;
    await this.storage.put("used-flows", used);
  }
  async flow(request, purpose) {
    const value = await this.readCookie(request, "flow");
    if (!value || value.purpose !== purpose || new URL(request.url).searchParams.get("state") !== value.state) fail("Sign-in state expired or did not match. Return to the admin page.", 400);
    await this.consume(value.state);
    return value;
  }
  async post(request, s) {
    if (request.method !== "POST") fail("Method not allowed.", 405);
    if (request.headers.get("Origin") !== this.env.PUBLIC_ORIGIN) fail("Submit this form from the admin page.", 403);
    if (!(request.headers.get("Content-Type") || "").startsWith("application/x-www-form-urlencoded")) fail("Invalid form.", 415);
    const values = new URLSearchParams(await limitedText(request.body, 20 * 1024));
    if (values.get("csrf") !== s.csrf) fail("Form expired. Reload the admin page.", 403);
    return values;
  }
  fetch(request) {
    return this.serial(async () => {
      try {
        return await this.route(request);
      } catch (e) {
        return page(`<section><h2>Request not completed</h2><p>${escape(e.safe ? e.message : "The request could not be completed. No sensitive details have been logged.")}</p><a href="/admin">Return to admin</a></section>`, e.safe ? e.status : 500);
      }
    });
  }
  async route(request) {
    const url = new URL(request.url), path = url.pathname, origin = this.env.PUBLIC_ORIGIN;
    if (url.origin !== origin) fail("Wrong host.", 421);
    const s = await this.session(request);
    const app = await this.read("github-app");
    if (path === "/admin" && request.method === "GET") {
      if (!app) return this.setupPage();
      if (!s) return page(`<section><h2>Sign in to administer your agent</h2><p>Access is restricted to <strong>${escape(this.env.GITHUB_OWNER_LOGIN)}</strong>.</p><a class="button" href="/auth/github">Continue with GitHub</a></section>`);
      const model = await this.read("chatgpt");
      const connected = model?.status === "ready";
      return page(`<p class="muted">Signed in as ${escape(this.env.GITHUB_OWNER_LOGIN)}</p><section><h2>ChatGPT connection</h2><p>${connected ? "Connected. Your credentials are saved encrypted for the agent." : model ? "Reconnect required. No automatic model requests will be made." : "Not connected yet."}</p>${connected ? `<p class="muted">Account: ${escape(model.identity.email || model.identity.sub)}</p>` : ""}${form(s, "/admin/chatgpt/start", connected ? "Reconnect ChatGPT" : "Connect ChatGPT")}${model ? form(s, "/admin/chatgpt/disconnect", "Disconnect locally", true) : ""}</section><section><h2>Webhook agent</h2><p>Not enabled yet. This page completes secure account setup; the full Pi \u2192 Modal run is still being integrated.</p></section>${form(s, "/admin/logout", "Sign out of admin", true)}`);
    }
    if (path === "/setup/callback" && request.method === "GET") {
      if (app) fail("GitHub is already configured.", 409);
      await this.flow(request, "manifest");
      const code = url.searchParams.get("code");
      if (!code || !/^[a-zA-Z0-9_-]{10,200}$/.test(code)) fail("Missing GitHub setup code.");
      const data = await this.json(`https://api.github.com/app-manifests/${encodeURIComponent(code)}/conversions`, { method: "POST", headers: { "X-GitHub-Api-Version": "2022-11-28" } });
      if (String(data.owner?.id) !== this.env.GITHUB_OWNER_ID) fail("This app must be owned by the configured GitHub account. No configuration was saved.", 403);
      if (!data.client_id || !data.client_secret || !data.id) fail("GitHub app response is incomplete.", 502);
      await this.save("github-app", { id: data.id, clientId: data.client_id, clientSecret: data.client_secret, owner: this.env.GITHUB_OWNER_ID });
      return redirect("/auth/github", [cookie("flow", "", 0)]);
    }
    if (path === "/auth/github" && request.method === "GET") {
      if (!app) return redirect("/admin");
      const state = random(), verifier = random();
      const dest = new URL("https://github.com/login/oauth/authorize");
      dest.search = new URLSearchParams({ client_id: app.clientId, redirect_uri: origin + "/auth/github/callback", state, code_challenge: await hash(verifier), code_challenge_method: "S256", login: this.env.GITHUB_OWNER_LOGIN }).toString();
      return redirect(dest.toString(), [await this.setCookie("flow", { purpose: "github", state, verifier }, 600)]);
    }
    if (path === "/auth/github/callback" && request.method === "GET") {
      if (!app) fail("GitHub is not configured.", 503);
      const f = await this.flow(request, "github");
      const code = url.searchParams.get("code");
      if (!code || url.searchParams.has("error")) fail("GitHub authorization was not completed.");
      const grant = await this.json("https://github.com/login/oauth/access_token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: app.clientId, client_secret: app.clientSecret, code, redirect_uri: origin + "/auth/github/callback", code_verifier: f.verifier }) });
      if (typeof grant.access_token !== "string" || grant.error) fail("GitHub authorization failed.", 403);
      const user = await this.json("https://api.github.com/user", { headers: { Authorization: `Bearer ${grant.access_token}`, "X-GitHub-Api-Version": "2022-11-28" } });
      if (String(user.id) !== this.env.GITHUB_OWNER_ID) fail("Only the configured GitHub owner can use this admin page.", 403);
      const session = { owner: this.env.GITHUB_OWNER_ID, sid: random(), csrf: random(), epoch: await this.storage.get("epoch") || 0 };
      return redirect("/admin", [cookie("flow", "", 0), await this.setCookie("session", session, SESSION_MS / 1e3)]);
    }
    if (!s) fail("Sign in with GitHub first.", 401);
    if (path === "/admin/logout") {
      await this.post(request, s);
      await this.storage.put("epoch", (await this.storage.get("epoch") || 0) + 1);
      await this.storage.delete("chatgpt-pending");
      return redirect("/admin", [cookie("session", "", 0)]);
    }
    if (path === "/admin/chatgpt/start") {
      await this.post(request, s);
      const old = await this.read("chatgpt");
      let host = await this.storage.get("host");
      if (!host) {
        host = "urn:uuid:" + crypto.randomUUID();
        await this.storage.put("host", host);
      }
      await this.save("chatgpt-pending", { sid: s.sid, state: random(), nonce: random(), verifier: random(), expires: this.now() + TEN_MINUTES, status: "pending", clientId: old?.credential.clientId || "dynamic_agent_client", subject: old?.identity.sub, host });
      return redirect("/admin/chatgpt");
    }
    if (path === "/admin/chatgpt" && request.method === "GET") {
      const pending = await this.pending(s);
      const dest = new URL(OPENAI_ISSUER + "/api/accounts/authorize");
      dest.search = new URLSearchParams({ client_id: pending.clientId, agent_name_hint: "Durable Pi Modal", ext_agent_host_id: pending.host, response_type: "code", redirect_uri: CALLBACK, resource: RESOURCE, scope: SCOPES, state: pending.state, nonce: pending.nonce, code_challenge: await hash(pending.verifier), code_challenge_method: "S256" }).toString();
      return page(`<section><h2>Connect your ChatGPT account</h2><p>Open ChatGPT in a new tab and approve access for your personal agent.</p><a class="button" target="_blank" rel="noopener noreferrer" href="${escape(dest)}">Continue with ChatGPT</a><p>After approval, your browser may show a connection error at <code>127.0.0.1:1455</code>. Copy the <strong>complete URL</strong> from that tab\u2019s address bar and paste it here.</p><form method="post" action="/admin/chatgpt/complete">${csrfInput(s)}<label for="callback">Final redirect URL</label><input id="callback" name="callback" type="url" required autocomplete="off" spellcheck="false" placeholder="http://127.0.0.1:1455/auth/callback?\u2026"><button>Save ChatGPT connection</button></form><p class="muted">Only this private page should receive the URL. Never paste it into chat.</p></section><a href="/admin">Back to admin</a>`);
    }
    if (path === "/admin/chatgpt/complete") {
      const body = await this.post(request, s), pending = await this.pending(s);
      let cb;
      try {
        cb = new URL(body.get("callback"));
      } catch {
        fail("Paste the complete callback URL from this sign-in.");
      }
      if (cb.origin !== "http://127.0.0.1:1455" || cb.pathname !== "/auth/callback" || cb.username || cb.password || cb.hash || cb.searchParams.get("state") !== pending.state || cb.searchParams.has("error") || !cb.searchParams.get("code")) fail("Callback URL or state did not match. No token exchange was attempted.");
      const clientId = cb.searchParams.get("client_id") || (pending.clientId !== "dynamic_agent_client" ? pending.clientId : null);
      if (!clientId || clientId === "dynamic_agent_client" || pending.clientId !== "dynamic_agent_client" && clientId !== pending.clientId) fail("Missing or mismatched issued client ID.");
      pending.status = "exchanging";
      await this.save("chatgpt-pending", pending);
      try {
        const data = await this.token(new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code: cb.searchParams.get("code"), code_verifier: pending.verifier, redirect_uri: CALLBACK, resource: RESOURCE }));
        const identity = await this.verifyIdentity(data.id_token, clientId, pending.nonce);
        if (pending.subject && identity.sub !== pending.subject) fail("This is a different ChatGPT account. Disconnect locally before switching accounts.", 403);
        const credential = this.credential(data, clientId);
        await this.save("chatgpt", { status: "ready", credential, identity: { sub: identity.sub, email: identity.email }, connectedAt: this.now() });
        await this.storage.delete("chatgpt-pending");
        return redirect("/admin");
      } catch (e) {
        await this.storage.delete("chatgpt-pending");
        throw e;
      }
    }
    if (path === "/admin/chatgpt/disconnect") {
      await this.post(request, s);
      await this.storage.delete(["chatgpt", "chatgpt-pending"]);
      return page('<section><h2>Disconnected locally</h2><p>The saved ChatGPT credentials have been removed from this agent. To revoke the authorization at OpenAI too, remove the app in your ChatGPT settings.</p><a href="/admin">Return to admin</a></section>');
    }
    fail("Not found.", 404);
  }
  async setupPage() {
    const state = random();
    const origin = this.env.PUBLIC_ORIGIN;
    const manifest = { name: "Durable Pi Modal " + this.env.GITHUB_OWNER_LOGIN, url: origin, redirect_url: origin + "/setup/callback", callback_urls: [origin + "/auth/github/callback"], hook_attributes: { url: origin + "/github/events", active: false }, public: false, default_permissions: {}, default_events: [], description: "Private owner-only sign-in for Durable Pi Modal. No repository access requested." };
    return page(`<section><h2>One-time GitHub setup</h2><p>Create the private sign-in app under <strong>${escape(this.env.GITHUB_OWNER_LOGIN)}</strong>. GitHub will ask you to confirm its name. No repository permissions are requested.</p><form method="post" action="https://github.com/settings/apps/new?state=${state}"><input type="hidden" name="manifest" value="${escape(JSON.stringify(manifest))}"><button>Set up with GitHub</button></form><p class="muted">After setup, sign in with GitHub to connect ChatGPT. Other GitHub accounts cannot claim this agent.</p></section>`, 200, { "Set-Cookie": await this.setCookie("flow", { purpose: "manifest", state }, 600) });
  }
  async pending(s) {
    const p = await this.read("chatgpt-pending");
    if (!p || p.sid !== s.sid || p.expires <= this.now() || p.status !== "pending") fail("ChatGPT sign-in expired or was already submitted. Start a fresh connection.", 409);
    return p;
  }
  async token(body) {
    return this.json(TOKEN_URL, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  }
  credential(data, clientId) {
    if (typeof data.access_token !== "string" || !data.access_token || typeof data.refresh_token !== "string" || !data.refresh_token || !Number.isFinite(data.expires_in) || data.expires_in <= 180 || typeof data.scope !== "string" || !data.scope.split(/\s+/).includes("chatgpt.tokens.use.direct")) fail("ChatGPT plan usage was not granted. No credentials were saved.", 403);
    return { type: "oauth", access: data.access_token, refresh: data.refresh_token, expires: this.now() + data.expires_in * 1e3 - 18e4, clientId, scopes: data.scope.split(/\s+/) };
  }
  async verifyIdentity(idToken, clientId, nonce) {
    if (typeof idToken !== "string") fail("OpenAI did not return a verifiable identity.", 403);
    const jwks = await this.json(OPENAI_ISSUER + "/.well-known/jwks.json");
    try {
      const { payload } = await jwtVerify(idToken, createLocalJWKSet(jwks), { issuer: OPENAI_ISSUER, audience: clientId, algorithms: ["RS256", "ES256"], requiredClaims: ["sub", "exp", "iat"], clockTolerance: 5, currentDate: new Date(this.now()) });
      if (payload.nonce !== nonce || typeof payload.sub !== "string" || !payload.sub) throw Error("identity");
      return payload;
    } catch {
      fail("ChatGPT identity validation failed. No credentials were saved.", 403);
    }
  }
  // Internal integration seam for the webhook/Pi runtime. Not an HTTP route or
  // Durable Object RPC export: this class uses only the fetch interface.
  async withModelCredential(fn) {
    return this.serial(async () => {
      let model = await this.read("chatgpt");
      if (!model || model.status !== "ready") fail("Reconnect ChatGPT from admin.", 409);
      if (model.credential.expires <= this.now()) {
        model.status = "refreshing";
        await this.save("chatgpt", model);
        try {
          const old = model.credential;
          const grant = await this.token(new URLSearchParams({ grant_type: "refresh_token", client_id: old.clientId, refresh_token: old.refresh, resource: RESOURCE }));
          model.credential = this.credential(grant, old.clientId);
          model.status = "ready";
          await this.save("chatgpt", model);
        } catch (e) {
          model.status = "reconnect-required";
          await this.save("chatgpt", model);
          throw e;
        }
      }
      return fn(model.credential);
    });
  }
};
export {
  OwnerAuthority,
  worker_default as default
};
