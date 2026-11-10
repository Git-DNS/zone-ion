// Canonical domain documents, ed25519 signatures and TOML output for the
// .ion registration site. This module has no DOM dependencies so the same
// code can run in the browser and in Node tests.

const KEY_PREFIX = "ed25519:";
const RECORD_FIELDS = [
  "ttl",
  "value",
  "values",
  "priority",
  "weight",
  "port",
  "flags",
  "tag",
];
const encoder = new TextEncoder();

export const MAX_TTL = 604800;
export const MAX_RECORDS = 64;
export const MAX_VALUES = 16;
export const ISSUE_MARKER = "<!-- gitdns-registration:v1 -->";

export class ZoneError extends Error {
  constructor(message) {
    super(message);
    this.name = "ZoneError";
  }
}

export function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64Url(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) {
    throw new ZoneError("value is not valid base64url");
  }
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function utf8(text) {
  return encoder.encode(text);
}

export function compactJson(value) {
  return JSON.stringify(value);
}

function canonicalRecord(record) {
  const out = { type: String(record.type).trim().toUpperCase() };
  for (const key of RECORD_FIELDS) {
    if (record[key] !== undefined && record[key] !== null) {
      out[key] = record[key];
    }
  }
  return out;
}

function compareBytes(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return left.length - right.length;
}

// Build the exact bytes that the owner signs. Field order, record sorting and
// JSON formatting must match gitdns-core/src/record.rs and
// scripts/zone_admin.py.
export function canonicalPayload(zone, domain) {
  const records = domain.records.map(canonicalRecord);
  records.sort((left, right) =>
    compareBytes(utf8(compactJson(left)), utf8(compactJson(right))),
  );

  const payload = {
    schema: domain.schema,
    zone: String(zone).trim().replace(/\.+$/, "").toLowerCase(),
    name: String(domain.name).trim(),
    owner: domain.owner || "",
    created: String(domain.created).trim(),
    updated: String(domain.updated).trim(),
  };
  if (domain.ttl !== undefined && domain.ttl !== null) {
    payload.ttl = domain.ttl;
  }
  payload.records = records;
  return compactJson(payload);
}

function requireNacl() {
  const nacl = globalThis.nacl;
  if (!nacl || !nacl.sign) {
    throw new ZoneError("the ed25519 library is not loaded");
  }
  return nacl;
}

export function identityFromSeed(seedBytes) {
  if (seedBytes.length !== 32) {
    throw new ZoneError("the identity seed must be 32 bytes");
  }
  const pair = requireNacl().sign.keyPair.fromSeed(seedBytes);
  return {
    seed: encodeBase64Url(seedBytes),
    publicKey: KEY_PREFIX + encodeBase64Url(pair.publicKey),
    secretKey: pair.secretKey,
    publicKeyBytes: pair.publicKey,
  };
}

export function generateIdentity() {
  const pair = requireNacl().sign.keyPair();
  return identityFromSeed(pair.secretKey.slice(0, 32));
}

export function signDomain(zone, domain, identity) {
  const owner = identity.publicKey;
  const document = {
    schema: 1,
    name: domain.name,
    owner,
    created: domain.created,
    updated: domain.updated,
    records: domain.records,
  };
  if (domain.ttl !== undefined && domain.ttl !== null) {
    document.ttl = domain.ttl;
  }
  const payload = canonicalPayload(zone, document);
  const signature = requireNacl().sign.detached(utf8(payload), identity.secretKey);
  return {
    ...document,
    signature: {
      key: owner,
      value: encodeBase64Url(signature),
      signed_at: new Date().toISOString(),
    },
  };
}

export function tomlString(value) {
  return JSON.stringify(String(value));
}

export function dumpDomainToml(domain) {
  const lines = [
    `schema = ${domain.schema}`,
    `name = ${tomlString(domain.name)}`,
  ];
  if (domain.owner) {
    lines.push(`owner = ${tomlString(domain.owner)}`);
  }
  lines.push(
    `created = ${tomlString(domain.created)}`,
    `updated = ${tomlString(domain.updated)}`,
  );
  if (domain.ttl !== undefined && domain.ttl !== null) {
    lines.push(`ttl = ${domain.ttl}`);
  }
  for (const record of domain.records) {
    lines.push("", "[[records]]", `type = ${tomlString(record.type)}`);
    for (const key of RECORD_FIELDS) {
      if (record[key] === undefined || record[key] === null) {
        continue;
      }
      if (key === "values") {
        lines.push(`values = [${record[key].map(tomlString).join(", ")}]`);
      } else if (typeof record[key] === "string") {
        lines.push(`${key} = ${tomlString(record[key])}`);
      } else {
        lines.push(`${key} = ${record[key]}`);
      }
    }
  }
  if (domain.signature) {
    lines.push(
      "",
      "[signature]",
      `key = ${tomlString(domain.signature.key)}`,
      `value = ${tomlString(domain.signature.value)}`,
    );
    if (domain.signature.signed_at) {
      lines.push(`signed_at = ${tomlString(domain.signature.signed_at)}`);
    }
  }
  return lines.join("\n") + "\n";
}

// Return a list of human-readable problems. The server repeats every check.
export function validateName(name) {
  const errors = [];
  const trimmed = String(name || "").trim().toLowerCase();
  if (!trimmed) {
    errors.push("Enter a name.");
    return errors;
  }
  if (trimmed === "@" || trimmed === "ion") {
    errors.push("The zone apex is managed by the maintainers.");
    return errors;
  }
  if (trimmed.length > 253) {
    errors.push("The name is too long.");
  }
  const labels = trimmed.split(".");
  if (labels.length > 16) {
    errors.push("Use no more than 16 labels.");
  }
  for (const label of labels) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) {
      errors.push(`"${label}" must use a-z, 0-9 and inner hyphens (1-63 characters).`);
    }
  }
  return errors;
}

export function validateRecords(records) {
  const errors = [];
  if (!records.length) {
    errors.push("Add at least one record.");
  }
  if (records.length > MAX_RECORDS) {
    errors.push(`Use no more than ${MAX_RECORDS} records.`);
  }
  const hasCname = records.some((record) => record.type === "CNAME");
  if (hasCname && records.length > 1) {
    errors.push("CNAME cannot be combined with other records.");
  }
  for (const record of records) {
    const type = String(record.type || "").toUpperCase();
    const values = record.values || (record.value !== undefined ? [record.value] : []);
    if (!values.length) {
      errors.push(`${type}: enter a value.`);
    }
    if (values.length > MAX_VALUES) {
      errors.push(`${type}: too many values.`);
    }
    if (record.ttl !== undefined && record.ttl !== null) {
      const ttl = Number(record.ttl);
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_TTL) {
        errors.push(`${type}: TTL must be between 1 and ${MAX_TTL}.`);
      }
    }
    if (type === "CNAME" || type === "MX" || type === "NS" || type === "PTR" || type === "SRV") {
      if (values.length !== 1) {
        errors.push(`${type}: exactly one target is required.`);
      }
    }
    if (type === "MX") {
      const priority = record.priority === undefined ? 10 : Number(record.priority);
      if (!Number.isInteger(priority) || priority < 0 || priority > 65535) {
        errors.push("MX: priority must be between 0 and 65535.");
      }
    }
    if (type === "SRV") {
      for (const key of ["priority", "weight", "port"]) {
        const value = record[key] === undefined ? (key === "port" ? undefined : 0) : Number(record[key]);
        if (value === undefined || !Number.isInteger(value) || value < 0 || value > 65535) {
          errors.push(`SRV: ${key} must be between 0 and 65535.`);
        }
      }
    }
    if (type === "CAA") {
      const flags = record.flags === undefined ? 0 : Number(record.flags);
      if (!Number.isInteger(flags) || flags < 0 || flags > 255) {
        errors.push("CAA: flags must be between 0 and 255.");
      }
      const tag = record.tag === undefined ? "issue" : String(record.tag).trim();
      if (!/^[A-Za-z0-9]{1,15}$/.test(tag)) {
        errors.push("CAA: tag must be 1-15 letters or digits.");
      }
    }
    if (type === "A" || type === "AAAA") {
      // The server performs the strict check; this only catches obvious typos.
      for (const value of values) {
        if (!/^[0-9a-fA-F:.]+$/.test(String(value).trim())) {
          errors.push(`${type}: "${value}" does not look like an IP address.`);
        }
      }
    }
  }
  return errors;
}

export function relativeName(name) {
  return String(name || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

export function secondLevel(name) {
  const labels = relativeName(name).split(".");
  return labels[labels.length - 1];
}
