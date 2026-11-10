// Cross-implementation test: the browser code must produce the same canonical
// payload and the same deterministic ed25519 signature as gitdns-core (Rust).
// The fixture was signed by the Rust CLI with the test seed in this folder.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import nacl from "../web/vendor/tweetnacl.min.js";
import {
  canonicalPayload,
  decodeBase64Url,
  dumpDomainToml,
  identityFromSeed,
  signDomain,
} from "../web/zone.js";

globalThis.nacl = nacl;

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "fixtures", "canonical-shop.json"), "utf8"),
);
const signedToml = readFileSync(join(here, "fixtures", "signed-shop.toml"), "utf8");

test("canonical payload matches the Rust implementation", () => {
  assert.equal(canonicalPayload(fixture.zone, fixture.domain), fixture.payload);
});

test("record order does not change the payload", () => {
  const shuffled = {
    ...fixture.domain,
    records: [...fixture.domain.records].reverse(),
  };
  assert.equal(canonicalPayload(fixture.zone, shuffled), fixture.payload);
});

test("ed25519 signature matches the Rust fixture", () => {
  const identity = identityFromSeed(decodeBase64Url(fixture.seed));
  assert.equal(identity.publicKey, fixture.public);

  const signed = signDomain(
    fixture.zone,
    {
      name: fixture.domain.name,
      created: fixture.domain.created,
      updated: fixture.domain.updated,
      records: fixture.domain.records,
    },
    identity,
  );
  assert.equal(signed.signature.value, fixture.signature);
  assert.equal(signed.owner, fixture.public);
});

test("TOML output can be parsed again and keeps the signature", () => {
  const text = dumpDomainToml(fixture.domain);
  assert.match(text, /\[signature\]/);
  assert.ok(text.includes(`key = "ed25519:`));
  for (const record of fixture.domain.records) {
    assert.ok(text.includes(`type = "${record.type}"`));
  }
  // The CLI writes the same field set. Compare normalized lines so the test
  // does not depend on blank-line placement between TOML tables.
  const normalize = (value) =>
    value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .join("\n");
  assert.equal(normalize(text), normalize(signedToml));
});
