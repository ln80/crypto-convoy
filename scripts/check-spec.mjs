#!/usr/bin/env node
// Consistency checks for the specification documents in docs/.
// Run with `npm run check:spec` after any change to docs/. Exits 1 on failure.
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const docsDir = join(root, "docs");
const read = (path) => readFileSync(path, "utf8");

const docs = Object.fromEntries(
  readdirSync(docsDir)
    .filter((name) => name.endsWith(".md"))
    .map((name) => [name, read(join(docsDir, name))]),
);
const readme = read(join(root, "README.md"));
const protocol = docs["protocol.md"];
const properties = docs["security-properties.md"];
const allDocs = Object.entries(docs).map(([name, text]) => ({ name, text }));

const failures = [];
const fail = (check, message) => failures.push(`[${check}] ${message}`);
const unique = (values) => [...new Set(values)].sort();

// 1. Labels: every label used is in the protocol §1 table, and every table entry is used.
{
  const tableStart = protocol.indexOf("| Short name |");
  const tableEnd = protocol.indexOf("\n\n", tableStart);
  const table = unique(
    [...protocol.slice(tableStart, tableEnd).matchAll(/^\| `([a-z-]+)` \|/gm)].map((m) => m[1]),
  );
  const used = unique([
    ...[...protocol.matchAll(/\b(?:wrap|seal|sign|stream)\([^,()]+, "([a-z-]+)"/g)].map((m) => m[1]),
    ...[...protocol.matchAll(/label\("([a-z-]+)"\)/g)].map((m) => m[1]),
  ]);
  if (table.length === 0) fail("labels", "label table not found in protocol §1");
  for (const name of used) if (!table.includes(name)) fail("labels", `"${name}" is used but not in the §1 table`);
  for (const name of table) if (!used.includes(name)) fail("labels", `"${name}" is in the §1 table but never used`);
}

// 2. Ids: every referenced D-/TH-/SP-/AS- id is defined by a heading or an index/table row.
{
  const defined = new Set();
  for (const { text } of allDocs) {
    for (const m of text.matchAll(/^#+ ((?:D|TH|SP|AS)-\d+):/gm)) defined.add(m[1]);
    for (const m of text.matchAll(/^\| ((?:D|TH|SP|AS)-\d+) \|/gm)) defined.add(m[1]);
  }
  const referenced = unique(
    [...allDocs.map((d) => d.text), readme].flatMap((text) =>
      [...text.matchAll(/\b((?:D|TH|SP|AS)-\d+)\b/g)].map((m) => m[1]),
    ),
  );
  for (const id of referenced) if (!defined.has(id)) fail("ids", `${id} is referenced but never defined`);
}

// 3. Section references: every §n or §n.m resolves to a protocol heading.
{
  const headings = new Set(
    [...protocol.matchAll(/^#{2,} (\d+(?:\.\d+)?)\.? /gm)].map((m) => m[1]),
  );
  for (const { name, text } of allDocs) {
    for (const ref of unique([...text.matchAll(/§(\d+(?:\.\d+)?)/g)].map((m) => m[1]))) {
      if (!headings.has(ref)) fail("sections", `${name}: §${ref} has no matching protocol heading`);
    }
  }
}

// Properties, split into entries, with their deferred status.
const propertyEntries = properties
  .split(/^(?=### SP-\d+:)/m)
  .filter((chunk) => chunk.startsWith("### SP-"))
  .map((chunk) => ({
    id: chunk.match(/^### (SP-\d+):/)[1],
    deferred: /^Status: deferred/im.test(chunk),
    text: chunk,
  }));

// 4. Vectors: every vector file named by a non-deferred property is listed in protocol §13.
{
  const listed = new Set([...protocol.matchAll(/^\| `([a-z-]+\.v\d+\.json)` \|/gm)].map((m) => m[1]));
  for (const entry of propertyEntries.filter((e) => !e.deferred)) {
    for (const m of entry.text.matchAll(/test\/vectors\/([a-z-]+\.v\d+\.json)/g)) {
      if (!listed.has(m[1])) fail("vectors", `${entry.id} names ${m[1]}, not listed in protocol §13`);
    }
  }
}

// 5. Traceability: every non-deferred property is realized somewhere in the hierarchy or protocol.
{
  const mechanisms = docs["key-hierarchy.md"] + protocol;
  for (const entry of propertyEntries.filter((e) => !e.deferred)) {
    if (!new RegExp(`\\b${entry.id}\\b`).test(mechanisms)) {
      fail("traceability", `${entry.id} is not referenced in key-hierarchy.md or protocol.md`);
    }
  }
}

// 6. Product terms: none, except in decision D-12, which explains the renaming.
{
  const productTerms = /\b(doconvoy|workspace|tenant|receivable|shareable)\b/i;
  const check = (name, text) => {
    const withoutD12 = name === "decisions.md" ? text.replace(/^## D-12:[\s\S]*?(?=^## D-)/m, "") : text;
    for (const line of withoutD12.split("\n")) {
      if (productTerms.test(line)) fail("terms", `${name}: product term in "${line.trim().slice(0, 80)}"`);
    }
  };
  for (const { name, text } of allDocs) check(name, text);
  check("README.md", readme);
}

if (failures.length > 0) {
  console.error(`check:spec found ${failures.length} problem(s):`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log("check:spec passed: labels, ids, § references, vectors, traceability, product terms.");
