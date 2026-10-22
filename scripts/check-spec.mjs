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

// Lines of a document, each with the ids of the sections it sits in ("D-13", "TH-33", "4.6")
// and, for an index row, the row's own id. Lines in fenced code are marked.
function linesWithContext(text) {
  const stack = [];
  let fenced = false;
  return text.split("\n").map((line, i) => {
    if (line.startsWith("```")) fenced = !fenced;
    const heading = !fenced && line.match(/^(#+) (.*)$/);
    if (heading) {
      const level = heading[1].length;
      while (stack.length > 0 && stack.at(-1).level >= level) stack.pop();
      stack.push({ level, id: heading[2].match(/^((?:D|TH|SP|AS)-\d+|\d+(?:\.\d+)?)\b/)?.[1] });
    }
    const row = line.match(/^\| ((?:D|TH|SP|AS)-\d+) \|/);
    const ids = [...stack.map((s) => s.id).filter(Boolean), ...(row ? [row[1]] : [])];
    return { n: i + 1, line, fenced, ids };
  });
}

// Threats: index rows and entries.
const threats = docs["threat-model.md"];
const threatIndex = new Map(
  [...threats.matchAll(/^\| (TH-\d+) \| (.*?) \| (.*?) \| (.*) \|$/gm)].map((m) => [
    m[1],
    { title: m[2], disposition: m[4] },
  ]),
);
const threatEntries = new Map(
  threats
    .split(/^(?=### TH-\d+:)/m)
    .filter((chunk) => chunk.startsWith("### TH-"))
    .map((chunk) => {
      const [, id, title] = chunk.match(/^### (TH-\d+): (.*)$/m);
      return [id, { title, text: chunk.split(/^## /m)[0] }];
    }),
);
const ids = (text, prefix) => new Set([...text.matchAll(new RegExp(`\\b${prefix}-\\d+\\b`, "g"))].map((m) => m[0]));

// 7. Threat index = threat entries: same ids and titles, the index's disposition class in the
//    entry, the index's properties cited by the entry, and every mitigated threat cites a property.
{
  for (const id of threatIndex.keys()) if (!threatEntries.has(id)) fail("threats", `${id} is in the index but has no entry`);
  for (const [id, entry] of threatEntries) {
    const row = threatIndex.get(id);
    if (!row) {
      fail("threats", `${id} has an entry but no index row`);
      continue;
    }
    if (!row.title.startsWith(entry.title)) fail("threats", `${id}: index title "${row.title}" differs from the heading "${entry.title}"`);
    const disposition = entry.text.match(/^Disposition:[\s\S]*/m)?.[0].toLowerCase() ?? "";
    const kind = row.disposition.toLowerCase().match(/^(not applicable|partly mitigated|mitigated|accepted)/)?.[1];
    if (!kind) fail("threats", `${id}: index disposition doesn't start with Mitigated, Partly mitigated, Accepted or Not applicable`);
    else if (!disposition.includes(kind)) fail("threats", `${id}: index says "${kind}", the entry's Disposition doesn't`);
    const rowProperties = ids(row.disposition, "SP");
    if (kind?.endsWith("mitigated") && rowProperties.size === 0) fail("threats", `${id} is ${kind} but its index row cites no property`);
    for (const sp of rowProperties) if (!ids(entry.text, "SP").has(sp)) fail("threats", `${id}: index cites ${sp}, the entry doesn't`);
  }
}

// 8. Threats ↔ properties: a property's "Related threats" and the threat index cite each other.
//    Deferred properties are exempt: v1 doesn't claim them.
{
  const propertyIndex = new Map([...properties.matchAll(/^\| (SP-\d+) \| (.*) \|$/gm)].map((m) => [m[1], m[2]]));
  for (const entry of propertyEntries) {
    const title = entry.text.match(/^### SP-\d+: (.*)$/m)[1];
    const row = propertyIndex.get(entry.id);
    if (!row) fail("properties", `${entry.id} has an entry but no index row`);
    else if (!row.startsWith(title)) fail("properties", `${entry.id}: index title "${row}" differs from the heading "${title}"`);
    if (entry.deferred) continue;
    const related = ids(entry.text.match(/^Related threats:.*$/m)?.[0] ?? "", "TH");
    if (related.size === 0) fail("properties", `${entry.id} lists no related threats`);
    for (const th of related) {
      if (!ids(threatIndex.get(th)?.disposition ?? "", "SP").has(entry.id)) fail("properties", `${entry.id} lists ${th}, whose index row doesn't cite ${entry.id}`);
    }
  }
  const active = new Set(propertyEntries.filter((e) => !e.deferred).map((e) => e.id));
  for (const [th, row] of threatIndex) {
    for (const sp of ids(row.disposition, "SP")) {
      const entry = propertyEntries.find((e) => e.id === sp);
      if (active.has(sp) && !ids(entry.text.match(/^Related threats:.*$/m)?.[0] ?? "", "TH").has(th)) {
        fail("properties", `${th}'s index row cites ${sp}, which doesn't list ${th} in Related threats`);
      }
    }
  }
}

// 9. Errors: the codes and reasons of protocol §9 are those of src/errors.ts, and the docs use no other.
{
  const section9 = protocol.slice(protocol.indexOf("## 9."), protocol.indexOf("## 10."));
  const tableCodes = unique([...section9.matchAll(/^\| `([A-Z_]+)` \|/gm)].map((m) => m[1]));
  const reasonsCell = section9.match(/^\| `TRUST_FAILURE` \|.*$/m)?.[0] ?? "";
  const tableReasons = unique([...reasonsCell.matchAll(/`([a-z_]+)`/g)].map((m) => m[1])).filter((r) => r !== "reason");
  const source = read(join(root, "src/errors.ts"));
  const union = (name) => unique([...(source.match(new RegExp(`type ${name} =([^;]*);`))?.[1] ?? "").matchAll(/"([A-Za-z_]+)"/g)].map((m) => m[1]));
  const compare = (what, spec, code) => {
    for (const v of spec) if (!code.includes(v)) fail("errors", `${what} ${v} is in protocol §9 but not in src/errors.ts`);
    for (const v of code) if (!spec.includes(v)) fail("errors", `${what} ${v} is in src/errors.ts but not in protocol §9`);
  };
  compare("code", tableCodes, union("ErrorCode"));
  compare("reason", tableReasons, union("TrustReason"));
  const notCodes = new Set(["ALG_ARGON2ID13"]);
  for (const { name, text } of [...allDocs, { name: "README.md", text: readme }]) {
    for (const m of text.matchAll(/`([A-Z]+(?:_[A-Z0-9]+)+)`/g)) {
      if (!notCodes.has(m[1]) && !tableCodes.includes(m[1])) fail("errors", `${name}: \`${m[1]}\` isn't an error code of §9`);
    }
    for (const m of text.matchAll(/`TRUST_FAILURE`[^`\n]{0,20}`([a-z_]+)`/g)) {
      if (m[1] !== "reason" && !tableReasons.includes(m[1])) fail("errors", `${name}: reason \`${m[1]}\` isn't in §9`);
    }
  }
}

// 10. Tables: every row has as many cells as its header (pipes inside backticks don't count).
{
  const cells = (line) => line.replace(/`[^`]*`/g, "").replace(/\\\|/g, "").split("|").length - 2;
  for (const { name, text } of [...allDocs, { name: "README.md", text: readme }]) {
    let header = null;
    for (const { n, line, fenced } of linesWithContext(text)) {
      if (fenced || !line.startsWith("|")) {
        header = null;
        continue;
      }
      if (header === null) header = cells(line);
      else if (cells(line) !== header) fail("tables", `${name}:${n} has ${cells(line)} cells, its header ${header}`);
    }
  }
}

// 11. Retired wording (scripts/retired-terms.json): what a decision retired appears only in the
//     sections allowed to tell its history, or as a known match waiting on an open gap.
const notes = [];
{
  const { terms } = JSON.parse(read(join(root, "scripts/retired-terms.json")));
  for (const term of terms) {
    const pattern = new RegExp(term.pattern);
    const known = (term.known ?? []).map((k) => ({ ...k, seen: false }));
    for (const { name, text } of [...allDocs, { name: "README.md", text: readme }]) {
      const allowed = term.allow[name] ?? [];
      for (const { n, line, ids: within } of linesWithContext(text)) {
        if (!pattern.test(line) || within.some((id) => allowed.includes(id))) continue;
        const match = known.find((k) => k.file === name && line.includes(k.text));
        if (match) {
          match.seen = true;
          notes.push(`${name}:${n} kept until decided: ${match.gap}`);
        } else {
          fail("retired", `${name}:${n} uses wording retired by ${term.decision} ("${line.match(pattern)[0]}"); use: ${term.use}`);
        }
      }
    }
    for (const k of known.filter((k) => !k.seen)) fail("retired", `known match "${k.text}" in ${k.file} is gone: remove it from retired-terms.json`);
  }
}

if (failures.length > 0) {
  console.error(`check:spec found ${failures.length} problem(s):`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
for (const note of notes) console.log(`  note: ${note}`);
console.log(
  "check:spec passed: labels, ids, § references, vectors, traceability, product terms, threats, threats ↔ properties, errors, tables, retired wording.",
);
