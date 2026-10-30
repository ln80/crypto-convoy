// Runs the formal models in formal/ with Tamarin and compares each lemma's result with
// formal/expected.json, then checks that each mutation breaks the lemma it names (plan 027).
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const { models } = JSON.parse(readFileSync(join(root, "formal/expected.json"), "utf8"));

if (spawnSync("tamarin-prover", ["--version"], { encoding: "utf8" }).status !== 0) {
  console.log("check:formal skipped: tamarin-prover isn't installed (formal/README.md).");
  process.exit(0);
}

/** Every lemma's result in a batch run: `verified` or `falsified`, else `unfinished`. */
function prove(file, flags = []) {
  const output = execFileSync("tamarin-prover", ["--prove", ...flags.map((f) => `-D=${f}`), join(root, "formal", file)], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });
  const summary = output.slice(output.lastIndexOf("summary of summaries"));
  const results = {};
  for (const [, lemma, result] of summary.matchAll(/^\s*([A-Za-z0-9_]+) \((?:all-traces|exists-trace)\): (verified|falsified|analysis incomplete)/gm)) {
    results[lemma] = result === "analysis incomplete" ? "unfinished" : result;
  }
  return results;
}

const failures = [];
for (const [file, { lemmas, mutations }] of Object.entries(models)) {
  const results = prove(file);
  for (const [lemma, expected] of Object.entries(lemmas)) {
    if (results[lemma] !== expected) failures.push(`${file}: ${lemma} is ${results[lemma] ?? "missing"}, expected ${expected}`);
  }
  for (const lemma of Object.keys(results)) if (!(lemma in lemmas)) failures.push(`${file}: ${lemma} isn't in formal/expected.json`);
  for (const [flag, lemma] of Object.entries(mutations ?? {})) {
    const mutated = prove(file, [flag]);
    if (mutated[lemma] !== "falsified") failures.push(`${file} with ${flag}: ${lemma} is ${mutated[lemma] ?? "missing"}, expected falsified`);
  }
}

if (failures.length > 0) {
  console.error(`check:formal found ${failures.length} problem(s):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log(`check:formal passed: ${Object.keys(models).join(", ")}, every lemma as expected, every mutation caught.`);
