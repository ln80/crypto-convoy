// Runs the formal models in formal/ with Tamarin and compares each lemma's result with
// formal/expected.json, then checks that each mutation breaks the lemma it names (plan 027).
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const { models } = JSON.parse(readFileSync(join(root, "formal/expected.json"), "utf8"));

// A native tamarin-prover, else the image built from formal/Dockerfile (Intel macOS has no native build).
const IMAGE = "crypto-convoy-tamarin:1.12.0";
const native = spawnSync("tamarin-prover", ["--version"], { encoding: "utf8" }).status === 0;
const docker = !native && spawnSync("docker", ["image", "inspect", IMAGE], { encoding: "utf8" }).status === 0;
if (!native && !docker) {
  console.log(`check:formal skipped: no tamarin-prover, and no ${IMAGE} image (formal/README.md).`);
  process.exit(0);
}
const tamarin = (args) =>
  native
    ? ["tamarin-prover", args.map((a) => (a.endsWith(".spthy") ? join(root, "formal", a) : a))]
    : ["docker", ["run", "--rm", "--platform", "linux/amd64", "-v", `${join(root, "formal")}:/formal:ro`, IMAGE, ...args]];

/**
 * Every lemma's result in a batch run (`only`: one lemma): `verified` or `falsified`, else
 * `unfinished`. Tamarin's output, proofs included, can run to many megabytes: it goes to a file.
 */
function prove(file, flags = [], only) {
  const [command, args] = tamarin([`--prove${only ? `=${only}` : ""}`, ...flags.map((f) => `-D=${f}`), file]);
  // An exists-trace lemma is searched breadth-first: a deep search can follow the chain forever.
  args.splice(args.length - 1, 0, "--stop-on-trace=BFS", "--derivcheck-timeout=0");
  const dir = mkdtempSync(join(tmpdir(), "check-formal-"));
  const out = openSync(join(dir, "out.txt"), "w");
  const started = Date.now();
  try {
    execFileSync(command, args, { stdio: ["ignore", out, out] });
  } finally {
    closeSync(out);
  }
  const output = readFileSync(join(dir, "out.txt"), "utf8");
  rmSync(dir, { recursive: true });
  console.log(`  ${file}${flags.length > 0 ? ` -D=${flags.join(" -D=")}` : ""}${only ? ` (${only})` : ""}: ${Math.round((Date.now() - started) / 1000)}s`);
  const summary = output.slice(output.lastIndexOf("summary of summaries"));
  const results = {};
  for (const [, lemma, result] of summary.matchAll(/^\s*([A-Za-z0-9_]+) \((?:all-traces|exists-trace)\): (verified|falsified|analysis incomplete)/gm)) {
    results[lemma] = result === "analysis incomplete" ? "unfinished" : result;
  }
  return results;
}

const failures = [];
// A model is a file run with optional preprocessor flags (`file`, `flags`; the key names the run).
for (const [name, { file = name, flags = [], lemmas, mutations }] of Object.entries(models)) {
  const results = prove(file, flags);
  for (const [lemma, expected] of Object.entries(lemmas)) {
    if (results[lemma] !== expected) failures.push(`${name}: ${lemma} is ${results[lemma] ?? "missing"}, expected ${expected}`);
  }
  for (const lemma of Object.keys(results)) if (!(lemma in lemmas)) failures.push(`${name}: ${lemma} isn't in formal/expected.json`);
  for (const [flag, lemma] of Object.entries(mutations ?? {})) {
    const mutated = prove(file, [...flags, flag], lemma);
    if (mutated[lemma] !== "falsified") failures.push(`${name} with ${flag}: ${lemma} is ${mutated[lemma] ?? "missing"}, expected falsified`);
  }
}

if (failures.length > 0) {
  console.error(`check:formal found ${failures.length} problem(s):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log(`check:formal passed: ${Object.keys(models).join(", ")}, every lemma as expected, every mutation caught.`);
