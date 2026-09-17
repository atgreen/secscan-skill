#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Anthony Green
//
// Structure and interpreter adapted from cloudflare/security-audit-skill's
// validate-findings.cjs (MIT); see NOTICE.

/**
 * Validates a secscan findings.json against findings.schema.json.
 * Usage: node validate-findings.cjs [--repo <root>] <path-to-findings.json>
 *
 * The validation rules live in findings.schema.json — the single source of
 * truth. This script reads that schema at runtime and interprets the subset of
 * JSON Schema it uses: type (object|array|string|number|integer|boolean),
 * properties, required, additionalProperties:false, enum, const, items,
 * minItems, minimum, maximum, and oneOf.
 *
 * Some constraints can't be expressed in that subset (source_ref/sink_ref must
 * look like file:line). They're applied as an explicit, clearly-labelled
 * semantic layer after schema validation.
 *
 * With --repo <root>, a third layer resolves every file:line citation against
 * the scanned tree: the file must exist inside it and the line must be in
 * range and non-blank. A citation that doesn't resolve was never read, it was
 * imagined — the cheapest filter there is on the dominant LLM-SAST failure
 * mode, and it costs no model tokens. Without --repo the citation layer is
 * skipped and behaviour is unchanged.
 *
 * Still a structural check — a resolving citation proves the line exists, not
 * that the finding is correct (that was s6's job). Zero dependencies. Exits 0
 * on success, 1 on validation failure.
 */

const fs = require("fs");
const path = require("path");

const USAGE = "Usage: node validate-findings.cjs [--repo <root>] <path-to-findings.json>";

// --repo is optional: without it we check shape only, with it we also resolve
// every citation against the tree that was scanned.
let file = null;
let repoArg = null;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
	const arg = argv[i];
	if (arg === "--repo") {
		repoArg = argv[++i];
		if (repoArg === undefined) {
			console.error("--repo requires a path");
			process.exit(1);
		}
	} else if (arg.startsWith("--repo=")) {
		repoArg = arg.slice("--repo=".length);
	} else if (arg === "-h" || arg === "--help") {
		console.log(USAGE);
		process.exit(0);
	} else if (arg.startsWith("-") && arg !== "-") {
		console.error(`Unknown option: ${arg}\n${USAGE}`);
		process.exit(1);
	} else if (file === null) {
		file = arg;
	} else {
		console.error(`Unexpected extra argument: ${arg}\n${USAGE}`);
		process.exit(1);
	}
}

if (!file) {
	console.error(USAGE);
	process.exit(1);
}

let repoRoot = null;
if (repoArg !== null) {
	if (repoArg === "") {
		console.error("--repo requires a path");
		process.exit(1);
	}
	repoRoot = path.resolve(repoArg);
	let stat;
	try {
		stat = fs.statSync(repoRoot);
	} catch (e) {
		console.error(`--repo: cannot stat ${repoRoot}: ${e.message}`);
		process.exit(1);
	}
	if (!stat.isDirectory()) {
		console.error(`--repo: not a directory: ${repoRoot}`);
		process.exit(1);
	}
}

const schemaPath = path.join(__dirname, "findings.schema.json");
let itemSchema;
try {
	const doc = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
	itemSchema = doc.output_schema;
	if (!itemSchema) throw new Error('findings.schema.json is missing top-level "output_schema"');
} catch (e) {
	console.error(`Failed to load schema from ${schemaPath}:`, e.message);
	process.exit(1);
}

let findings;
try {
	findings = JSON.parse(fs.readFileSync(file, "utf8"));
} catch (e) {
	console.error("Failed to parse JSON:", e.message);
	process.exit(1);
}

if (!Array.isArray(findings)) {
	console.error("findings.json must be an array");
	process.exit(1);
}

// --- Generic JSON Schema interpreter (the subset used by findings.schema.json) ---

function typeOf(v) {
	if (Array.isArray(v)) return "array";
	if (v === null) return "null";
	return typeof v; // "object" | "string" | "number" | "boolean"
}

// For oneOf: find a property defined with a `const` so error messages can point
// at the intended branch (e.g. discriminate true_positive vs false_positive by
// "verdict").
function findDiscriminator(schema) {
	if (!schema.properties) return null;
	for (const [key, sub] of Object.entries(schema.properties)) {
		if (sub && Object.prototype.hasOwnProperty.call(sub, "const")) {
			return { key, value: sub.const };
		}
	}
	return null;
}

function validate(value, schema, p, errors) {
	if (schema.oneOf) {
		// Prefer the branch whose const discriminator matches, so the caller sees
		// detailed errors for the branch they clearly intended.
		for (const branch of schema.oneOf) {
			const disc = findDiscriminator(branch);
			if (disc && value && typeof value === "object" && value[disc.key] === disc.value) {
				validate(value, branch, p, errors);
				return;
			}
		}
		// No discriminator matched. If every branch is discriminated by the same
		// key, report the bad discriminator value clearly.
		const discs = schema.oneOf.map(findDiscriminator).filter(Boolean);
		if (discs.length === schema.oneOf.length && value && typeof value === "object") {
			const key = discs[0].key;
			const allowed = discs.map((d) => JSON.stringify(d.value)).join(", ");
			errors.push(`${p}: "${key}" must be one of ${allowed}, got ${JSON.stringify(value[key])}`);
			return;
		}
		const passing = schema.oneOf.filter((b) => collect(value, b, p).length === 0);
		if (passing.length !== 1) {
			errors.push(`${p}: does not match exactly one of the allowed schemas`);
		}
		return;
	}

	if (Object.prototype.hasOwnProperty.call(schema, "const") && value !== schema.const) {
		errors.push(`${p}: must equal ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
	}

	if (schema.enum && !schema.enum.includes(value)) {
		const allowed = schema.enum.map((v) => JSON.stringify(v)).join(", ");
		errors.push(`${p}: invalid value ${JSON.stringify(value)} (expected one of ${allowed})`);
	}

	switch (schema.type) {
		case "object": {
			if (typeOf(value) !== "object") {
				errors.push(`${p}: expected object, got ${typeOf(value)}`);
				return;
			}
			for (const req of schema.required || []) {
				if (!(req in value)) errors.push(`${p}: missing required field "${req}"`);
			}
			for (const key of Object.keys(value)) {
				if (schema.properties && key in schema.properties) {
					validate(value[key], schema.properties[key], `${p}.${key}`, errors);
				} else if (schema.additionalProperties === false) {
					errors.push(`${p}: unexpected field "${key}"`);
				}
			}
			break;
		}
		case "array": {
			if (typeOf(value) !== "array") {
				errors.push(`${p}: expected array, got ${typeOf(value)}`);
				return;
			}
			if (typeof schema.minItems === "number" && value.length < schema.minItems) {
				errors.push(`${p}: must have at least ${schema.minItems} item(s), got ${value.length}`);
			}
			if (schema.items) {
				value.forEach((el, i) => validate(el, schema.items, `${p}[${i}]`, errors));
			}
			break;
		}
		case "number": {
			if (typeOf(value) !== "number") {
				errors.push(`${p}: expected number, got ${typeOf(value)}`);
				break;
			}
			if (typeof schema.minimum === "number" && value < schema.minimum) {
				errors.push(`${p}: must be >= ${schema.minimum}, got ${value}`);
			}
			if (typeof schema.maximum === "number" && value > schema.maximum) {
				errors.push(`${p}: must be <= ${schema.maximum}, got ${value}`);
			}
			break;
		}
		case "integer": {
			if (typeOf(value) !== "number" || !Number.isInteger(value)) {
				errors.push(`${p}: expected integer, got ${typeOf(value)}`);
			}
			break;
		}
		case "string": {
			if (typeOf(value) !== "string") {
				errors.push(`${p}: expected string, got ${typeOf(value)}`);
			}
			break;
		}
		case "boolean": {
			if (typeOf(value) !== "boolean") {
				errors.push(`${p}: expected boolean, got ${typeOf(value)}`);
			}
			break;
		}
		default:
			break; // no type constraint at this node
	}
}

function collect(value, schema, p) {
	const errors = [];
	validate(value, schema, p, errors);
	return errors;
}

// A ref must look like "path:line" — a non-empty path, a colon, and a line
// number. This is what makes a finding checkable against source.
function isFileLine(ref) {
	return typeof ref === "string" && /^.+:\d+$/.test(ref.trim());
}

// --- Citation layer (only with --repo) ----------------------------------------
// Resolve each file:line against the scanned tree. A finding that points at a
// file that isn't there, or past the end of one, was not read — it was
// imagined, and no amount of prose around it makes the path real.

const fileCache = new Map();

// Read a file once and split it into lines. A trailing newline terminates the
// last line rather than starting an empty one, so `foo\n` is one line, not two.
function linesOf(abs) {
	if (fileCache.has(abs)) return fileCache.get(abs);
	let result;
	try {
		const lines = fs.readFileSync(abs, "utf8").split("\n");
		if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
		result = { lines };
	} catch (e) {
		result = { error: e.message };
	}
	fileCache.set(abs, result);
	return result;
}

// Split on the LAST colon: a Windows path or a URL-ish prefix may contain others.
function splitRef(ref) {
	const trimmed = String(ref).trim();
	const idx = trimmed.lastIndexOf(":");
	return { relPath: trimmed.slice(0, idx), line: Number(trimmed.slice(idx + 1)) };
}

function checkCitation(ref, p, errors) {
	const { relPath, line } = splitRef(ref);
	const abs = path.resolve(repoRoot, relPath);

	// Refuse to follow a citation out of the tree that was scanned — an absolute
	// path or a ../ climb points at something the scan never covered.
	if (abs !== repoRoot && !abs.startsWith(repoRoot + path.sep)) {
		errors.push(`${p}: ${relPath} resolves outside the scanned tree (${repoRoot})`);
		return;
	}

	let stat;
	try {
		stat = fs.statSync(abs);
	} catch (e) {
		errors.push(`${p}: no such file in the scanned tree: ${relPath}`);
		return;
	}
	if (!stat.isFile()) {
		errors.push(`${p}: not a regular file: ${relPath}`);
		return;
	}

	const read = linesOf(abs);
	if (read.error) {
		errors.push(`${p}: cannot read ${relPath}: ${read.error}`);
		return;
	}
	if (line < 1 || line > read.lines.length) {
		errors.push(`${p}: line ${line} is out of range — ${relPath} has ${read.lines.length} line(s)`);
		return;
	}
	if (read.lines[line - 1].trim() === "") {
		errors.push(`${p}: line ${line} of ${relPath} is blank — a citation must point at code`);
	}
}

// --- Run ----------------------------------------------------------------------

let errorCount = 0;

findings.forEach((f, i) => {
	const label = `[${i}] ${(f && f.title) || "(untitled)"}`;
	console.log(`Checking ${label}`);

	const errs = collect(f, itemSchema, `[${i}]`);

	// Semantic layer — constraints the schema subset can't express:
	// a true_positive must cite source_ref and sink_ref as file:line.
	if (f && f.verdict === "true_positive") {
		if ("source_ref" in f && !isFileLine(f.source_ref)) {
			errs.push(`[${i}].source_ref must look like file:line, got ${JSON.stringify(f.source_ref)}`);
		}
		if ("sink_ref" in f && !isFileLine(f.sink_ref)) {
			errs.push(`[${i}].sink_ref must look like file:line, got ${JSON.stringify(f.sink_ref)}`);
		}
	}

	// Citation layer — only for refs that are well-formed enough to resolve;
	// a malformed ref already failed above and would only error twice.
	if (repoRoot && f && f.verdict === "true_positive") {
		if (isFileLine(f.source_ref)) checkCitation(f.source_ref, `[${i}].source_ref`, errs);
		if (isFileLine(f.sink_ref)) checkCitation(f.sink_ref, `[${i}].sink_ref`, errs);
	}

	for (const msg of errs) console.error("  ERROR:", msg);
	errorCount += errs.length;
});

console.log();
if (errorCount === 0) {
	const scope = repoRoot ? "valid, citations resolved" : "valid (shape only — pass --repo to resolve citations)";
	console.log(`PASS: ${findings.length} finding(s) ${scope}`);
} else {
	console.error(`FAIL: ${errorCount} error(s) across ${findings.length} finding(s)`);
	process.exit(1);
}
