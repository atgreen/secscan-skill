#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Anthony Green
//
// Structure and interpreter adapted from cloudflare/security-audit-skill's
// validate-findings.cjs (MIT); see NOTICE.

/**
 * Validates a secscan findings.json against findings.schema.json.
 * Usage: node validate-findings.cjs <path-to-findings.json>
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
 * Structural check only — it confirms the JSON conforms to the schema, not that
 * the findings are correct (that was s6's job). Zero dependencies. Exits 0 on
 * success, 1 on validation failure.
 */

const fs = require("fs");
const path = require("path");

const file = process.argv[2];
if (!file) {
	console.error("Usage: node validate-findings.cjs <path-to-findings.json>");
	process.exit(1);
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

	for (const msg of errs) console.error("  ERROR:", msg);
	errorCount += errs.length;
});

console.log();
if (errorCount === 0) {
	console.log(`PASS: ${findings.length} finding(s) valid`);
} else {
	console.error(`FAIL: ${errorCount} error(s) across ${findings.length} finding(s)`);
	process.exit(1);
}
