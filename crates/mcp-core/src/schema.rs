//! A small, dependency-free JSON Schema validator covering the subset the MCP
//! tool contracts use.
//!
//! This is deliberately **not** a full JSON Schema implementation — pulling a
//! heavy validator into a WASM edge binary is a size/compat risk, and the goal
//! here is to enforce the advertised tool contract before a handler runs so
//! that client/model input cannot silently contradict it (CWE-20). It covers:
//!
//! * `type` (object, string, number, integer, boolean, array, null)
//! * object `properties`, `required`, and `additionalProperties: false`
//!   (reject unknown keys on a closed contract)
//! * string `minLength` / `maxLength` / `enum`
//! * number/integer `minimum` / `maximum`
//! * array `items` / `minItems` / `maxItems`
//! * a hard nesting-depth guard to bound validation work
//!
//! Adopters needing full JSON Schema can validate in their handler or swap this
//! for a complete validator behind the same call site.
//!
//! Reconciliation with the official SDK: `rmcp` is adopted types-only here and
//! ships no JSON Schema *validator* (its tool `input_schema` is an opaque
//! `JsonObject`, and `ToolsCapability` only carries a `schema_validation`
//! capability flag). There is therefore nothing to adopt for enforcement — this
//! fail-closed subset validator (CMCP-010) remains authoritative, and the
//! advertised contract is kept equal to the enforced subset via
//! [`unsupported_keywords`] at registration.

use serde_json::Value;

/// Maximum instance nesting depth accepted during validation (bounds work).
const MAX_DEPTH: usize = 32;

/// Validate `instance` against `schema`. `Ok(())` when valid; `Err(msg)` with a
/// human-readable path/reason otherwise. An empty schema (`{}` / non-object)
/// accepts anything.
pub fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    validate_at(schema, instance, "$", 0)
}

/// Validation keywords this subset enforces.
const ENFORCED: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties", // bool only; a schema-valued form is unsupported
    "enum",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "items",
    "minItems",
    "maxItems",
];

/// Annotation keywords that carry no validation constraint and are safely
/// ignored (so their presence does not mark a schema as unsupported).
const ANNOTATIONS: &[&str] = &[
    "title",
    "description",
    "default",
    "examples",
    "$schema",
    "$id",
    "$comment",
];

/// Return the schema keywords present in `schema` (recursively, through
/// `properties` and `items`) that this validator does **not** enforce — e.g.
/// `pattern`, `const`, `oneOf`/`anyOf`/`allOf`, `$ref`, `format`, or a
/// schema-valued `additionalProperties`. A tool advertising any of these would
/// have that constraint silently unenforced, so registration rejects it
/// (fail-closed) — keeping the enforced subset equal to the advertised contract.
pub fn unsupported_keywords(schema: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_unsupported(schema, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_unsupported(schema: &Value, out: &mut Vec<String>) {
    let Some(obj) = schema.as_object() else {
        return;
    };
    for (key, value) in obj {
        if key == "additionalProperties" {
            if !value.is_boolean() {
                out.push("additionalProperties (schema-valued)".to_string());
            }
            continue;
        }
        if !ENFORCED.contains(&key.as_str()) && !ANNOTATIONS.contains(&key.as_str()) {
            out.push(key.clone());
        }
    }
    // Recurse only where validation itself recurses.
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for sub in props.values() {
            collect_unsupported(sub, out);
        }
    }
    if let Some(items) = obj.get("items") {
        collect_unsupported(items, out);
    }
}

fn validate_at(schema: &Value, instance: &Value, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{path}: nesting exceeds max depth {MAX_DEPTH}"));
    }
    let Some(schema) = schema.as_object() else {
        return Ok(()); // non-object schema: no constraints
    };

    if let Some(ty) = schema.get("type").and_then(Value::as_str) {
        check_type(ty, instance, path)?;
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.iter().any(|a| a == instance) {
            return Err(format!("{path}: value is not one of the allowed enum values"));
        }
    }

    match instance {
        Value::Object(obj) => validate_object(schema, obj, path, depth)?,
        Value::Array(arr) => validate_array(schema, arr, path, depth)?,
        Value::String(s) => validate_string(schema, s, path)?,
        Value::Number(n) => validate_number(schema, n, path)?,
        _ => {}
    }
    Ok(())
}

fn check_type(ty: &str, instance: &Value, path: &str) -> Result<(), String> {
    let ok = match ty {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        "number" => instance.is_number(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        _ => true, // unknown type keyword: don't reject
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{path}: expected type {ty}"))
    }
}

fn validate_object(
    schema: &serde_json::Map<String, Value>,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    let properties = schema.get("properties").and_then(Value::as_object);

    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for req in required.iter().filter_map(Value::as_str) {
            if !obj.contains_key(req) {
                return Err(format!("{path}: missing required property '{req}'"));
            }
        }
    }

    // Closed contract: reject unknown properties when additionalProperties=false.
    let additional = schema.get("additionalProperties");
    let closed = additional == Some(&Value::Bool(false));
    if closed {
        if let Some(props) = properties {
            for key in obj.keys() {
                if !props.contains_key(key) {
                    return Err(format!("{path}: unknown property '{key}' (additionalProperties is false)"));
                }
            }
        }
    }

    if let Some(props) = properties {
        for (key, subschema) in props {
            if let Some(child) = obj.get(key) {
                validate_at(subschema, child, &format!("{path}.{key}"), depth + 1)?;
            }
        }
    }
    Ok(())
}

fn validate_array(
    schema: &serde_json::Map<String, Value>,
    arr: &[Value],
    path: &str,
    depth: usize,
) -> Result<(), String> {
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
        if arr.len() as u64 > max {
            return Err(format!("{path}: array exceeds maxItems {max}"));
        }
    }
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        if (arr.len() as u64) < min {
            return Err(format!("{path}: array below minItems {min}"));
        }
    }
    if let Some(items) = schema.get("items") {
        for (i, item) in arr.iter().enumerate() {
            validate_at(items, item, &format!("{path}[{i}]"), depth + 1)?;
        }
    }
    Ok(())
}

fn validate_string(
    schema: &serde_json::Map<String, Value>,
    s: &str,
    path: &str,
) -> Result<(), String> {
    let len = s.chars().count() as u64;
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
        if len > max {
            return Err(format!("{path}: string exceeds maxLength {max}"));
        }
    }
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
        if len < min {
            return Err(format!("{path}: string below minLength {min}"));
        }
    }
    Ok(())
}

fn validate_number(
    schema: &serde_json::Map<String, Value>,
    n: &serde_json::Number,
    path: &str,
) -> Result<(), String> {
    let v = n.as_f64().unwrap_or(f64::NAN);
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
        if v < min {
            return Err(format!("{path}: value below minimum {min}"));
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
        if v > max {
            return Err(format!("{path}: value above maximum {max}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_schema_accepts_anything() {
        assert!(validate(&json!({}), &json!({ "x": 1 })).is_ok());
        assert!(validate(&json!(true), &json!("whatever")).is_ok());
    }

    #[test]
    fn type_mismatch_rejected() {
        assert!(validate(&json!({ "type": "object" }), &json!("nope")).is_err());
        assert!(validate(&json!({ "type": "string" }), &json!(5)).is_err());
        assert!(validate(&json!({ "type": "integer" }), &json!(3)).is_ok());
        assert!(validate(&json!({ "type": "integer" }), &json!(3.5)).is_err());
    }

    #[test]
    fn required_properties_enforced() {
        let schema = json!({ "type": "object", "properties": { "message": { "type": "string" } }, "required": ["message"] });
        assert!(validate(&schema, &json!({ "message": "hi" })).is_ok());
        let err = validate(&schema, &json!({})).unwrap_err();
        assert!(err.contains("missing required property 'message'"), "{err}");
    }

    #[test]
    fn wrong_property_type_rejected() {
        let schema = json!({ "type": "object", "properties": { "message": { "type": "string" } }, "required": ["message"] });
        assert!(validate(&schema, &json!({ "message": 123 })).is_err());
    }

    #[test]
    fn closed_object_rejects_unknown_keys() {
        let schema = json!({ "type": "object", "properties": { "a": {} }, "additionalProperties": false });
        assert!(validate(&schema, &json!({ "a": 1 })).is_ok());
        let err = validate(&schema, &json!({ "a": 1, "b": 2 })).unwrap_err();
        assert!(err.contains("unknown property 'b'"), "{err}");
    }

    #[test]
    fn string_and_number_bounds() {
        assert!(validate(&json!({ "type": "string", "maxLength": 3 }), &json!("abcd")).is_err());
        assert!(validate(&json!({ "type": "number", "maximum": 10 }), &json!(11)).is_err());
        assert!(validate(&json!({ "type": "number", "minimum": 0 }), &json!(-1)).is_err());
    }

    #[test]
    fn enum_enforced() {
        let schema = json!({ "enum": ["a", "b"] });
        assert!(validate(&schema, &json!("a")).is_ok());
        assert!(validate(&schema, &json!("c")).is_err());
    }

    #[test]
    fn array_items_and_bounds() {
        let schema = json!({ "type": "array", "items": { "type": "integer" }, "maxItems": 2 });
        assert!(validate(&schema, &json!([1, 2])).is_ok());
        assert!(validate(&schema, &json!([1, 2, 3])).is_err());
        assert!(validate(&schema, &json!([1, "x"])).is_err());
    }

    #[test]
    fn unsupported_keywords_are_detected() {
        // pattern is not enforced -> flagged.
        assert_eq!(
            unsupported_keywords(&json!({ "type": "string", "pattern": "^[0-9]+$" })),
            vec!["pattern".to_string()]
        );
        // combinators and schema-valued additionalProperties flagged.
        let bad = unsupported_keywords(&json!({
            "type": "object",
            "properties": { "x": { "oneOf": [ { "type": "string" } ] } },
            "additionalProperties": { "type": "string" }
        }));
        assert!(bad.contains(&"additionalProperties (schema-valued)".to_string()));
        assert!(bad.contains(&"oneOf".to_string()));
    }

    #[test]
    fn supported_subset_and_annotations_are_clean() {
        let schema = json!({
            "type": "object",
            "title": "Echo args",
            "description": "…",
            "properties": { "message": { "type": "string", "maxLength": 100 } },
            "required": ["message"],
            "additionalProperties": false
        });
        assert!(unsupported_keywords(&schema).is_empty());
    }

    #[test]
    fn deeply_nested_is_bounded() {
        // Build an instance deeper than MAX_DEPTH against a recursive-ish schema.
        let mut inst = json!(0);
        for _ in 0..40 {
            inst = json!({ "child": inst });
        }
        let schema = json!({ "type": "object" });
        // Top-level is an object; nested validation only recurses where the
        // schema has matching `properties`, so this specific schema won't
        // recurse — assert the guard triggers when properties chain deeply.
        let mut deep_schema = json!({ "type": "integer" });
        for _ in 0..40 {
            deep_schema = json!({ "type": "object", "properties": { "child": deep_schema } });
        }
        let err = validate(&deep_schema, &inst).unwrap_err();
        assert!(err.contains("max depth"), "{err}");
        // The shallow schema still accepts the object without deep recursion.
        assert!(validate(&schema, &inst).is_ok());
    }
}
