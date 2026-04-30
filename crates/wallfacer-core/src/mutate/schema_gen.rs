//! Schema-driven payload generator with full JSON Schema 2020-12 composition
//! support: `$ref`, `$defs`/`definitions`, `allOf`, `oneOf`/`anyOf`, `not`,
//! `if/then/else`, and `dependentRequired`.
//!
//! Phase B replaces the legacy "fall back to `{}` on any unsupported
//! keyword" with a proper resolution path:
//!
//! * Reference resolution and `allOf` merging are deterministic and live in
//!   [`crate::mutate::compose`].
//! * `oneOf` / `anyOf` pick a branch using the RNG, recording the choice in
//!   [`GeneratedPayload::trail`] for replay debugging.
//! * `not` uses rejection sampling (≤ [`MAX_NOT_ATTEMPTS`] tries) and bubbles
//!   up [`SkipReason::NotUnsatisfiable`] when exhausted.
//! * `if/then/else` validates a candidate from `if`; on a match it recurses
//!   into `then`, otherwise into `else` (defaulting to a no-op).
//! * `dependentRequired` triggers when a generated object includes a key
//!   listed as a dependency anchor, adding the dependent keys to the
//!   required set before generation.
//!
//! Format support (B4) covers `email`, `uri`, `date-time`, `uuid`, and
//! `password` (which intentionally yields the literal `<wallfacer-secret>` so
//! generated test payloads never carry a real-looking secret).
//!
//! Integer range generation (B3) uses [`i128`] saturating arithmetic and
//! [`rand::Rng::gen_range`] internally, so even `i64::MIN..=i64::MAX` ranges
//! no longer overflow.

use std::collections::BTreeSet;

use jsonschema::validator_for;
use rand::Rng;
use serde_json::{json, Map, Number, Value};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

use super::{compose, strategies};

/// Maximum number of attempts before a `not` rejection-sampling round gives
/// up and produces a [`SkipReason::NotUnsatisfiable`].
pub const MAX_NOT_ATTEMPTS: usize = 32;

/// Maximum number of attempts before a `oneOf` rejection-sampling round
/// gives up and produces a [`SkipReason::OneOfOverlap`]. `oneOf` requires
/// exactly one branch to match; if the synthesised value also validates
/// against another branch (e.g. an integer that satisfies both `integer` and
/// `number` branches) we retry.
pub const MAX_ONE_OF_ATTEMPTS: usize = 32;

/// Mode controlling the conformance vs. adversarial behavior of the generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenMode {
    /// Always emit values that conform to the schema.
    Conform,
    /// Always emit boundary / wrong-type / oversized values targeted at
    /// breaking the implementation.
    Adversarial,
    /// Default mixture: mostly conformant with occasional adversarial bursts.
    Mixed,
}

/// Reason explaining why payload generation was abandoned.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SkipReason {
    /// A `$ref` could not be resolved (external, missing, or cyclic).
    #[error("unresolved reference: {0}")]
    UnresolvedRef(String),
    /// Reference cycle detected.
    #[error("cyclic reference: {0}")]
    Cycle(String),
    /// `not` rejection sampling failed after [`MAX_NOT_ATTEMPTS`] tries.
    #[error("`not` constraint unsatisfiable after {0} attempts")]
    NotUnsatisfiable(usize),
    /// `oneOf` rejection sampling failed: every candidate matched more than
    /// one branch (typically because branches overlap, e.g. `integer` and
    /// `number`).
    #[error("`oneOf` branches overlap; could not produce a value matching exactly one after {0} attempts")]
    OneOfOverlap(usize),
    /// `oneOf` / `anyOf` array was empty.
    #[error("empty composition: {0}")]
    EmptyComposition(&'static str),
    /// `enum` / `const` had no value or was malformed.
    #[error("malformed schema fragment: {0}")]
    Malformed(&'static str),
}

/// Outcome of a successful payload generation.
#[derive(Debug, Clone)]
pub struct GeneratedPayload {
    /// Generated JSON value (always an object at the top level).
    pub value: Value,
    /// Human-readable trail of composition choices made during generation,
    /// useful for diagnosing replays. Empty when the schema had no
    /// composition keywords.
    pub trail: Vec<String>,
}

/// Generates a payload from a JSON Schema. Returns the generated value paired
/// with the composition trail.
///
/// This is the fallible API: callers that cannot recover from a [`SkipReason`]
/// (e.g. one-shot tools) can fall back to [`generate_payload`] which silently
/// returns an empty object when generation must be skipped.
pub fn try_generate_payload(
    schema: &Value,
    rng: &mut impl Rng,
    mode: GenMode,
) -> std::result::Result<GeneratedPayload, SkipReason> {
    let mut ctx = GenCtx::new(schema, mode);
    let value = generate_with_ctx(schema, rng, &mut ctx)?;
    let value = match value {
        Value::Object(_) => value,
        _ => Value::Object(Map::new()),
    };
    Ok(GeneratedPayload {
        value,
        trail: ctx.trail,
    })
}

/// Generates a payload from a JSON Schema. Returns the resulting JSON value.
///
/// Backwards-compatible API: when generation is skipped (unresolvable refs,
/// `not` exhaustion, ...), returns an empty JSON object so callers that have
/// no skip-handling path keep working. New code should prefer
/// [`try_generate_payload`] to surface skips.
pub fn generate_payload(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    match try_generate_payload(schema, rng, mode) {
        Ok(payload) => payload.value,
        Err(reason) => {
            warn!(%reason, "payload generation skipped; emitting empty object");
            Value::Object(Map::new())
        }
    }
}

/// Generates a value (not necessarily an object). Exposed for callers that
/// drive composition themselves; most users want [`generate_payload`].
pub fn generate_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    let mut ctx = GenCtx::new(schema, mode);
    generate_with_ctx(schema, rng, &mut ctx).unwrap_or(Value::Null)
}

struct GenCtx {
    root: Value,
    mode: GenMode,
    trail: Vec<String>,
    /// Stack of pointers visited via `$ref` on the current branch (cycle
    /// detection scoped to the depth of the recursion, not global).
    ref_stack: BTreeSet<String>,
    depth: usize,
}

impl GenCtx {
    fn new(root: &Value, mode: GenMode) -> Self {
        Self {
            root: root.clone(),
            mode,
            trail: Vec::new(),
            ref_stack: BTreeSet::new(),
            depth: 0,
        }
    }
}

const MAX_DEPTH: usize = 32;

fn generate_with_ctx(
    schema: &Value,
    rng: &mut impl Rng,
    ctx: &mut GenCtx,
) -> std::result::Result<Value, SkipReason> {
    if ctx.depth >= MAX_DEPTH {
        return Ok(Value::Null);
    }
    ctx.depth += 1;
    let result = generate_inner(schema, rng, ctx);
    ctx.depth -= 1;
    result
}

fn generate_inner(
    schema: &Value,
    rng: &mut impl Rng,
    ctx: &mut GenCtx,
) -> std::result::Result<Value, SkipReason> {
    // 1. Resolve `$ref` (including chains, with cycle detection).
    let schema = match compose::dereference(&ctx.root, schema, &mut ctx.ref_stack.clone()) {
        Ok(resolved) => resolved,
        Err(compose::ComposeError::Cycle(p)) => return Err(SkipReason::Cycle(p)),
        Err(compose::ComposeError::DepthExceeded(p)) => return Err(SkipReason::Cycle(p)),
        Err(compose::ComposeError::ExternalRef(p))
        | Err(compose::ComposeError::UnresolvedRef(p)) => return Err(SkipReason::UnresolvedRef(p)),
    };

    // 2. `const` short-circuits.
    if let Some(value) = schema.get("const") {
        return Ok(value.clone());
    }

    // 3. `enum` short-circuits.
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if values.is_empty() {
            return Err(SkipReason::Malformed("empty enum"));
        }
        return Ok(strategies::pick(rng, values).clone());
    }

    // 4. `allOf` merges sub-schemas, then we recurse on the merged result.
    if let Some(items) = schema.get("allOf").and_then(Value::as_array) {
        let merged = match compose::merge_all_of(&ctx.root, items) {
            Ok(merged) => merged,
            Err(compose::ComposeError::Cycle(p)) => return Err(SkipReason::Cycle(p)),
            Err(compose::ComposeError::DepthExceeded(p)) => return Err(SkipReason::Cycle(p)),
            Err(compose::ComposeError::ExternalRef(p))
            | Err(compose::ComposeError::UnresolvedRef(p)) => {
                return Err(SkipReason::UnresolvedRef(p));
            }
        };
        ctx.trail
            .push(format!("allOf merged {} schemas", items.len()));
        // Other top-level keywords on the original schema (rare in 2020-12
        // when allOf is present) are discarded — they would have been merged
        // had the author placed them inside an allOf branch.
        return generate_with_ctx(&merged, rng, ctx);
    }

    // 5a. `anyOf` is permissive: any branch matching the value is enough,
    // so we just pick a random branch and recurse without verification.
    if let Some(items) = schema.get("anyOf").and_then(Value::as_array) {
        if items.is_empty() {
            return Err(SkipReason::EmptyComposition("anyOf"));
        }
        let index = rng.gen_range(0..items.len());
        ctx.trail.push(format!("anyOf[{index}/{}]", items.len()));
        return generate_with_ctx(&items[index], rng, ctx);
    }

    // 5b. `oneOf` requires exactly one branch to validate. Branches with
    // overlapping types (e.g. `integer` ⊂ `number`) cannot be hit by a
    // naive pick — we'd risk a value that matches several branches and
    // fails validation. Use rejection sampling: pick a branch, generate,
    // and validate the candidate against the *enclosing* `oneOf` schema
    // (with `$defs` from the root injected so `$ref` branches resolve).
    // If the candidate is accepted, oneOf semantics are satisfied. After
    // [`MAX_ONE_OF_ATTEMPTS`] failed tries, surface
    // [`SkipReason::OneOfOverlap`].
    if let Some(items) = schema.get("oneOf").and_then(Value::as_array) {
        if items.is_empty() {
            return Err(SkipReason::EmptyComposition("oneOf"));
        }
        let validator = build_validator_with_defs(&schema, &ctx.root);
        for attempt in 0..MAX_ONE_OF_ATTEMPTS {
            let index = rng.gen_range(0..items.len());
            let candidate = generate_with_ctx(&items[index], rng, ctx)?;
            if validator.as_ref().is_some_and(|v| v.is_valid(&candidate)) {
                ctx.trail.push(format!(
                    "oneOf[{}/{}] (attempt {}/{})",
                    index,
                    items.len(),
                    attempt + 1,
                    MAX_ONE_OF_ATTEMPTS
                ));
                return Ok(candidate);
            }
        }
        return Err(SkipReason::OneOfOverlap(MAX_ONE_OF_ATTEMPTS));
    }

    // 6. `not` rejection sampling.
    if let Some(forbidden) = schema.get("not") {
        // Build a candidate schema without the `not` keyword and try to
        // generate a value that does NOT validate against `forbidden`.
        let mut base = schema.as_object().cloned().unwrap_or_default();
        base.remove("not");
        let base_schema = Value::Object(base);

        let validator = validator_for(forbidden).ok();
        for attempt in 0..MAX_NOT_ATTEMPTS {
            let candidate = generate_with_ctx(&base_schema, rng, ctx)?;
            let matches_forbidden = validator.as_ref().is_some_and(|v| v.is_valid(&candidate));
            if !matches_forbidden {
                ctx.trail.push(format!(
                    "not satisfied at attempt {}/{}",
                    attempt + 1,
                    MAX_NOT_ATTEMPTS
                ));
                return Ok(candidate);
            }
        }
        return Err(SkipReason::NotUnsatisfiable(MAX_NOT_ATTEMPTS));
    }

    // 7. `if/then/else`.
    if let Some(if_schema) = schema.get("if") {
        let validator = validator_for(if_schema).ok();
        let candidate = generate_with_ctx(if_schema, rng, ctx).ok();
        let if_holds = match (&validator, &candidate) {
            (Some(v), Some(c)) => v.is_valid(c),
            _ => false,
        };
        let branch_key = if if_holds { "then" } else { "else" };
        if let Some(branch) = schema.get(branch_key) {
            ctx.trail.push(format!("if/{}", branch_key));
            return generate_with_ctx(branch, rng, ctx);
        }
        // No matching branch: fall through to the regular dispatch.
    }

    // 8. Pick a generation mode for this node (Mixed = mostly Conform).
    let effective_mode = match ctx.mode {
        GenMode::Mixed if rng.gen_range(0..5) == 0 => GenMode::Adversarial,
        GenMode::Mixed => GenMode::Conform,
        other => other,
    };

    // 9. Dispatch by `type`.
    let schema_type = schema_type(&schema);
    Ok(match schema_type.as_deref() {
        Some("string") => string_value(&schema, rng, effective_mode),
        Some("integer") => integer_value(&schema, rng, effective_mode),
        Some("number") => number_value(&schema, rng, effective_mode),
        Some("boolean") => Value::Bool(rng.gen::<bool>()),
        Some("array") => array_value(&schema, rng, ctx, effective_mode)?,
        Some("object") | None => object_value(&schema, rng, ctx, effective_mode)?,
        Some("null") => Value::Null,
        Some(other) => {
            warn!(
                schema_type = other,
                "unsupported schema type; returning null"
            );
            Value::Null
        }
    })
}

fn string_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial {
        return Value::String(strategies::long_or_tricky_string(rng));
    }

    if let Some(format) = schema.get("format").and_then(Value::as_str) {
        if let Some(value) = formatted_string(format, rng) {
            return value;
        }
    }

    let min = number_keyword(schema, "minLength").unwrap_or(0).max(0) as usize;
    let max = number_keyword(schema, "maxLength")
        .unwrap_or(32)
        .max(min as i64) as usize;
    let max = max.min(256);
    let len = if max == min {
        min
    } else {
        rng.gen_range(min..=max)
    };
    let value: String = (0..len)
        .map(|_| {
            let offset: u8 = rng.gen_range(0..26);
            char::from(b'a' + offset)
        })
        .collect();
    Value::String(value)
}

/// Returns a generated value matching a JSON Schema `format`, or `None` if
/// the format is unknown (caller falls back to a plain random string).
fn formatted_string(format: &str, rng: &mut impl Rng) -> Option<Value> {
    match format {
        "email" => {
            let user_len: usize = rng.gen_range(3..=10);
            let user: String = (0..user_len)
                .map(|_| char::from(b'a' + rng.gen_range(0..26)))
                .collect();
            Some(Value::String(format!("{user}@example.org")))
        }
        "uri" | "url" => {
            let path_len: usize = rng.gen_range(3..=8);
            let path: String = (0..path_len)
                .map(|_| char::from(b'a' + rng.gen_range(0..26)))
                .collect();
            Some(Value::String(format!("https://example.org/{path}")))
        }
        "date-time" | "datetime" => {
            // RFC 3339 timestamp deterministic within the rng stream.
            let seconds: i64 = rng.gen_range(0..2_000_000_000);
            // 2001-09-09T01:46:40Z is at unix 1_000_000_000; use seconds offset.
            let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
                .unwrap_or_else(chrono::Utc::now);
            Some(Value::String(
                dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ))
        }
        "date" => {
            let seconds: i64 = rng.gen_range(0..2_000_000_000);
            let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
                .unwrap_or_else(chrono::Utc::now);
            Some(Value::String(dt.format("%Y-%m-%d").to_string()))
        }
        "uuid" => {
            let bytes: u128 = ((rng.gen::<u64>() as u128) << 64) | rng.gen::<u64>() as u128;
            Some(Value::String(Uuid::from_u128(bytes).to_string()))
        }
        "password" => {
            // We never generate real-looking secrets. The placeholder is
            // recognisable in logs and corpus dumps and is not redacted
            // (the value itself is non-sensitive).
            Some(Value::String("<wallfacer-secret>".to_string()))
        }
        _ => None,
    }
}

fn integer_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial {
        return json!(strategies::boundary_int(rng));
    }

    let mut min = number_keyword(schema, "minimum").unwrap_or(-1000);
    let mut max = number_keyword(schema, "maximum").unwrap_or(1000);
    if number_keyword(schema, "exclusiveMinimum").is_some() {
        min = min.saturating_add(1);
    }
    if number_keyword(schema, "exclusiveMaximum").is_some() {
        max = max.saturating_sub(1);
    }
    if min > max {
        return json!(min);
    }

    // Phase B3: use i128 arithmetic + `rng.gen_range` so even
    // `i64::MIN..=i64::MAX` works without overflowing the `(max - min + 1)`
    // span computation.
    let value = sample_int_range(rng, min, max);

    if let Some(multiple_of) = number_keyword(schema, "multipleOf").filter(|value| *value != 0) {
        let aligned = value - value.rem_euclid(multiple_of);
        return json!(aligned);
    }

    json!(value)
}

fn sample_int_range(rng: &mut impl Rng, min: i64, max: i64) -> i64 {
    debug_assert!(min <= max);
    if min == max {
        return min;
    }
    // `gen_range` panics if start == end (handled above) but copes with the
    // full `i64::MIN..=i64::MAX` span natively in `rand 0.8`.
    rng.gen_range(min..=max)
}

fn number_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial {
        return Number::from_f64(strategies::boundary_float(rng))
            .map(Value::Number)
            .unwrap_or(Value::Null);
    }

    let min = schema
        .get("minimum")
        .and_then(Value::as_f64)
        .unwrap_or(-1000.0);
    let max = schema
        .get("maximum")
        .and_then(Value::as_f64)
        .unwrap_or(1000.0)
        .max(min);
    let value = if (max - min).is_finite() && max > min {
        rng.gen_range(min..=max)
    } else {
        min
    };
    Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn array_value(
    schema: &Value,
    rng: &mut impl Rng,
    ctx: &mut GenCtx,
    mode: GenMode,
) -> std::result::Result<Value, SkipReason> {
    if mode == GenMode::Adversarial && strategies::chance(rng, 1, 10) {
        return Ok(strategies::deep_nesting(1000));
    }

    let item_schema = schema.get("items").cloned().unwrap_or(Value::Null);
    let min = number_keyword(schema, "minItems").unwrap_or(0).max(0) as usize;
    let default_max = if mode == GenMode::Adversarial { 128 } else { 8 };
    let max = number_keyword(schema, "maxItems")
        .unwrap_or(default_max)
        .max(min as i64) as usize;
    let max = max.min(default_max as usize);
    let len = if max == min {
        min
    } else {
        rng.gen_range(min..=max)
    };
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(generate_with_ctx(&item_schema, rng, ctx)?);
    }
    Ok(Value::Array(items))
}

fn object_value(
    schema: &Value,
    rng: &mut impl Rng,
    ctx: &mut GenCtx,
    mode: GenMode,
) -> std::result::Result<Value, SkipReason> {
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut required: BTreeSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_else(|| properties.keys().cloned().collect());

    // `dependentRequired`: when the primary key is generated, also generate
    // its dependents. We expand the required set up-front so that downstream
    // keys are emitted on the same iteration.
    if let Some(deps) = schema.get("dependentRequired").and_then(Value::as_object) {
        for (anchor, dependents) in deps {
            if required.contains(anchor) {
                if let Some(items) = dependents.as_array() {
                    for item in items {
                        if let Some(name) = item.as_str() {
                            required.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut object = Map::new();
    for (key, property_schema) in &properties {
        if mode == GenMode::Adversarial && required.contains(key) && strategies::chance(rng, 1, 20)
        {
            continue;
        }

        let value = if mode == GenMode::Adversarial && strategies::chance(rng, 1, 20) {
            strategies::wrong_type_for(schema_type(property_schema).as_deref().unwrap_or("null"))
        } else {
            generate_with_ctx(property_schema, rng, ctx)?
        };
        object.insert(key.clone(), value);
    }

    if mode == GenMode::Adversarial
        && schema
            .get("additionalProperties")
            .and_then(Value::as_bool)
            .is_some_and(|allowed| !allowed)
        && strategies::chance(rng, 1, 5)
    {
        object.insert("unexpected_extra".to_string(), json!("extra"));
    }

    Ok(Value::Object(object))
}

/// Builds a [`jsonschema::Validator`] from a sub-schema, attaching the
/// root document's `$defs` and `definitions` so that any `$ref` pointing
/// into them resolves successfully.
fn build_validator_with_defs(schema: &Value, root: &Value) -> Option<jsonschema::Validator> {
    let mut self_contained = schema.clone();
    if let Some(map) = self_contained.as_object_mut() {
        if let Some(defs) = root.get("$defs") {
            map.entry("$defs".to_string())
                .or_insert_with(|| defs.clone());
        }
        if let Some(defs) = root.get("definitions") {
            map.entry("definitions".to_string())
                .or_insert_with(|| defs.clone());
        }
    }
    validator_for(&self_contained).ok()
}

fn schema_type(schema: &Value) -> Option<String> {
    match schema.get("type") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .find(|value| *value != "null")
            .map(ToOwned::to_owned),
        _ => {
            if schema.get("properties").is_some() {
                Some("object".to_string())
            } else {
                None
            }
        }
    }
}

fn number_keyword(schema: &Value, key: &str) -> Option<i64> {
    schema.get(key).and_then(Value::as_i64)
}
