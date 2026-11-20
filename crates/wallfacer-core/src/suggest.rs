//! Phase P — pack-suggestion engine.
//!
//! Given a live list of MCP tools, infer which embedded rule packs
//! likely apply and pre-fill their template parameters from the
//! observable tool catalog. Bootstraps `wallfacer init` style
//! onboarding so a new user doesn't have to read the whole pack
//! library to know which packs to enable.
//!
//! Rules are deliberately conservative — *suggestion* not
//! *autoconfiguration*. The output is meant to be reviewed by a
//! human and pasted into `wallfacer.toml`. False positives waste
//! review time but don't break a run; false negatives leave a class
//! of bugs un-tested. When in doubt, suggest.
//!
//! Heuristics are name- + schema- + annotation-driven. For each
//! shipped pack we encode one or more "this tool looks like the
//! pack's witness" patterns and emit a [`PackSuggestion`] with a
//! human-readable reason and the parameter overrides the pack needs
//! to actually run against this server.

use std::collections::{BTreeMap, BTreeSet};

use rmcp::model::Tool;
use serde::Serialize;
use serde_json::Value;

/// One pack the engine recommends for the target server.
#[derive(Debug, Clone, Serialize)]
pub struct PackSuggestion {
    /// Embedded pack name (e.g. `path-traversal`). Always one of
    /// [`crate::run::EMBEDDED_PACKS`].
    pub pack: String,
    /// Tool name that triggered this suggestion (when the pack is
    /// tool-specific). `None` for packs that apply globally
    /// (annotation-driven, envelope-shape, etc.).
    pub witness_tool: Option<String>,
    /// `wallfacer.toml` parameter overrides recommended for this
    /// pack. Empty when the pack's defaults already work.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub param_overrides: BTreeMap<String, String>,
    /// One-sentence reason surfaced to the operator. Should reference
    /// the observable signal that triggered the suggestion (tool
    /// name, schema field, annotation).
    pub reason: String,
}

/// Walks `tools` and emits one [`PackSuggestion`] per (pack, witness)
/// pair that matches a heuristic. Suggestions are deduplicated on
/// `(pack, witness_tool)` — the same pack against two different
/// tools produces two suggestions; the same pack with `None` witness
/// is collapsed.
pub fn suggest_packs(tools: &[Tool]) -> Vec<PackSuggestion> {
    let mut out: Vec<PackSuggestion> = Vec::new();
    let mut seen: BTreeSet<(String, Option<String>)> = BTreeSet::new();

    let mut emit = |s: PackSuggestion, out: &mut Vec<PackSuggestion>| {
        let key = (s.pack.clone(), s.witness_tool.clone());
        if seen.insert(key) {
            out.push(s);
        }
    };

    // ---- Always-applicable packs -----------------------------------
    //
    // `secrets-leakage`, `unicode` and `large-payload` probe a server
    // through one string-taking witness tool. The probes are hostile
    // inputs, so the witness is never a tool that changes state
    // (`create_scene`, `write_file`): the probe would create or overwrite
    // things. Tools whose job is to reflect their input (`echo`) come
    // last: they are valid witnesses (none of these packs flags
    // reflection) but exercise less of the server.
    if let Some(witness) = pick_witness(tools) {
        for (pack, params) in [
            ("secrets-leakage", &["witness_tool", "witness_field"][..]),
            ("unicode", &["witness_tool", "witness_field"][..]),
            (
                "large-payload",
                &["string_witness_tool", "string_witness_field"][..],
            ),
        ] {
            let mut param_overrides = BTreeMap::from([
                (params[0].to_string(), witness.tool.clone()),
                (params[1].to_string(), witness.field.clone()),
            ]);
            if pack == "large-payload" {
                if let Some(array) = tools
                    .iter()
                    .filter(|tool| !is_mutating(tool))
                    .find_map(integer_array_field)
                {
                    param_overrides.insert("array_witness_tool".to_string(), array.tool);
                    param_overrides.insert("array_witness_field".to_string(), array.field);
                }
            }
            emit(
                PackSuggestion {
                    pack: pack.to_string(),
                    witness_tool: Some(witness.tool.clone()),
                    param_overrides,
                    reason: format!(
                        "tool `{}` accepts a string field `{}` — usable as the {pack} witness",
                        witness.tool, witness.field
                    ),
                },
                &mut out,
            );
        }
    }

    // `error-shape` and `tool-annotations` apply globally with no
    // tool-specific parameter, so we always emit one suggestion.
    emit(
        PackSuggestion {
            pack: "error-shape".to_string(),
            witness_tool: None,
            param_overrides: BTreeMap::new(),
            reason: "every MCP server should produce well-formed error envelopes".to_string(),
        },
        &mut out,
    );
    if tools.iter().any(|t| t.annotations.is_some()) {
        emit(
            PackSuggestion {
                pack: "tool-annotations".to_string(),
                witness_tool: None,
                param_overrides: BTreeMap::new(),
                reason: "server declares MCP tool annotations \
                         (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`)"
                    .to_string(),
            },
            &mut out,
        );
    }

    // ---- Tool-specific heuristics ----------------------------------
    for tool in tools {
        let name = tool.name.as_ref();
        let description_lower = tool.description.as_deref().unwrap_or("").to_lowercase();

        // No `auth` suggestion: its checks encode an application contract
        // (an unauthenticated `whoami` answers `isError` or
        // `anonymous: true`) and assume the server runs without
        // credentials. Neither holds for an arbitrary server — a
        // configured one legitimately returns its user, an unconfigured
        // one says "not logged in" in plain text — so the pack is opt-in.

        // Path traversal — schema has `path` / `file_path` / `filepath`
        // field. Only non-mutating tools become the read witness: the
        // pack sends traversal paths, and pointing it at
        // `create_directory` would create directories outside the root.
        // `write_file_tool` keeps its default; the runner skips it when
        // the server does not advertise that tool.
        let mutating = is_mutating(tool);
        let path_field = first_matching_field(
            &tool.input_schema,
            &["path", "file_path", "filepath", "filename"],
        );
        if let (Some(field), false) = (path_field, mutating) {
            emit(
                PackSuggestion {
                    pack: "path-traversal".to_string(),
                    witness_tool: Some(name.to_string()),
                    param_overrides: BTreeMap::from([
                        ("read_file_tool".to_string(), name.to_string()),
                        ("path_field".to_string(), field),
                    ]),
                    reason: format!("tool `{name}` accepts a path-shaped argument"),
                },
                &mut out,
            );
        }

        // SQL injection — schema has `query` / `sql` field
        if let Some(field) =
            first_matching_field(&tool.input_schema, &["query", "sql", "stmt", "statement"])
        {
            emit(
                PackSuggestion {
                    pack: "injection-sql".to_string(),
                    witness_tool: Some(name.to_string()),
                    param_overrides: BTreeMap::from([
                        ("query_tool".to_string(), name.to_string()),
                        ("query_field".to_string(), field),
                    ]),
                    reason: format!("tool `{name}` accepts a SQL-shaped argument"),
                },
                &mut out,
            );
        }

        // Shell injection — name like run_*/exec_* OR schema has command/cmd/shell field
        let shell_field =
            first_matching_field(&tool.input_schema, &["command", "cmd", "shell", "exec"]);
        if shell_field.is_some()
            || matches_any_token(name, &["run_shell", "exec", "shell", "subprocess"])
        {
            let field = shell_field.unwrap_or_else(|| "command".to_string());
            emit(
                PackSuggestion {
                    pack: "injection-shell".to_string(),
                    witness_tool: Some(name.to_string()),
                    param_overrides: BTreeMap::from([
                        ("shell_tool".to_string(), name.to_string()),
                        ("shell_field".to_string(), field),
                    ]),
                    reason: format!("tool `{name}` accepts a shell-shaped argument"),
                },
                &mut out,
            );
        }

        // Prompt injection — schema has prompt/llm/chat/message field, or
        // description mentions LLM / completion.
        let prompt_field = first_matching_field(
            &tool.input_schema,
            &["prompt", "messages", "chat", "completion"],
        );
        let prompt_via_desc = description_lower.contains("llm")
            || description_lower.contains("completion")
            || description_lower.contains("language model");
        if prompt_field.is_some() || (prompt_via_desc && string_field(tool).is_some()) {
            let field = prompt_field
                .or_else(|| string_field(tool).map(|w| w.field))
                .unwrap_or_else(|| "prompt".to_string());
            emit(
                PackSuggestion {
                    pack: "prompt-injection".to_string(),
                    witness_tool: Some(name.to_string()),
                    param_overrides: BTreeMap::from([
                        ("llm_tool".to_string(), name.to_string()),
                        ("prompt_field".to_string(), field),
                    ]),
                    reason: format!("tool `{name}` looks like an LLM-prompt forwarder"),
                },
                &mut out,
            );
        }
    }

    // ---- Stateful pack — needs a create/read/delete triple ---------
    if let Some(triple) = infer_create_read_delete_triple(tools) {
        emit(
            PackSuggestion {
                pack: "stateful".to_string(),
                witness_tool: Some(triple.create.clone()),
                param_overrides: BTreeMap::from([
                    ("create_tool".to_string(), triple.create),
                    ("read_tool".to_string(), triple.read),
                    ("delete_tool".to_string(), triple.delete),
                ]),
                reason:
                    "found a create/read/delete tool triple — sequence pack can probe state-leak"
                        .to_string(),
            },
            &mut out,
        );
    }

    // ---- Auth-flow pack — needs a login/logout pair ----------------
    if let Some(pair) = infer_login_logout_pair(tools) {
        let mut overrides = BTreeMap::from([
            ("login_tool".to_string(), pair.login),
            ("logout_tool".to_string(), pair.logout),
        ]);
        if let Some(protected) = pair.protected {
            overrides.insert("protected_tool".to_string(), protected);
        }
        emit(
            PackSuggestion {
                pack: "auth-flow".to_string(),
                witness_tool: None,
                param_overrides: overrides,
                reason: "found a login/logout pair — sequence pack can probe token revocation"
                    .to_string(),
            },
            &mut out,
        );
    }

    out
}

/// Lightweight witness reference produced by [`pick_witness`].
struct StringWitness {
    tool: String,
    field: String,
}

/// First string-typed property of the tool's `inputSchema`, if any.
fn string_field(tool: &Tool) -> Option<StringWitness> {
    let schema_value = serde_json::to_value(tool.input_schema.as_ref()).ok()?;
    let props = schema_value.get("properties")?.as_object()?;
    props
        .iter()
        .find(|(_, val)| val.get("type").and_then(Value::as_str) == Some("string"))
        .map(|(key, _)| StringWitness {
            tool: tool.name.to_string(),
            field: key.clone(),
        })
}

/// First property declared as an array of integers or numbers: the
/// `large-payload` array probe sends 10 000 small integers.
fn integer_array_field(tool: &Tool) -> Option<StringWitness> {
    let schema_value = serde_json::to_value(tool.input_schema.as_ref()).ok()?;
    let props = schema_value.get("properties")?.as_object()?;
    props
        .iter()
        .find(|(_, val)| {
            val.get("type").and_then(Value::as_str) == Some("array")
                && matches!(
                    val.pointer("/items/type").and_then(Value::as_str),
                    Some("integer" | "number")
                )
        })
        .map(|(key, _)| StringWitness {
            tool: tool.name.to_string(),
            field: key.clone(),
        })
}

/// Witness for the always-applicable packs: the first non-mutating tool
/// with a string field, reflectors (`echo`) only when nothing else
/// qualifies.
fn pick_witness(tools: &[Tool]) -> Option<StringWitness> {
    let candidates = || tools.iter().filter(|tool| !is_mutating(tool));
    candidates()
        .filter(|tool| !is_reflector(tool))
        .find_map(string_field)
        .or_else(|| candidates().find_map(string_field))
}

/// Name words of tools that create, change or delete state. Probes with
/// hostile input must not be sent to them.
/// Name words of tools that change state or trigger side effects. Such a
/// tool is never a witness: the packs send it hostile inputs.
const MUTATING_WORDS: &[&str] = &[
    "write", "save", "create", "put", "edit", "append", "move", "rename", "mkdir", "delete",
    "remove", "upload", "set", "update", "insert", "drop", "send", "post", "publish", "run",
    "exec", "execute", "start", "stop", "kill", "launch", "spawn", "trigger", "deploy", "install",
];

fn is_mutating(tool: &Tool) -> bool {
    matches_any_token(&tool.name, MUTATING_WORDS)
}

/// Returns the first property name in `schema` that matches any of
/// `candidates` (case-insensitive). Used to detect path / query /
/// command / prompt fields without depending on their exact spelling.
fn first_matching_field(schema: &rmcp::model::JsonObject, candidates: &[&str]) -> Option<String> {
    let value: Value = serde_json::to_value(schema).ok()?;
    let props = value.get("properties")?.as_object()?;
    for (key, _) in props {
        let lower = key.to_lowercase();
        if candidates
            .iter()
            .any(|c| lower == *c || lower == c.replace('_', ""))
        {
            return Some(key.clone());
        }
    }
    None
}

/// A tool whose documented purpose is to return its input (`echo`,
/// `ping`, `reverse`). Matched on whole name tokens so `echo_logs`
/// counts but `checkout` does not.
fn is_reflector(tool: &Tool) -> bool {
    matches_any_token(
        &tool.name,
        &["echo", "ping", "reverse", "repeat", "mirror", "parrot"],
    )
}

/// Returns `true` when `name` contains any of `phrases` as whole words
/// (`current_user` matches `getCurrentUser`, `me` does not match
/// `customerDataProvider`). Used for cheap name-based heuristics.
fn matches_any_token(name: &str, phrases: &[&str]) -> bool {
    let words = name_words(name);
    phrases.iter().any(|phrase| {
        let phrase: Vec<&str> = phrase.split('_').collect();
        words
            .windows(phrase.len())
            .any(|window| window.iter().zip(&phrase).all(|(w, p)| w == p))
    })
}

/// Lowercase words of a tool name, split on any non-alphanumeric
/// character and on camelCase boundaries: `getCurrentUser` and
/// `get-current_user` both give `[get, current, user]`. Matching on whole
/// words keeps `me` from matching `customerDataProvider` and `exec` from
/// matching `execute_insights_query` (both seen in the campaign).
fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        current.extend(c.to_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Triple of tool names that look like a create / read / delete trio
/// (e.g. `record_create` / `record_read` / `record_delete`). Used
/// by the `stateful` pack suggestion.
struct CrudTriple {
    create: String,
    read: String,
    delete: String,
}

/// Looks for a shared lowercase prefix where one variant is a
/// "create" tool, another a "read" / "get" / "fetch" tool, and a
/// third a "delete" / "remove" tool.
///
/// Conservative — requires all three to share the same first token
/// (e.g. `record_*`, `user_*`). Multi-prefix servers will produce
/// multiple suggestions naturally.
fn infer_create_read_delete_triple(tools: &[Tool]) -> Option<CrudTriple> {
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    for create in &lower {
        let prefix = match create.split_once('_').map(|(p, _)| p.to_string()) {
            Some(p) => p,
            None => continue,
        };
        if !create.contains("create") {
            continue;
        }
        let read = lower.iter().find(|n| {
            n.starts_with(&format!("{prefix}_"))
                && (n.contains("read") || n.contains("get") || n.contains("fetch"))
        })?;
        let delete = lower.iter().find(|n| {
            n.starts_with(&format!("{prefix}_"))
                && (n.contains("delete") || n.contains("remove") || n.contains("destroy"))
        })?;
        // Map back to the original-case tool name.
        let original = |needle: &String| -> Option<String> {
            names.iter().find(|n| &n.to_lowercase() == needle).cloned()
        };
        return Some(CrudTriple {
            create: original(create)?,
            read: original(read)?,
            delete: original(delete)?,
        });
    }
    None
}

/// Login / logout / optional-protected triple inferred from tool
/// names. Conservative — requires both login and logout to be
/// present.
struct AuthFlow {
    login: String,
    logout: String,
    protected: Option<String>,
}

fn infer_login_logout_pair(tools: &[Tool]) -> Option<AuthFlow> {
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let login_idx = lower
        .iter()
        .position(|n| n.contains("login") || n.contains("signin"))?;
    let logout_idx = lower
        .iter()
        .position(|n| n.contains("logout") || n.contains("signout"))?;
    let protected = lower.iter().position(|n| {
        n.contains("protected")
            || n.contains("private")
            || (n.contains("get_") && n.contains("profile"))
    });
    Some(AuthFlow {
        login: names[login_idx].clone(),
        logout: names[logout_idx].clone(),
        protected: protected.map(|i| names[i].clone()),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use rmcp::model::{Tool, ToolAnnotations};
    use serde_json::json;
    use std::sync::Arc;

    fn tool(name: &str, schema: Value, description: Option<&str>) -> Tool {
        let obj = match schema {
            Value::Object(o) => o,
            _ => serde_json::Map::new(),
        };
        // `Tool::new(name, description, input_schema)` since rmcp
        // 1.5. Both `Tool` and `ToolAnnotations` are
        // `#[non_exhaustive]` so we have to go through the
        // constructor.
        Tool::new(
            name.to_string(),
            description.map(|d| d.to_string()).unwrap_or_default(),
            Arc::new(obj),
        )
    }

    fn tool_with_annotations(name: &str, read_only: bool) -> Tool {
        let mut t = tool(name, json!({}), None);
        t.annotations = Some(ToolAnnotations::new().read_only(read_only));
        t
    }

    #[test]
    fn empty_tools_emits_only_global_suggestions() {
        let s = suggest_packs(&[]);
        // error-shape applies globally even with no tools.
        assert!(s.iter().any(|p| p.pack == "error-shape"));
        assert!(!s.iter().any(|p| p.pack == "secrets-leakage"));
    }

    /// Campaign regression: `auth` was auto-applied to `whoami`-like
    /// tools and failed on servers that answered "not logged in" in
    /// plain text, or that hold credentials and return their user.
    #[test]
    fn auth_pack_is_never_auto_suggested() {
        for name in ["whoami", "getCurrentUser", "get_me", "user_info"] {
            assert!(
                !suggest_packs(&[tool(name, json!({}), None)])
                    .iter()
                    .any(|p| p.pack == "auth"),
                "`{name}` must not trigger the auth pack"
            );
        }
    }

    /// Campaign regression: `workers_run` (a `path` field, no write verb)
    /// became the path-traversal read witness and was sent UNC paths.
    #[test]
    fn side_effecting_tools_are_never_witnesses() {
        let path = json!({"type": "object", "properties": {"path": {"type": "string"}}});
        for name in [
            "workers_run",
            "execute_script",
            "start_server",
            "kill_process",
        ] {
            let s = suggest_packs(&[tool(name, path.clone(), None)]);
            assert!(
                s.iter().all(|p| p.witness_tool.as_deref() != Some(name)),
                "`{name}` must not be a witness: {s:?}"
            );
        }
    }

    #[test]
    fn path_field_triggers_path_traversal_pack() {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        });
        let tools = vec![tool("read_file", schema, None)];
        let s = suggest_packs(&tools);
        let pt = s.iter().find(|p| p.pack == "path-traversal").unwrap();
        assert_eq!(pt.witness_tool.as_deref(), Some("read_file"));
        assert_eq!(
            pt.param_overrides.get("read_file_tool").map(|s| s.as_str()),
            Some("read_file")
        );
    }

    #[test]
    fn witness_prefers_non_reflectors_and_never_mutates() {
        let text = json!({"type": "object", "properties": {"message": {"type": "string"}}});
        // A reflector is a valid fallback witness: no pack flags reflection.
        let only_echo = suggest_packs(&[tool("echo", text.clone(), None)]);
        for pack in ["secrets-leakage", "unicode", "large-payload"] {
            let s = only_echo.iter().find(|p| p.pack == pack).unwrap();
            assert_eq!(s.witness_tool.as_deref(), Some("echo"), "{pack}");
        }

        let mixed = suggest_packs(&[
            tool("echo", text.clone(), None),
            tool("createScene", text.clone(), None),
            tool("log_message", text.clone(), None),
        ]);
        let sl = mixed.iter().find(|p| p.pack == "secrets-leakage").unwrap();
        assert_eq!(sl.witness_tool.as_deref(), Some("log_message"));

        // Campaign regression: hostile probes went to state-changing tools.
        let only_mutating = suggest_packs(&[tool("create_scene", text, None)]);
        assert!(!only_mutating
            .iter()
            .any(|p| ["secrets-leakage", "unicode", "large-payload"].contains(&p.pack.as_str())));
    }

    #[test]
    fn large_payload_gets_a_real_array_witness() {
        let text = json!({"type": "object", "properties": {"q": {"type": "string"}}});
        let ints = json!({"type": "object", "properties": {
            "ids": {"type": "array", "items": {"type": "integer"}}}});
        let s = suggest_packs(&[tool("search", text.clone(), None), tool("sum", ints, None)]);
        let lp = s.iter().find(|p| p.pack == "large-payload").unwrap();
        assert_eq!(lp.param_overrides["array_witness_tool"], "sum");
        assert_eq!(lp.param_overrides["array_witness_field"], "ids");
        // Without an integer array the array probe keeps its default
        // and is skipped as a missing tool, never sent to a string field.
        let s = suggest_packs(&[tool("search", text, None)]);
        let lp = s.iter().find(|p| p.pack == "large-payload").unwrap();
        assert!(!lp.param_overrides.contains_key("array_witness_tool"));
    }

    /// Campaign regression: a first tool without `properties` made the
    /// witness search give up on the whole server.
    #[test]
    fn witness_search_skips_tools_without_properties() {
        let text = json!({"type": "object", "properties": {"query": {"type": "string"}}});
        let s = suggest_packs(&[
            tool("list_all", json!({}), None),
            tool("search", text, None),
        ]);
        let sl = s.iter().find(|p| p.pack == "secrets-leakage").unwrap();
        assert_eq!(sl.witness_tool.as_deref(), Some("search"));
    }

    #[test]
    fn path_traversal_skips_mutating_tools_and_carries_field() {
        let schema = json!({
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
        });
        let tools = vec![
            tool("create_directory", schema.clone(), None),
            tool("get_file_info", schema, None),
        ];
        let s = suggest_packs(&tools);
        let pt: Vec<_> = s.iter().filter(|p| p.pack == "path-traversal").collect();
        assert_eq!(pt.len(), 1);
        assert_eq!(pt[0].witness_tool.as_deref(), Some("get_file_info"));
        assert_eq!(
            pt[0].param_overrides.get("path_field").map(|s| s.as_str()),
            Some("file_path")
        );
        assert!(!pt[0].param_overrides.contains_key("write_file_tool"));
    }

    /// Contract: every override `suggest` emits must be declared by the
    /// embedded pack it targets, otherwise `wallfacer property` aborts
    /// on the generated config (campaign regression on desktop-commander).
    #[test]
    fn every_suggestion_resolves_against_its_embedded_pack() {
        use crate::run::pack::{embedded_pack_source, resolve, EmbeddedLoader};
        let s = |props: Value| json!({"type": "object", "properties": props});
        let tools = vec![
            tool("echo", s(json!({"message": {"type": "string"}})), None),
            tool("whoami", json!({}), None),
            tool("read_file", s(json!({"path": {"type": "string"}})), None),
            tool("query_db", s(json!({"sql": {"type": "string"}})), None),
            tool("run_shell", s(json!({"cmd": {"type": "string"}})), None),
            tool("ask", s(json!({"prompt": {"type": "string"}})), None),
            tool("record_create", json!({}), None),
            tool("record_read", json!({}), None),
            tool("record_delete", json!({}), None),
            tool("auth_login", json!({}), None),
            tool("auth_logout", json!({}), None),
            tool_with_annotations("list_users", true),
        ];
        let suggestions = suggest_packs(&tools);
        assert!(
            suggestions.len() >= 10,
            "fixture should exercise most heuristics"
        );
        for sug in suggestions {
            let source = embedded_pack_source(&sug.pack)
                .unwrap_or_else(|| panic!("suggested pack `{}` is not embedded", sug.pack));
            if let Err(e) = resolve(source, &sug.param_overrides, &EmbeddedLoader) {
                panic!(
                    "pack `{}` rejects overrides {:?}: {e}",
                    sug.pack, sug.param_overrides
                );
            }
        }
    }

    #[test]
    fn name_words_split_snake_kebab_and_camel_case() {
        assert_eq!(name_words("getCurrentUser"), ["get", "current", "user"]);
        assert_eq!(name_words("get-current_user"), ["get", "current", "user"]);
        assert_eq!(name_words("API-get-self"), ["api", "get", "self"]);
        assert_eq!(name_words("s3Bucket2List"), ["s3", "bucket2", "list"]);
    }

    /// Campaign regression: substring matching made
    /// `execute_insights_query` look like a shell tool (`exec`), and
    /// `compute_output` look like a mutating tool (`put`).
    #[test]
    fn name_heuristics_match_whole_words_only() {
        let names = |tools: &[&str]| {
            let tools: Vec<Tool> = tools.iter().map(|n| tool(n, json!({}), None)).collect();
            suggest_packs(&tools)
        };
        assert!(!names(&["execute_insights_query"])
            .iter()
            .any(|p| p.pack == "injection-shell"));
        assert!(names(&["exec"]).iter().any(|p| p.pack == "injection-shell"));

        let path = json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let pt = |n: &str| {
            suggest_packs(&[tool(n, path.clone(), None)])
                .iter()
                .any(|p| p.pack == "path-traversal")
        };
        assert!(pt("compute_output"), "`put` inside `output` is not a write");
        assert!(!pt("createDirectory"));
        assert!(!pt("write_file"));
    }

    #[test]
    fn query_field_triggers_injection_sql_pack() {
        let schema = json!({
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"]
        });
        let tools = vec![tool("query_db", schema, None)];
        let s = suggest_packs(&tools);
        assert!(s.iter().any(|p| p.pack == "injection-sql"));
    }

    #[test]
    fn create_read_delete_triple_triggers_stateful_pack() {
        let tools = vec![
            tool("record_create", json!({}), None),
            tool("record_read", json!({}), None),
            tool("record_delete", json!({}), None),
        ];
        let s = suggest_packs(&tools);
        let st = s.iter().find(|p| p.pack == "stateful").unwrap();
        assert_eq!(
            st.param_overrides.get("create_tool").map(|s| s.as_str()),
            Some("record_create")
        );
        assert_eq!(
            st.param_overrides.get("delete_tool").map(|s| s.as_str()),
            Some("record_delete")
        );
    }

    #[test]
    fn login_logout_triggers_auth_flow_pack() {
        let tools = vec![
            tool("auth_login", json!({}), None),
            tool("auth_logout", json!({}), None),
        ];
        let s = suggest_packs(&tools);
        assert!(s.iter().any(|p| p.pack == "auth-flow"));
    }

    #[test]
    fn annotations_present_triggers_tool_annotations_pack() {
        let tools = vec![tool_with_annotations("list_users", true)];
        let s = suggest_packs(&tools);
        assert!(s.iter().any(|p| p.pack == "tool-annotations"));
    }
}
