use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JsonPathError {
    #[error("JSONPath must start with `$`: {0}")]
    InvalidRoot(String),
    #[error("invalid JSONPath segment near `{0}`")]
    InvalidSegment(String),
    #[error("path segment `{0}` did not resolve")]
    Missing(String),
    #[error("wildcard is only supported as the final segment")]
    WildcardNotFinal,
}

pub type Result<T> = std::result::Result<T, JsonPathError>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Field(String),
    Index(usize),
    Wildcard,
}

pub fn resolve_one(root: &Value, path: &str) -> Result<Value> {
    let values = resolve(root, path)?;
    values
        .into_iter()
        .next()
        .ok_or_else(|| JsonPathError::Missing(path.to_string()))
}

pub fn resolve(root: &Value, path: &str) -> Result<Vec<Value>> {
    let segments = parse(path)?;
    let mut current = vec![root.clone()];

    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        let mut next = Vec::new();

        for value in &current {
            match segment {
                Segment::Field(field) => {
                    let Some(child) = value.get(field) else {
                        return Err(JsonPathError::Missing(field.clone()));
                    };
                    next.push(child.clone());
                }
                Segment::Index(item_index) => {
                    let Some(child) = value.as_array().and_then(|items| items.get(*item_index))
                    else {
                        return Err(JsonPathError::Missing(format!("[{item_index}]")));
                    };
                    next.push(child.clone());
                }
                Segment::Wildcard => {
                    if !last {
                        return Err(JsonPathError::WildcardNotFinal);
                    }
                    let Some(items) = value.as_array() else {
                        return Err(JsonPathError::Missing("[*]".to_string()));
                    };
                    next.extend(items.iter().cloned());
                }
            }
        }

        current = next;
    }

    Ok(current)
}

fn parse(path: &str) -> Result<Vec<Segment>> {
    let Some(mut rest) = path.strip_prefix('$') else {
        return Err(JsonPathError::InvalidRoot(path.to_string()));
    };
    let mut segments = Vec::new();

    while !rest.is_empty() {
        if let Some(after_dot) = rest.strip_prefix('.') {
            let field_len = after_dot.find(['.', '[']).unwrap_or(after_dot.len());
            if field_len == 0 {
                return Err(JsonPathError::InvalidSegment(rest.to_string()));
            }
            let field = &after_dot[..field_len];
            segments.push(Segment::Field(field.to_string()));
            rest = &after_dot[field_len..];
        } else if let Some(after_bracket) = rest.strip_prefix('[') {
            let Some(end) = after_bracket.find(']') else {
                return Err(JsonPathError::InvalidSegment(rest.to_string()));
            };
            let token = &after_bracket[..end];
            if token == "*" {
                segments.push(Segment::Wildcard);
            } else {
                let index = token
                    .parse::<usize>()
                    .map_err(|_| JsonPathError::InvalidSegment(rest.to_string()))?;
                segments.push(Segment::Index(index));
            }
            rest = &after_bracket[end + 1..];
        } else {
            return Err(JsonPathError::InvalidSegment(rest.to_string()));
        }
    }

    Ok(segments)
}
