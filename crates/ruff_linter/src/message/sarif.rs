use std::io::Write;
use url::Url;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::json;

use ruff_source_file::OneIndexed;

use crate::message::{Emitter, EmitterContext, Message};
use crate::registry::{AsRule, Linter, Rule, RuleNamespace};
use crate::settings::rule_table::RuleTable;
use crate::VERSION;

#[derive(Debug, Clone)]
struct SarifRule<'a> {
    name: &'a str,
    code: String,
    linter: &'a str,
    summary: &'a str,
    message_formats: &'a [&'a str],
    fix: String,
    explanation: Option<&'a str>,
    preview: bool,
    url: Option<String>,
}

impl<'a> SarifRule<'a> {
    fn from_rule(rule: Rule) -> Self {
        let code = rule.noqa_code().to_string();
        let (linter, _) = Linter::parse_code(&code).unwrap();
        let fix = rule.fixable().to_string();
        Self {
            name: rule.to_owned().into(),
            code,
            linter: linter.name(),
            summary: rule.message_formats()[0],
            message_formats: rule.message_formats(),
            fix,
            explanation: rule.explanation(),
            preview: rule.is_preview() || rule.is_nursery(),
            url: rule.url(),
        }
    }
}

// This is the "rules" field in the Sarif output under "tool"
impl Serialize for SarifRule<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        json!({
            "id": self.code,
            "shortDescription": {
                "text": self.summary,
            },
            "fullDescription": {
                "text": self.explanation,
            },
            "helpUri": self.url,
            "properties": {
                "category": self.linter,
                //"severity": self.severity(),
                //"tags": self.tags(),
            },
        })
        .serialize(serializer)
    }
}
#[derive(Default)]
pub struct SarifEmitter<'a> {
    applied_rules: Vec<SarifRule<'a>>,
}

impl SarifEmitter<'_> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_applied_rules(mut self, rule_table: RuleTable) -> Self {
        let mut applied_rules = Vec::new();

        for rule in rule_table.iter_enabled() {
            applied_rules.push(SarifRule::from_rule(rule.to_owned()).to_owned());
        }

        self.applied_rules = applied_rules;
        self
    }
}

impl Emitter for SarifEmitter<'_> {
    fn emit(
        &mut self,
        writer: &mut dyn Write,
        messages: &[Message],
        _context: &EmitterContext,
    ) -> anyhow::Result<()> {
        let results = messages
            .iter()
            .map(|message| SarifResult::from_message(message))
            .collect::<Vec<_>>();

        let output = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ruff",
                        "informationUri": "https://github.com/astral-sh/ruff",
                        "rules": self.applied_rules,
                        "version": VERSION.to_string(),

                    }
                },
                "results": results,
            }],
        });
        serde_json::to_writer_pretty(writer, &output)?;

        Ok(())
    }
}

struct Location {
    uri: String,
    start_line: OneIndexed,
    start_column: OneIndexed,
}

impl Serialize for Location {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        json!({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": self.uri,
                    //"index": 0,
                },
                "region": {
                    "startLine": self.start_line,
                    "startColumn": self.start_column,
                }
            }
        })
        .serialize(serializer)
    }
}

struct SarifResult {
    rule: Rule,
    level: String,
    message: String,
    locations: Vec<Location>,
}

impl SarifResult {
    fn from_message(message: &Message) -> Self {
        let start_location = message.compute_start_location();
        Self {
            rule: message.kind.rule(),
            level: "error".to_string(),
            message: message.kind.name.to_owned(),
            locations: vec![Location {
                uri: Url::from_file_path(message.filename()).unwrap().to_string(),
                start_line: start_location.row,
                start_column: start_location.column
            }],
        }
    }
}

impl Serialize for SarifResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        json!({
            "level": self.level,
            "message": {
                "text": self.message,
            },
            "locations": self.locations,
            "ruleId": self.rule.noqa_code().to_string(),
        })
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;

    use crate::message::tests::{capture_emitter_output, create_messages};
    use crate::message::SarifEmitter;

    #[test]
    fn output() {
        let mut emitter = SarifEmitter::default();
        let content = capture_emitter_output(&mut emitter, &create_messages());

        assert_snapshot!(content);
    }
}
