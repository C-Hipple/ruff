use std::io::Write;
use url::Url;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::json;

use ruff_diagnostics::Edit;
use ruff_source_file::SourceCode;
use ruff_text_size::Ranged;

use crate::VERSION;
use crate::message::{Emitter, EmitterContext, Message};
use crate::registry::{AsRule, Linter, Rule, RuleNamespace};
use crate::settings::rule_table::RuleTable;

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
        let results = group_messages_by_rule_id(messages);

        let output = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ruffc",
                        "informationUri": "https://github.com/astral-sh/ruff",
                        "rules": self.applied_rules,
                        "version": VERSION.to_string(),

                    }
                },
                // TODO: Add artifacts
                //"artifacts": &SarifResult { messages: artifacts_from_messages(messages) },
                "results": results,
            }],
        });
        serde_json::to_writer_pretty(writer, &output)?;

        Ok(())
    }
}

// type Artifact = Message;

// impl Serialize for Artifact {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where S: Serializer,
//     {
//         json!({
//             "location": {
//                 "uri": self.filename(),
//                 "region": {
//                     "startLine": self.start(),
//                     "startColumn": self.start(),
//                     "endLine": self.end(),
//                     "endColumn": self.end(),
//                 }
//             }
//         })
//             .serialize(serializer)
//     }
// }

// fn artifacts_from_messages(messages: &[Message]) -> &[Artifact]{
//     let artifacts: Vec<&Artifact>;
//     for message in messages {
//         artifacts.push(message as &Artifact);
//         // let source_code = message.file.to_source_code();

//         // let start_location = source_code.source_location(message.start());
//         // let end_location = source_code.source_location(message.end());
//         // let noqa_location = source_code.source_location(message.noqa_offset);

//         // let artifact = Artifact {
//         //     range: message.range,
//         //     kind: message.kind,
//         //     fix: message.fix,
//         //     file: message.file,
//         //     noqa_offset: message.noqa_offset,
//         // };
//         // artifacts.push(&artifact);

//     }
//     artifacts.as_slice()
//     //messages.iter().map(|m| m as &Artifact).collect::<Vec<Artifact>>().as_slice()
// }

struct Location {
    uri: String,
    index: usize,
    start_line: usize,
    start_column: usize,
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
                    "index": 0,
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
    fn from_messages(messages: Vec<&Message>) -> Self {
        let locations = messages
            .iter()
            .map(|m| Location {
                uri: Url::from_file_path(m.filename()).unwrap().to_string(),
                index: 0,
                start_line: m.start().to_usize(),
                start_column: 0, // does ruff currently support column numbers?
            })
            .collect::<Vec<Location>>();
        Self {
            rule: messages[0].kind.rule().to_owned(),
            level: "error".to_string(),
            message: messages[0].kind.name.to_owned(),
            locations: locations,
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

// pub(crate) fn get_applied_rules() ->
pub(crate) fn group_messsag_by_rule() {}

// Ruff outputs each individual finding
// Sarif groups findings by rule, so we build each mesasge into the Location vector for all found rules.
fn group_messages_by_rule_id(messages: &[Message]) -> Vec<SarifResult> {
    let mut map = std::collections::HashMap::new();

    for message in messages {
        let rule_code = message.kind.rule().noqa_code().to_string();
        map.entry(rule_code).or_insert_with(Vec::new).push(message);
    }
    let mut results = Vec::new();
    for (rule_code, messages) in map {
        let result = SarifResult::from_messages(messages);
        results.push(result);
    }
    results
}

// fn message_to_sarif_result(message: &Message) -> Value {
//     let source_code = message.file.to_source_code();

//     let start_location = source_code.source_location(message.start());
//     let end_location = source_code.source_location(message.end());
//     let noqa_location = source_code.source_location(message.noqa_offset);

//     json!({
//         "code": message.kind.rule().noqa_code().to_string(),
//         "url": message.kind.rule().url(),
//         "location": start_location,
//         "end_location": end_location,
//         "filename": message.filename(),
//         "noqa_row": noqa_location.row
//     })
// }

struct ExpandedEdits<'a> {
    edits: &'a [Edit],
    source_code: &'a SourceCode<'a, 'a>,
}

impl Serialize for ExpandedEdits<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_seq(Some(self.edits.len()))?;

        for edit in self.edits {
            let value = json!({
                "content": edit.content().unwrap_or_default(),
                "location": self.source_code.source_location(edit.start()),
                "end_location": self.source_code.source_location(edit.end())
            });
            s.serialize_element(&value)?;
        }

        s.end()
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
