use std::io::Write;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::{json, Value};

use ruff_diagnostics::Edit;
use ruff_source_file::SourceCode;
use ruff_text_size::Ranged;

use crate::message::{Emitter, EmitterContext, Message};
use crate::registry::{AsRule, Rule, Linter, RuleNamespace};
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
            name: rule.as_ref(),
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

#[derive(Default)]
pub struct SarifEmitter<'a > {
    applied_rules: Vec<&'a SarifRule<'a>>,
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
        let output = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ruffc",
                        "informationUri": "https://github.com/astral-sh/ruff",
                        "rules": self.applied_rules
                    }
                },
                //"artifacts": &ExpandedSarifMessages { messages: artifacts_from_messages(messages) },
                "results": &ExpandedSarifMessages { messages },
            }],
        });
        serde_json::to_writer_pretty(writer, &output)?;

        Ok(())
    }
}

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

type Artifact = Message;


impl Serialize for Artifact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        json!({
            "location": {
                "uri": self.filename(),
                "region": {
                    "startLine": self.start(),
                    "startColumn": self.start(),
                    "endLine": self.end(),
                    "endColumn": self.end(),
                }
            }
        })
            .serialize(serializer)
    }
}

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

struct ExpandedSarifMessages<'a> {
    messages: &'a [Message],
}

impl Serialize for ExpandedSarifMessages<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_seq(Some(self.messages.len()))?;
        for message in self.messages {
            let result = message_to_sarif_result(message);
            s.serialize_element(&result)?;
        }

        let res = s.end();
        res
    }
}

// pub(crate) fn get_applied_rules() ->

pub(crate) fn group_messages_by_rule_id(messages: &[Message]) -> Vec<(String, Vec<&Message>)> {
    let mut map = std::collections::HashMap::new();

    for message in messages {
        let rule_code = message.kind.rule().noqa_code().to_string();
        map.entry(rule_code).or_insert_with(Vec::new).push(message);
    }

    map.into_iter().collect()
}

pub(crate) fn message_to_sarif_result(message: &Message) -> Value {
    let source_code = message.file.to_source_code();

    let fix = message.fix.as_ref().map(|fix| {
        json!({
            "applicability": fix.applicability(),
            "message": message.kind.suggestion.as_deref(),
            "edits": &ExpandedEdits { edits: fix.edits(), source_code: &source_code },
        })
    });

    let start_location = source_code.source_location(message.start());
    let end_location = source_code.source_location(message.end());
    let noqa_location = source_code.source_location(message.noqa_offset);

    json!({
        "code": message.kind.rule().noqa_code().to_string(),
        "url": message.kind.rule().url(),
        "message": message.kind.body,
        "fix": fix,
        "location": start_location,
        "end_location": end_location,
        "filename": message.filename(),
        "noqa_row": noqa_location.row
    })
}

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
