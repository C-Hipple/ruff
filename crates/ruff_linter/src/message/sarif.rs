use std::io::Write;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::{json, Value};

use ruff_diagnostics::Edit;
use ruff_source_file::SourceCode;
use ruff_text_size::Ranged;

use crate::message::{Emitter, EmitterContext, Message};
use crate::registry::AsRule;

#[derive(Default)]
pub struct SarifEmitter;

impl Emitter for SarifEmitter {
    fn emit(
        &mut self,
        writer: &mut dyn Write,
        messages: &[Message],
        _context: &EmitterContext,
    ) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(writer, &ExpandedMessages { messages })?;

        Ok(())
    }
}

struct ExpandedMessages<'a> {
    messages: &'a [Message],
}

impl Serialize for ExpandedMessages<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let header = json!(
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
        );

        let mut s = serializer.serialize_seq(Some(self.messages.len()))?;

        for message in self.messages {
            let result = message_to_sarif_result(message);
            s.serialize_element(&result)?;
        }


        s.end()
    }
}

pub(crate) fn get_applied_rules() ->

pub(crate) fn group_messages_by_rule_id(messages: &[Message]) -> Vec<(String, Vec<&Message>)> {
    let mut map = std::collections::HashMap::new();

    for message in messages {
        let rule_code = message.kind.rule().id().to_string();
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
        let mut emitter = SarifEmitter;
        let content = capture_emitter_output(&mut emitter, &create_messages());

        assert_snapshot!(content);
    }
}
