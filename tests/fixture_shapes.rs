//! The fixtures against the shapes salve reads (`salve::model`): every
//! answer the stub serves parses, and carries the fields the mapping uses,
//! so a renamed field fails here instead of silently emptying a record.
//! Each fixture's keys are also checked against the query that asks for it,
//! so a fixture cannot drift from what salve sends.

mod common;

use common::fixture;
use salve::model::{
    self, ConversationV0Answer, ConversationsV0, ConversationsV3, DocumentsAnswer, FormAnswer, FormsAnswer, MeOnly,
    MessagesV3, PatientAndClinic, VideoCallsAnswer,
};
use salve::queries::{self, Op};
use serde_json::Value;

fn data(name: &str) -> Value {
    let v: Value = serde_json::from_str(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    v["data"].clone()
}

/// Every object key in an answer, for checking against a query's text. A
/// form's `definition` and `submission` are JSON values of their own, whole
/// as the query selects them.
fn keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                out.push(k.clone());
                if k != "definition" && k != "submission" {
                    keys(v, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
        _ => {}
    }
}

/// Each key the fixture answers is a field (or alias) the query selects.
fn selected(op: &Op, name: &str) {
    let mut found = Vec::new();
    keys(&data(name), &mut found);
    let words: Vec<&str> = op
        .document
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    for k in found {
        assert!(
            words.contains(&k.as_str()),
            "{name}: `{k}` is not selected by {}",
            op.name
        );
    }
}

#[test]
fn the_account_answers_parse() {
    selected(&queries::PATIENT_AND_CLINIC, "patient-and-clinic.json");
    let pc: PatientAndClinic = model::read(data("patient-and-clinic.json"), "x").unwrap();
    let me = pc.me.unwrap();
    assert!(me.patientid.is_some() && me.name.is_some());
    let clinic = pc.clinic.unwrap();
    assert!(clinic.id.is_some() && clinic.name.is_some());
    selected(&queries::PATIENT_ID, "patient-id.json");
    let m: MeOnly = model::read(data("patient-id.json"), "x").unwrap();
    let me = m.me.unwrap();
    assert!(me.firstname.is_some() && me.lastname.is_some());
    selected(&queries::PATIENT_CLINICS, "patient-clinics.json");
}

#[test]
fn documents_and_files_parse_with_their_addresses() {
    selected(&queries::DOCUMENTS, "documents.json");
    selected(&queries::FILES, "files.json");
    for (name, files) in [("documents.json", false), ("files.json", true)] {
        let d: DocumentsAnswer = model::read(data(name), name).unwrap();
        let me = d.me.unwrap();
        let list = if files { me.files } else { me.documents };
        assert!(!list.is_empty(), "{name}");
        for item in list {
            assert!(
                item.id.is_some() && item.uri.is_some() && item.sentdate.is_some(),
                "{name}: {item:?}"
            );
            assert!(item.name.is_some() && item.filetype.is_some(), "{name}: {item:?}");
        }
    }
}

#[test]
fn forms_parse_with_their_answers() {
    selected(&queries::FORMS, "forms.json");
    let f: FormsAnswer = model::read(data("forms.json"), "forms").unwrap();
    let forms = f.me.unwrap().forms;
    assert_eq!(forms.len(), 3);
    for s in &forms {
        assert!(s.id.is_some() && s.patientformid.is_some() && s.version.is_some() && s.progress_status.is_some());
    }
    for name in ["form-4001.json", "form-4003.json"] {
        selected(&queries::FORM, name);
        let a: FormAnswer = model::read(data(name), name).unwrap();
        let form = a.me.unwrap().form.unwrap();
        assert!(form.definition.is_object(), "{name}");
        let sub = form.latestsubmission.unwrap();
        assert!(sub.submission.is_object() && sub.issubmitted.is_some(), "{name}");
    }
    let gone: FormAnswer = model::read(data("form-not-found.json"), "x").unwrap();
    assert!(gone.me.unwrap().form.is_none());
}

#[test]
fn video_visits_parse_with_their_times() {
    for name in [
        "video-calls-past.json",
        "video-calls-future.json",
        "video-calls-empty.json",
    ] {
        selected(&queries::VIDEO_CALLS, name);
        let v: VideoCallsAnswer = model::read(data(name), name).unwrap();
        for call in v.me.unwrap().video_calls {
            assert_eq!(call.typename.as_deref(), Some("VideoCall"));
            assert!(call.id.is_some() && call.startdate.is_some() && call.enddate.is_some() && call.duration.is_some());
        }
    }
}

#[test]
fn both_messagings_parse() {
    selected(&queries::CONVERSATIONS_V3, "conversations-v3.json");
    let c: ConversationsV3 = model::read(data("conversations-v3.json"), "x").unwrap();
    let list = c.conversations.unwrap().records;
    assert!(list[0].id.is_some() && list[0].subject.is_some());
    let empty: ConversationsV3 = model::read(data("conversations-v3-empty.json"), "x").unwrap();
    assert!(empty.conversations.unwrap().records.is_empty());
    for name in ["messages-v3-7001-page1.json", "messages-v3-7001-page2.json"] {
        selected(&queries::MESSAGES_V3, name);
        let m: MessagesV3 = model::read(data(name), name).unwrap();
        for msg in m.conversation_messages.unwrap().records {
            assert!(msg.id.is_some() && msg.sent_date.is_some(), "{name}");
            assert!(msg.patient.is_some() || msg.clinic_user.is_some() || msg.system_message_type.is_some());
            for a in msg.attachments {
                assert!(a.url.is_some() && a.uuid.is_some() && a.file_name.is_some());
            }
        }
    }
    selected(&queries::CONVERSATIONS_V0, "conversations-v0.json");
    let c: ConversationsV0 = model::read(data("conversations-v0.json"), "x").unwrap();
    assert!(c.me.unwrap().conversations[0].id.is_some());
    selected(&queries::CONVERSATION_V0, "conversation-v0-8001.json");
    let d: ConversationV0Answer = model::read(data("conversation-v0-8001.json"), "x").unwrap();
    let messages = d.me.unwrap().conversation.unwrap().messages;
    assert_eq!(messages[0].typename.as_deref(), Some("MessageGroup"));
    let inner = &messages[0].messages[0];
    assert!(inner.id.is_some() && inner.sent.is_some() && inner.frompatient.is_some());
    assert!(inner.metadata[0].url.is_some());
}

#[test]
fn every_query_has_a_fixture() {
    let served = [
        "GetPatientAndClinic",
        "GetPatientId",
        "GetPatientClinics",
        "GetDocuments",
        "GetFiles",
        "GetForms",
        "GetForm",
        "GetVideoCalls",
        "FetchConversations",
        "GetConversation",
        "GetConversations",
        "GetConversationMessages",
    ];
    for op in queries::ALL {
        assert!(served.contains(&op.name), "{} has no fixture", op.name);
    }
}
