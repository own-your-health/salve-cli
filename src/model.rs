//! The shapes of Salve's answers that salve reads, as the queries in
//! [`crate::queries`] select them. Every field is optional and an id may be
//! a number or a string: Salve's schema is not published, so a value that
//! is missing or typed differently leaves that field out rather than
//! failing the read. `tests/fixture_shapes.rs` pins them to the fixtures.

use pk_cli_core::CliError;
use serde::de::Deserializer;
use serde::Deserialize;
use serde_json::Value;

/// A value read as text: a string as it is, a number or a boolean spelled
/// out, null or an object as none.
pub fn text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let v = Value::deserialize(d)?;
    Ok(match v {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

/// A list that may be null.
pub fn list<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

fn int<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    let v = Value::deserialize(d)?;
    Ok(match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    })
}

fn flag<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    let v = Value::deserialize(d)?;
    Ok(match v {
        Value::Bool(b) => Some(b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

/// `data.<path>` read as `T`; a shape salve cannot read is exit 5, naming
/// what was being read.
pub fn read<T: for<'de> Deserialize<'de>>(v: Value, what: &str) -> Result<T, CliError> {
    serde_json::from_value(v).map_err(|e| {
        CliError::Upstream(format!(
            "Salve answered {what} in a shape salve does not read: {}",
            de_why(&e)
        ))
    })
}

/// The error without the value it was reading.
fn de_why(e: &serde_json::Error) -> String {
    let s = e.to_string();
    s.split(" at line").next().unwrap_or(&s).chars().take(160).collect()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Me {
    #[serde(default, deserialize_with = "text")]
    pub patientid: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub firstname: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub lastname: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Clinic {
    #[serde(default, rename = "_id", deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "flag")]
    pub selected: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PatientAndClinic {
    #[serde(default)]
    pub me: Option<Me>,
    #[serde(default)]
    pub clinic: Option<Clinic>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MeOnly {
    #[serde(default)]
    pub me: Option<Me>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Clinics {
    #[serde(default, deserialize_with = "list")]
    pub clinics: Vec<Clinic>,
}

/// A document the clinic sent, or a file on the record (the query aliases
/// the file's fields to the document's names).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DocumentItem {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub uri: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub filetype: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub sentdate: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub readdate: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub uuid: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DocumentsMe {
    #[serde(default, deserialize_with = "list")]
    pub documents: Vec<DocumentItem>,
    #[serde(default, deserialize_with = "list")]
    pub files: Vec<DocumentItem>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DocumentsAnswer {
    #[serde(default)]
    pub me: Option<DocumentsMe>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormSummary {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub clinicid: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub patientformid: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub progress_status: Option<String>,
    #[serde(default, rename = "type", deserialize_with = "text")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FormsMe {
    #[serde(default, deserialize_with = "list")]
    pub forms: Vec<FormSummary>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FormsAnswer {
    #[serde(default)]
    pub me: Option<FormsMe>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Submission {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub version: Option<String>,
    #[serde(default)]
    pub submission: Value,
    #[serde(default, deserialize_with = "flag")]
    pub issubmitted: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Form {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub patientformid: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub version: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
    #[serde(default, rename = "type", deserialize_with = "text")]
    pub kind: Option<String>,
    #[serde(default)]
    pub definition: Value,
    #[serde(default)]
    pub latestsubmission: Option<Submission>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FormMe {
    #[serde(default)]
    pub form: Option<Form>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FormAnswer {
    #[serde(default)]
    pub me: Option<FormMe>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct VideoCall {
    #[serde(default, rename = "__typename", deserialize_with = "text")]
    pub typename: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub host: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub title: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub clinictimezone: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub startdate: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub enddate: Option<String>,
    #[serde(default, deserialize_with = "int")]
    pub duration: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoCallsMe {
    #[serde(default, deserialize_with = "list")]
    pub video_calls: Vec<VideoCall>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct VideoCallsAnswer {
    #[serde(default)]
    pub me: Option<VideoCallsMe>,
}

// ------------------------------------------------- the first messaging

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Latest {
    #[serde(default, deserialize_with = "text")]
    pub sent: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConversationV0 {
    #[serde(default, deserialize_with = "int")]
    pub id: Option<i64>,
    #[serde(default, deserialize_with = "text")]
    pub conversationtype: Option<String>,
    #[serde(default)]
    pub latest: Option<Latest>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConversationsV0Me {
    #[serde(default, deserialize_with = "list")]
    pub conversations: Vec<ConversationV0>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConversationsV0 {
    #[serde(default)]
    pub me: Option<ConversationsV0Me>,
}

/// A file a message carries (`MessageFileMetadata`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FileMeta {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub filename: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub filetype: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub url: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub uuid: Option<String>,
}

/// A message, or a group of messages sent together.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MessageV0 {
    #[serde(default, rename = "__typename", deserialize_with = "text")]
    pub typename: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub content: Option<String>,
    #[serde(default, deserialize_with = "flag")]
    pub deleted: Option<bool>,
    #[serde(default, deserialize_with = "flag")]
    pub frompatient: Option<bool>,
    #[serde(default, deserialize_with = "text")]
    pub sender: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub sent: Option<String>,
    #[serde(default, rename = "type", deserialize_with = "text")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub uuid: Option<String>,
    #[serde(default, deserialize_with = "list")]
    pub metadata: Vec<FileMeta>,
    /// A group's messages.
    #[serde(default, deserialize_with = "list")]
    pub messages: Vec<MessageV0>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConversationDetailV0 {
    #[serde(default, deserialize_with = "int")]
    pub id: Option<i64>,
    #[serde(default, deserialize_with = "text")]
    pub conversationtype: Option<String>,
    #[serde(default, deserialize_with = "list")]
    pub messages: Vec<MessageV0>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationV0Me {
    #[serde(default, rename = "conversationV2")]
    pub conversation: Option<ConversationDetailV0>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConversationV0Answer {
    #[serde(default)]
    pub me: Option<ConversationV0Me>,
}

// ------------------------------------------------- the newer messaging

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Folder {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationV3 {
    #[serde(default, deserialize_with = "int")]
    pub id: Option<i64>,
    #[serde(default, deserialize_with = "text")]
    pub subject: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub conversation_status: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub conversation_type: Option<String>,
    #[serde(default)]
    pub conversation_folder: Option<Folder>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Records<T> {
    #[serde(default, deserialize_with = "list")]
    pub records: Vec<T>,
    #[serde(default, deserialize_with = "text")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConversationsV3 {
    #[serde(default)]
    pub conversations: Option<Records<ConversationV3>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub first_name: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub last_name: Option<String>,
}

impl Person {
    pub fn display(&self) -> Option<String> {
        let parts: Vec<&str> = [&self.first_name, &self.last_name]
            .iter()
            .filter_map(|p| p.as_deref().map(str::trim).filter(|s| !s.is_empty()))
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV3 {
    #[serde(default, deserialize_with = "text")]
    pub file_name: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub file_type: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub url: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub uuid: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageV3 {
    #[serde(default, deserialize_with = "text")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub content: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub sent_date: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub deleted_date: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub system_message_type: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub uuid: Option<String>,
    #[serde(default, deserialize_with = "list")]
    pub attachments: Vec<AttachmentV3>,
    #[serde(default)]
    pub patient: Option<Person>,
    #[serde(default)]
    pub clinic_user: Option<Person>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesV3 {
    #[serde(default)]
    pub conversation_messages: Option<Records<MessageV3>>,
}
