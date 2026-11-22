//! Reading a patient's records from Salve, and writing them as a
//! records-stream.
//!
//! Salve is read through [`Reader`], one query or file per call, so a test
//! can answer from fixtures. Each list is one query, as the app asks for
//! it; video visits and the newer messaging's messages come a page at a
//! time.
//!
//! Salve has had two messaging systems. The newer one (the patient API's
//! `conversations`) is read first; when it has no conversation for the
//! patient, or the patient API does not answer, the first one (the app
//! API's `me.conversations`) is read instead.

use std::collections::BTreeSet;
use std::io::Write;

use pk_cli_core::CliError;
use pk_med_records::stream::skip;
use pk_med_records::{Finished, Header, RawResource, RecordsWriter, Skip};
use serde_json::{json, Value};

use crate::fhir::{self, Ctx};
use crate::model::{
    self, ConversationV0Answer, ConversationsV0, ConversationsV3, DocumentItem, DocumentsAnswer, FormAnswer,
    FormsAnswer, MessageV0, MessageV3, MessagesV3, VideoCall, VideoCallsAnswer,
};
use crate::queries::{self, Op};
use crate::salve::Answer;

/// Salve, as a pull reads it.
pub trait Reader {
    /// One of salve's queries.
    fn query(&self, op: &Op, variables: &Value) -> Result<Answer, CliError>;
    /// A file's bytes, from its address in a record (a message's file with
    /// its conversation).
    fn file(&self, uri: &str, conversation: Option<i64>) -> Result<Vec<u8>, CliError>;
}

/// Video visits per page, and pages read each way at most.
const VIDEO_PAGE: i64 = 50;
const VIDEO_PAGES: i64 = 20;
/// Conversations or messages asked for per page, and pages read of each
/// list at most. Without a limit Salve answers the whole list as one page.
const MESSAGE_PAGE: i64 = 100;
const MESSAGE_PAGES: usize = 50;

/// A file Salve serves: what `documents list` shows and the address that
/// fetches it.
#[derive(Debug, Clone)]
pub struct Fetchable {
    /// `doc-<id>`, `file-<id>` or `att-<uuid>`.
    pub id: String,
    pub name: String,
    pub category: &'static str,
    /// The day it is dated.
    pub date: Option<String>,
    pub filetype: Option<String>,
    pub uri: String,
    pub conversation: Option<i64>,
}

fn me_documents(r: &dyn Reader, op: &Op) -> Result<Vec<DocumentItem>, CliError> {
    let a = r.query(op, &json!({}))?;
    let d: DocumentsAnswer = model::read(a.data, op.name)?;
    let me = d.me.unwrap_or_default();
    Ok(if op.name == queries::FILES.name {
        me.files
    } else {
        me.documents
    })
}

fn fetchable(prefix: &str, category: &'static str, d: &DocumentItem) -> Option<Fetchable> {
    let id = d.id.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    let uri = d.uri.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    Some(Fetchable {
        id: format!("{prefix}-{id}"),
        name: d
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("{prefix}-{id}")),
        category,
        date: d.sentdate.as_deref().and_then(fhir::day),
        filetype: d.filetype.clone(),
        uri: uri.to_string(),
        conversation: None,
    })
}

/// Which messaging a patient's conversations are in.
pub enum Messaging {
    /// The newer: each conversation with its messages.
    V3(Vec<(model::ConversationV3, Vec<MessageV3>)>),
    /// The first.
    V0(Vec<(i64, Option<String>, Vec<MessageV0>)>),
}

/// A part of the messages that was not read: the search, the skip code and
/// why.
pub type Gap = (String, &'static str, String);

/// Pages of a cursor-paged list: each page asks for [`MESSAGE_PAGE`], and
/// the cursor is followed only after a full page. Salve answers every page
/// with a cursor, and a request past the end fails, so a short page is the
/// end. `Err` is a page that failed, with what was read before it.
fn pages<T, F>(mut read: F, key: impl Fn(&T) -> Option<String>) -> (Vec<T>, Option<(usize, CliError)>, bool)
where
    F: FnMut(Option<&str>) -> Result<model::Records<T>, CliError>,
{
    let mut all = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor: Option<String> = None;
    for page in 1..=MESSAGE_PAGES {
        let got = match read(cursor.as_deref()) {
            Ok(got) => got,
            Err(e) => return (all, Some((page, e)), false),
        };
        let full = got.records.len() as i64 >= MESSAGE_PAGE;
        let before = seen.len();
        for t in got.records {
            if key(&t).is_none_or(|k| seen.insert(k)) {
                all.push(t);
            }
        }
        let next = got.cursor.filter(|c| !c.is_empty() && Some(c) != cursor.as_ref());
        if !full || next.is_none() || seen.len() == before {
            return (all, None, false);
        }
        cursor = next;
    }
    (all, None, true)
}

/// The patient's conversations and their messages, from the messaging that
/// has them, and what of them was not read.
pub fn messaging(r: &dyn Reader) -> Result<(Messaging, Vec<Gap>), CliError> {
    let mut gaps: Vec<Gap> = Vec::new();
    let (v3_list, failed, capped) = pages(
        |cursor| {
            let mut vars = json!({ "limit": MESSAGE_PAGE });
            if let Some(c) = cursor {
                vars["cursor"] = json!(c);
            }
            let a = r.query(&queries::CONVERSATIONS_V3, &vars)?;
            Ok(model::read::<ConversationsV3>(a.data, "conversations")?
                .conversations
                .unwrap_or_default())
        },
        |c: &model::ConversationV3| c.id.map(|i| i.to_string()),
    );
    match failed {
        Some((_, e)) if e.is_auth() => return Err(e),
        // The newer messaging failing outright: the first may hold them.
        Some((1, _)) => {}
        Some((page, e)) => gaps.push((
            format!("GetConversations?page={page}"),
            skip::UPSTREAM,
            e.message().to_string(),
        )),
        None => {}
    }
    if capped {
        gaps.push((
            "GetConversations".into(),
            skip::PAGE_CAP,
            format!("pages past {MESSAGE_PAGES} were left"),
        ));
    }
    if !v3_list.is_empty() {
        let mut out = Vec::new();
        for c in v3_list {
            let Some(id) = c.id else { continue };
            let (messages, failed, capped) = pages(
                |cursor| {
                    let mut vars = json!({ "conversationId": id, "limit": MESSAGE_PAGE });
                    if let Some(c) = cursor {
                        vars["cursor"] = json!(c);
                    }
                    let a = r.query(&queries::MESSAGES_V3, &vars)?;
                    Ok(model::read::<MessagesV3>(a.data, "messages")?
                        .conversation_messages
                        .unwrap_or_default())
                },
                |m: &MessageV3| m.id.clone(),
            );
            let search = format!("GetConversationMessages?conversationId={id}");
            match failed {
                Some((_, e)) if e.is_auth() => return Err(e),
                // One conversation that fails costs its own messages only.
                Some((_, e)) => gaps.push((search.clone(), skip::UPSTREAM, e.message().to_string())),
                None => {}
            }
            if capped {
                gaps.push((search, skip::PAGE_CAP, format!("pages past {MESSAGE_PAGES} were left")));
            }
            out.push((c, messages));
        }
        return Ok((Messaging::V3(out), gaps));
    }
    let a = r.query(&queries::CONVERSATIONS_V0, &json!({}))?;
    let list: ConversationsV0 = model::read(a.data, "conversations")?;
    let mut out = Vec::new();
    for c in list.me.unwrap_or_default().conversations {
        let Some(id) = c.id else { continue };
        let a = r.query(&queries::CONVERSATION_V0, &json!({ "conversationId": id }))?;
        let detail: ConversationV0Answer = model::read(a.data, "a conversation")?;
        let detail = detail.me.and_then(|m| m.conversation).unwrap_or_default();
        let mut flat = Vec::new();
        for m in detail.messages {
            flatten(m, &mut flat);
        }
        out.push((id, detail.conversationtype.or(c.conversationtype), flat));
    }
    Ok((Messaging::V0(out), gaps))
}

/// A message group's messages, or the message itself.
fn flatten(m: MessageV0, out: &mut Vec<MessageV0>) {
    if m.typename.as_deref() == Some("MessageGroup") || (!m.messages.is_empty() && m.id.is_none()) {
        for inner in m.messages {
            flatten(inner, out);
        }
    } else {
        out.push(m);
    }
}

/// Everything the documents commands list: the clinic's documents, the
/// record's files and message attachments. A list Salve does not offer or
/// fails to answer is left out and said in `missing`; a sign-in it no
/// longer takes stops the listing.
pub fn documents(r: &dyn Reader) -> Result<(Vec<Fetchable>, Vec<String>), CliError> {
    let mut out = Vec::new();
    let mut missing = Vec::new();
    let mut tolerate =
        |answer: Result<Vec<DocumentItem>, CliError>, what: &str| -> Result<Vec<DocumentItem>, CliError> {
            match answer {
                Ok(v) => Ok(v),
                Err(e) if e.is_auth() => Err(e),
                Err(e) => {
                    missing.push(format!("{what} could not be read: {}", e.message()));
                    Ok(Vec::new())
                }
            }
        };
    for d in tolerate(me_documents(r, &queries::DOCUMENTS), "documents")? {
        out.extend(fetchable("doc", "document", &d));
    }
    for d in tolerate(me_documents(r, &queries::FILES), "files")? {
        out.extend(fetchable("file", "file", &d));
    }
    match messaging(r) {
        Ok((Messaging::V3(list), _)) => {
            for (c, messages) in &list {
                for m in messages {
                    for a in &m.attachments {
                        let (Some(id), Some(url)) = (fhir::attachment_v3_id(a), a.url.clone()) else {
                            continue;
                        };
                        out.push(Fetchable {
                            name: a.file_name.clone().unwrap_or_else(|| id.clone()),
                            id,
                            category: "message-attachment",
                            date: m.sent_date.as_deref().and_then(fhir::day),
                            filetype: a.file_type.clone(),
                            uri: url,
                            conversation: c.id,
                        });
                    }
                }
            }
        }
        Ok((Messaging::V0(list), _)) => {
            for (conv, _, messages) in &list {
                for m in messages {
                    for f in &m.metadata {
                        let (Some(id), Some(url)) = (fhir::meta_id(f), f.url.clone()) else {
                            continue;
                        };
                        out.push(Fetchable {
                            name: f.filename.clone().unwrap_or_else(|| id.clone()),
                            id,
                            category: "message-attachment",
                            date: m.sent.as_deref().and_then(fhir::day),
                            filetype: f.filetype.clone(),
                            uri: url,
                            conversation: Some(*conv),
                        });
                    }
                }
            }
        }
        Err(e) if e.is_auth() => return Err(e),
        Err(e) => missing.push(format!("messages could not be read: {}", e.message())),
    }
    let mut seen = BTreeSet::new();
    out.retain(|f| seen.insert(f.id.clone()));
    Ok((out, missing))
}

/// The patient's name and ids, from the stored session.
pub struct Who {
    pub patient_id: String,
    pub full_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub birth_date: Option<String>,
}

/// What a pull found, for the trailer's counts and the stderr summary.
#[derive(Debug, Default)]
pub struct Tally {
    /// Records left out by `--since`.
    pub before_since: u64,
}

fn skip_list<W: Write>(w: &mut RecordsWriter<W>, e: CliError, search: &str, what: &str) -> Result<(), CliError> {
    if e.is_auth() {
        return Err(e);
    }
    let code = if e.exit_code() == 4 {
        skip::UNSUPPORTED
    } else {
        skip::UPSTREAM
    };
    let why = if e.exit_code() == 4 {
        format!("Salve does not offer {what} to this patient")
    } else {
        e.message().to_string()
    };
    w.skip(Skip::search(search, code, why));
    Ok(())
}

/// Whether a dated record is kept under `--since`; an undated one always is.
fn keep(since: Option<&str>, day: Option<&str>) -> bool {
    match (since, day) {
        (Some(s), Some(d)) => d >= s,
        _ => true,
    }
}

/// One file, fetched and checked, as a Binary's bytes and content type; a
/// failure is a skip of `owner`.
fn fetch<W: Write>(
    r: &dyn Reader,
    w: &mut RecordsWriter<W>,
    f: &Fetchable,
    owner: (&str, &str),
) -> Result<Option<(Vec<u8>, String)>, CliError> {
    let bytes = match fetch_checked(r, f) {
        Ok(b) => b,
        Err(e) if e.is_auth() => return Err(e),
        Err(e) => {
            let code = if e.reason() == Some(pk_cli_core::Reason::BadRequest) {
                skip::VERIFY_FAILED
            } else if e.exit_code() == 4 {
                skip::NO_FILE
            } else {
                skip::UPSTREAM
            };
            w.skip(Skip::resource(
                owner.0,
                owner.1,
                code,
                format!("its file was not served: {}", e.message()),
            ));
            return Ok(None);
        }
    };
    let ctype = fhir::content_type(f.filetype.as_deref(), Some(&f.name), Some(&bytes));
    Ok(Some((bytes, ctype)))
}

/// A file's bytes, checked against what Salve or its name says it is: a PDF
/// that does not start `%PDF` is not one. A failed check is
/// [`pk_cli_core::Reason::BadRequest`].
pub fn fetch_checked(r: &dyn Reader, f: &Fetchable) -> Result<Vec<u8>, CliError> {
    let bytes = r.file(&f.uri, f.conversation)?;
    if bytes.is_empty() {
        return Err(CliError::NotFound(format!("Salve served {} empty", f.id)));
    }
    let ctype = fhir::content_type(f.filetype.as_deref(), Some(&f.name), None);
    let ext = match ctype.as_str() {
        "application/pdf" => Some("pdf"),
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/tiff" => Some("tiff"),
        _ => None,
    };
    if let Some(ext) = ext {
        pk_cli_documents::verify_download(&bytes, Some(ext))
            .map_err(|e| CliError::Upstream(e.message().to_string()).because(pk_cli_core::Reason::BadRequest))?;
    }
    Ok(bytes)
}

/// The pull: the stream's header, then each list's resources, then the
/// trailer. An error after the header ends the stream with `complete:
/// false` and is handed back beside it; `Err` is a failure to write.
pub fn export<W: Write>(
    r: &dyn Reader,
    out: W,
    header: &Header,
    ctx: &Ctx,
    who: &Who,
    now: &str,
) -> Result<(Finished, Tally, Option<CliError>), CliError> {
    let mut w = RecordsWriter::start(out, header)?;
    let mut tally = Tally::default();
    let result = write_all(r, &mut w, header.since.as_deref(), ctx, who, now, &mut tally);
    let finished_at = crate::app::now_rfc3339();
    let finished = w.finish(finished_at, result.as_ref().err())?;
    Ok((finished, tally, result.err()))
}

fn put<W: Write>(w: &mut RecordsWriter<W>, v: &Value) -> Result<(), CliError> {
    let raw = RawResource::parse(&v.to_string())
        .map_err(|e| CliError::Other(format!("a mapped resource does not read back: {e}")))?;
    w.resource(&raw)?;
    Ok(())
}

fn write_all<W: Write>(
    r: &dyn Reader,
    w: &mut RecordsWriter<W>,
    since: Option<&str>,
    ctx: &Ctx,
    who: &Who,
    now: &str,
    tally: &mut Tally,
) -> Result<(), CliError> {
    put(
        w,
        &fhir::patient(
            ctx,
            &who.patient_id,
            who.full_name.as_deref(),
            who.first_name.as_deref(),
            who.last_name.as_deref(),
            who.birth_date.as_deref(),
        ),
    )?;

    // Documents the clinic sent, and files on the record.
    for (op, prefix, kind, category) in [
        (&queries::DOCUMENTS, "doc", "Document", "document"),
        (&queries::FILES, "file", "File", "file"),
    ] {
        let items = match me_documents(r, op) {
            Ok(v) => v,
            Err(e) => {
                skip_list(w, e, op.name, &format!("{category}s"))?;
                continue;
            }
        };
        for d in &items {
            if !keep(since, d.sentdate.as_deref().and_then(fhir::day).as_deref()) {
                tally.before_since += 1;
                continue;
            }
            let fetched = match fetchable(prefix, category, d) {
                Some(f) => {
                    let rid = f.id.clone();
                    fetch(r, w, &f, ("DocumentReference", &rid))?
                }
                None => None,
            };
            if let Some(doc) = fhir::document(ctx, prefix, kind, d, fetched.as_ref().map(|(_, t)| t.as_str())) {
                put(w, &doc)?;
                if let Some((bytes, ctype)) = &fetched {
                    put(w, &fhir::binary(doc["id"].as_str().unwrap_or_default(), ctype, bytes))?;
                }
            }
        }
    }

    // Forms: the list, then each one the patient has answered.
    match r.query(&queries::FORMS, &json!({})) {
        Ok(a) => {
            let list: FormsAnswer = model::read(a.data, "forms")?;
            for f in list.me.unwrap_or_default().forms {
                let (Some(id), Some(pfid), Some(version)) = (f.id.clone(), f.patientformid.clone(), f.version.clone())
                else {
                    continue;
                };
                if f.progress_status
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case("NotStarted"))
                {
                    continue;
                }
                // Salve's FormInput takes the two numbers as integers; the
                // list answers them as integers too.
                let number = |s: &str| s.parse::<i64>().map_or_else(|_| json!(s), |n| json!(n));
                let input =
                    json!({ "input": { "id": id, "patientformid": number(&pfid), "version": number(&version) } });
                let form = match r.query(&queries::FORM, &input) {
                    Ok(a) => model::read::<FormAnswer>(a.data, "a form")?.me.and_then(|m| m.form),
                    Err(e) => {
                        skip_list(w, e, &format!("GetForm?patientformid={pfid}"), "this form")?;
                        continue;
                    }
                };
                let Some(form) = form else { continue };
                let Some(sub) = form.latestsubmission.clone().filter(|s| !s.submission.is_null()) else {
                    continue;
                };
                let rid = format!("form-{pfid}-{version}");
                let kept = json!({
                    "name": form.name,
                    "type": form.kind,
                    "version": form.version,
                    "progressStatus": f.progress_status,
                    "definition": form.definition,
                    "submission": sub.submission,
                    "issubmitted": sub.issubmitted,
                });
                let bytes = serde_json::to_vec(&kept).map_err(|e| CliError::Other(format!("writing a form: {e}")))?;
                put(w, &fhir::form_document(ctx, &rid, &form, f.progress_status.as_deref()))?;
                put(w, &fhir::binary(&rid, "application/json", &bytes))?;
            }
        }
        Err(e) => skip_list(w, e, queries::FORMS.name, "forms")?,
    }

    // Messages, with their attachments.
    match messaging(r) {
        Ok((m, gaps)) => {
            for (search, code, why) in gaps {
                w.skip(Skip::search(search, code, why));
            }
            write_messages(r, w, since, ctx, who, m, tally)?;
        }
        Err(e) => skip_list(w, e, "conversations", "messages")?,
    }

    // Video visits: those before now, newest first, then those after.
    let mut seen = BTreeSet::new();
    for (op, order) in [("LTE", "DESC"), ("GTE", "ASC")] {
        let mut page = 1;
        loop {
            let input = json!({ "input": { "date": now, "order": order, "dateOperator": op, "page": page, "size": VIDEO_PAGE } });
            let calls: Vec<VideoCall> = match r.query(&queries::VIDEO_CALLS, &input) {
                Ok(a) => {
                    model::read::<VideoCallsAnswer>(a.data, "video visits")?
                        .me
                        .unwrap_or_default()
                        .video_calls
                }
                Err(e) => {
                    skip_list(w, e, &format!("GetVideoCalls?dateOperator={op}"), "video visits")?;
                    break;
                }
            };
            let got = calls.len() as i64;
            let mut new = 0;
            for v in &calls {
                let Some(id) = v.id.clone() else { continue };
                if !seen.insert(id) {
                    continue;
                }
                new += 1;
                if !keep(since, v.startdate.as_deref().and_then(fhir::day).as_deref()) {
                    tally.before_since += 1;
                    continue;
                }
                if let Some(e) = fhir::video_encounter(ctx, v, now) {
                    put(w, &e)?;
                }
            }
            if got < VIDEO_PAGE || new == 0 {
                break;
            }
            page += 1;
            if page > VIDEO_PAGES {
                w.skip(Skip::search(
                    format!("GetVideoCalls?dateOperator={op}"),
                    skip::PAGE_CAP,
                    format!("pages past {VIDEO_PAGES} of {VIDEO_PAGE} were left"),
                ));
                break;
            }
        }
    }
    Ok(())
}

fn write_messages<W: Write>(
    r: &dyn Reader,
    w: &mut RecordsWriter<W>,
    since: Option<&str>,
    ctx: &Ctx,
    who: &Who,
    m: Messaging,
    tally: &mut Tally,
) -> Result<(), CliError> {
    match m {
        Messaging::V3(list) => {
            for (c, messages) in &list {
                let Some(conv) = c.id else { continue };
                let subject = c
                    .subject
                    .clone()
                    .or_else(|| c.conversation_folder.as_ref().and_then(|f| f.name.clone()));
                for m in messages {
                    if m.deleted_date.as_deref().is_some_and(|d| !d.trim().is_empty())
                        || m.system_message_type.is_some()
                    {
                        continue;
                    }
                    let Some(id) = m.id.clone() else { continue };
                    if !keep(since, m.sent_date.as_deref().and_then(fhir::day).as_deref()) {
                        tally.before_since += 1;
                        continue;
                    }
                    let from_patient = m.patient.as_ref().and_then(|p| p.id.as_deref())
                        == Some(who.patient_id.as_str())
                        || (m.clinic_user.is_none() && m.patient.is_some());
                    let msg_id = format!("cmsg-{id}");
                    let mut docs = Vec::new();
                    let mut files = Vec::new();
                    for a in &m.attachments {
                        let (Some(att), Some(url)) = (fhir::attachment_v3_id(a), a.url.clone()) else {
                            continue;
                        };
                        let f = Fetchable {
                            id: att.clone(),
                            name: a.file_name.clone().unwrap_or_else(|| att.clone()),
                            category: "message-attachment",
                            date: None,
                            filetype: a.file_type.clone(),
                            uri: url,
                            conversation: Some(conv),
                        };
                        if let Some((bytes, ctype)) = fetch(r, w, &f, ("DocumentReference", &att))? {
                            docs.push(att.clone());
                            files.push((att, a.file_name.clone(), bytes, ctype));
                        }
                    }
                    if let Some(c) = fhir::communication_v3(ctx, conv, subject.as_deref(), m, from_patient, &docs) {
                        put(w, &c)?;
                    }
                    for (att, name, bytes, ctype) in &files {
                        put(
                            w,
                            &fhir::attachment_document(
                                ctx,
                                att,
                                name.as_deref(),
                                &msg_id,
                                m.sent_date.as_deref(),
                                ctype,
                            ),
                        )?;
                        put(w, &fhir::binary(att, ctype, bytes))?;
                    }
                }
            }
        }
        Messaging::V0(list) => {
            for (conv, kind, messages) in &list {
                for m in messages {
                    if m.deleted == Some(true) {
                        continue;
                    }
                    let Some(id) = m.id.clone() else { continue };
                    if !keep(since, m.sent.as_deref().and_then(fhir::day).as_deref()) {
                        tally.before_since += 1;
                        continue;
                    }
                    let msg_id = format!("msg-{id}");
                    let mut docs = Vec::new();
                    let mut files = Vec::new();
                    for f in &m.metadata {
                        let (Some(att), Some(url)) = (fhir::meta_id(f), f.url.clone()) else {
                            continue;
                        };
                        let fe = Fetchable {
                            id: att.clone(),
                            name: f.filename.clone().unwrap_or_else(|| att.clone()),
                            category: "message-attachment",
                            date: None,
                            filetype: f.filetype.clone(),
                            uri: url,
                            conversation: Some(*conv),
                        };
                        if let Some((bytes, ctype)) = fetch(r, w, &fe, ("DocumentReference", &att))? {
                            docs.push(att.clone());
                            files.push((att, f.filename.clone(), bytes, ctype));
                        }
                    }
                    if let Some(c) = fhir::communication_v0(ctx, *conv, kind.as_deref(), m, &docs) {
                        put(w, &c)?;
                    }
                    for (att, name, bytes, ctype) in &files {
                        put(
                            w,
                            &fhir::attachment_document(ctx, att, name.as_deref(), &msg_id, m.sent.as_deref(), ctype),
                        )?;
                        put(w, &fhir::binary(att, ctype, bytes))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// The resource types a pull writes undated, so `--since` leaves them in.
pub const SINCE_UNBOUNDED: &[&str] = &["Patient", "DocumentReference", "Binary"];
