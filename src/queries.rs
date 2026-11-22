//! The GraphQL queries salve sends: the selections Salve's web app makes,
//! read from its code, with `__typename` where an answer mixes types and
//! without the app's client-only fields (`@client`). Reads only; every one
//! passes [`crate::salve::check_read`], which a test asserts.

/// Where a query goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// `mobile.salvehealth.co/app/graphql`: the app's API.
    App,
    /// `salve-api.salvehealth.co/patient/graphql`: the patient API the
    /// newer messaging reads, with the clinic's token beside the sign-in.
    Patient,
}

impl Host {
    pub fn name(self) -> &'static str {
        match self {
            Host::App => "app",
            Host::Patient => "patient",
        }
    }
}

pub struct Op {
    pub name: &'static str,
    pub host: Host,
    pub document: &'static str,
}

/// The signed-in patient and their clinic.
pub const PATIENT_AND_CLINIC: Op = Op {
    name: "GetPatientAndClinic",
    host: Host::App,
    document: "query GetPatientAndClinic { me { email name patientid } clinic { _id name } }",
};

/// The patient's name.
pub const PATIENT_ID: Op = Op {
    name: "GetPatientId",
    host: Host::App,
    document: "query GetPatientId { me { patientid firstname lastname } }",
};

/// The clinics the account belongs to; `selected` is the one the app shows.
pub const PATIENT_CLINICS: Op = Op {
    name: "GetPatientClinics",
    host: Host::App,
    document: "query GetPatientClinics { clinics { _id name fullsynccomplete selected } }",
};

/// Documents the clinic sent.
pub const DOCUMENTS: Op = Op {
    name: "GetDocuments",
    host: Host::App,
    document: "query GetDocuments { me { patientid documents { id name uri readdate filetype sentdate uuid } } }",
};

/// Files on the patient's record (the app names them with aliases).
pub const FILES: Op = Op {
    name: "GetFiles",
    host: Host::App,
    document: "query GetFiles { me { patientid files { id name: filename uri: url filetype sentdate: date uuid } } }",
};

/// The forms assigned to the patient.
pub const FORMS: Op = Op {
    name: "GetForms",
    host: Host::App,
    document: "query GetForms($input: FormsInput) { me { patientid forms(input: $input) { clinicid id name \
               nextFormPage patientformid progressStatus type version } } }",
};

/// One form: its definition and the patient's latest answers.
pub const FORM: Op = Op {
    name: "GetForm",
    host: Host::App,
    document: "query GetForm($input: FormInput!) { me { patientid form(input: $input) { id clinicid patientformid \
               version name type definition latestsubmission { id version submission issubmitted } } } }",
};

/// Video visits, a page at a time from a date, before or after it.
pub const VIDEO_CALLS: Op = Op {
    name: "GetVideoCalls",
    host: Host::App,
    document: "query GetVideoCalls($input: VideoCallsInput) { me { patientid videoCalls(input: $input) { \
               __typename ... on VideoCall { id name host title description clinictimezone startdate enddate \
               duration allowedduration ispartnerinvited } } } }",
};

/// The first messaging's conversations (the app's API).
pub const CONVERSATIONS_V0: Op = Op {
    name: "FetchConversations",
    host: Host::App,
    document: "query FetchConversations($preferredLanguageCode: String) { me { patientid \
               conversations(preferredlanguagecode: $preferredLanguageCode) { id preferredlanguagecode \
               conversationtype conversationtypeid latest { sent } } } }",
};

/// One conversation of the first messaging, with its messages.
pub const CONVERSATION_V0: Op = Op {
    name: "GetConversation",
    host: Host::App,
    document: "query GetConversation($conversationId: Int!, $preferredLanguageCode: String) { me { patientid \
               conversationV2(input: { id: $conversationId, preferredlanguagecode: $preferredLanguageCode }) { \
               conversationtype conversationtypeid id isreadonly preferredlanguagecode messages { __typename \
               ... on MessageGroup { content deleted frompatient read sender sent type uuid messages { \
               ...MessageItem } } ... on Message { ...MessageItem } } } } } \
               fragment MessageItem on Message { clinicuserid content deleted frompatient groupid id metadata { \
               __typename ... on MessageFileMetadata { filename filetype id type url uuid } } read sender sent \
               type uuid }",
};

/// The newer messaging's conversations (the patient API).
pub const CONVERSATIONS_V3: Op = Op {
    name: "GetConversations",
    host: Host::Patient,
    document: "query GetConversations($cursor: String, $limit: Int, $language: String) { conversations(cursor: \
               $cursor, limit: $limit, language: $language) { cursor records { id subject isStarred conversationStatus \
               conversationType conversationFolder { id name } } } me { id } }",
};

/// One conversation of the newer messaging, a page of messages at a time.
pub const MESSAGES_V3: Op = Op {
    name: "GetConversationMessages",
    host: Host::Patient,
    document: "query GetConversationMessages($language: String, $conversationId: Int!, $limit: Int, $cursor: \
               String) { conversationMessages(language: $language, conversationId: $conversationId, limit: $limit, \
               cursor: $cursor) { cursor records { id content sentDate deletedDate systemMessageType uuid \
               actionedByPatientId actionedByClinicUserId attachments { fileName fileType url uuid } patient { id \
               firstName lastName } clinicUser { id firstName lastName } } } }",
};

/// Every query salve sends, for the read-only test.
pub const ALL: &[&Op] = &[
    &PATIENT_AND_CLINIC,
    &PATIENT_ID,
    &PATIENT_CLINICS,
    &DOCUMENTS,
    &FILES,
    &FORMS,
    &FORM,
    &VIDEO_CALLS,
    &CONVERSATIONS_V0,
    &CONVERSATION_V0,
    &CONVERSATIONS_V3,
    &MESSAGES_V3,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_query_is_a_read_named_as_sent() {
        for op in ALL {
            crate::salve::check_read(op.document).unwrap_or_else(|e| panic!("{}: {e}", op.name));
            let rest = op
                .document
                .strip_prefix(&format!("query {}", op.name))
                .unwrap_or_default();
            assert!(rest.starts_with([' ', '(']), "{}", op.name);
            assert!(!op.document.contains("@client"), "{}", op.name);
        }
    }
}
