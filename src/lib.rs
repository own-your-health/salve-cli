//! `salve`: Salve, the patient app fertility clinics use, for the household
//! medical-records system (health-records/v1). Read-only.

pub mod app;
pub mod auth;
pub mod cli;
pub mod cognito;
pub mod endpoints;
pub mod fhir;
pub mod live;
pub mod model;
pub mod pull;
pub mod queries;
pub mod salve;
pub mod session;
pub mod srp;
