# Fixtures

Every file here is **synthetic**. None is a capture: no Salve traffic was
recorded while salve was built. Each answer is shaped from the selection set
of the query in `src/queries.rs` that asks for it, which is what Salve's web
app sends, and from Amazon Cognito's documented answers for the sign-in. Keys,
nesting and the aliases the queries use (`name: filename`, `uri: url`,
`sentdate: date`) follow the queries exactly; types follow what the web app
reads. Where Salve's real answer differs, the fixture changes with the fix.

The values are dummies:

- the patient is `Jane Example`, `patient@example.com`, patient id `100001`;
- the clinic is `Example Fertility` (`clinic-0001`), its staff `Nurse
  Example`, `Dr Example` and `Billing Example`;
- the masked phone number is `+*******0000`;
- ids are short invented numbers (`2001`, `7101`), and dates are in 2024,
  2025 and 2030;
- the files the stub serves are generated in `tests/common/mod.rs` (a
  minimal PDF and PNG), and none is tracked.

`{SALT}`, `{SRP_B}`, `{SECRET_BLOCK}`, `{USER_ID}`, `{SESSION}`, `{ID}`,
`{ACCESS}`, `{REFRESH}` and `{LINK}` are filled in by the stub per request.

`tests/no_personal_data.rs` checks the identity fields here against these
dummies, and every tracked file for personal-data shapes.
