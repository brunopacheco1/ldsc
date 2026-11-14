<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Reading Portitor's Rust

A short guide to the Rust patterns that Portitor uses, for people who read
Rust only now and then. Each section shows the pattern, what it means in
plain words, and where the code uses it. It is not a Rust course. For
that, see [The Rust Book](https://doc.rust-lang.org/book/).

The code aims to be plain. When a pattern below would hide what the code
does, write the longer form instead. Clippy's `pedantic` lints are on
(`Cargo.toml`), and some of them ask for the short forms, so a few of
these patterns are there because the linter asks for them.

## Values and references

| You see | It means |
|---------|----------|
| `String` | Text that this value owns. |
| `&str` | Borrowed text: read it, don't keep it. |
| `&x` | Borrow `x` to read it. |
| `&mut x` | Borrow `x` to change it. Only one such borrow at a time. |
| `x.clone()` | Make an independent copy. |
| `x.to_owned()`, `x.into()` | Turn borrowed data into owned data, or one type into another. |

## `Option` and `Result`

Rust has no `null` and no exceptions. Instead:

- `Option<T>` is either `Some(value)` or `None`.
- `Result<T, E>` is either `Ok(value)` or `Err(error)`.

A function that can fail returns a `Result`. The caller must look at it.
The compiler will not let you forget.

## The `?` operator

```rust
let negotiation = self.load(provider_pid, "", caller)?;
```

"If this is an error, return the error from this function now.
Otherwise, take the value out and go on." It only works inside a
function that itself returns a `Result` (or an `Option`). `x??` does
this twice, for a `Result` inside a `Result`. `serve.rs` (in
`portitor-runtime`) waits for a background task, which can fail, and then
for the server's own result, which can fail too.

### `?` that converts the error

```rust
impl From<rusqlite::Error> for StoreError { /* ... */ }

let mut rows = stmt.query([])?;   // a rusqlite::Error becomes a StoreError
```

`?` also changes the error's type when the function returns another
error type and a `From` conversion between the two exists
(`portitor-identity/src/store.rs`). So `?` can hide a conversion: look
for the `impl From`. With `thiserror`, `#[from]` writes that `impl`:

```rust
pub enum CredentialError {
    #[error(transparent)]
    Jws(#[from] Error),       // `?` on a JWS error gives CredentialError::Jws
    /* ... */
}
```

### A function name in `map_err`

```rust
tx.execute_batch(sql).map_err(sql_error)?;
```

`map_err` takes any function, not only a closure: `map_err(sql_error)`
is the same as `map_err(|e| sql_error(e))` (`portitor-runtime/src/sqlite.rs`).
A tuple struct's name is a function too: `.map_err(StoreError)` wraps the
text in a `StoreError`.

## `match`, `if let`, `let ... else`

```rust
match handled {
    Ok((ack, next)) => { /* use ack and next */ }
    Err(failure) => failed(failure),
}
```

`match` checks a value against each pattern in order and runs the first
one that fits. The compiler checks that every case is covered.
`Some(old) if old.version == expected =>` adds a condition (a
"guard") to a pattern.

```rust
if let Some(sent) = negotiation.pending.clone() { /* ... */ }
```

`if let` is a `match` with one interesting case: "if this is a `Some`,
call its content `sent`".

```rust
let Some(token) = bearer(&headers) else {
    return unauthorized();
};
```

`let ... else` says "this must be a `Some`; if not, leave now". After it,
`token` is a plain value (`data_plane.rs`).

```rust
if let Some(participant) = caller
    && transfer.counter_party != participant
{ /* ... */ }
```

A *let chain* (Rust 2024): `if let` and other conditions joined with
`&&`. The body runs only if all of them hold (`transfer/provider.rs`).

## More patterns

```rust
let [subject] = credential.subjects.as_slice() else {
    return Err(StatusError::NotAList("not exactly one subject"));
};
```

A *slice pattern* matches a list by its shape: `[only]` is "exactly one
item, call it `only`", `[]` is "empty", `[first, ..]` "at least one"
(`status_list.rs`; `DidDocument::key_for` in `did.rs` matches `[only]`,
`[]` and `_`).

```rust
Err(e @ QueryError::DefinitionNotSupported) => { /* use e */ }
```

`name @ pattern` checks the pattern and also gives the whole matched
value a name (`portitor-identity/src/presentation.rs`).

```rust
let Delivery {
    issuer,
    access_token,
    message,
} = delivery;
```

A *struct pattern* takes a value apart into its fields, each in a
variable of the same name (`portitor-identity/src/storage.rs`). In a
`match`, `Mode::Evaluate { now, .. }` takes only `now` and ignores the
rest (`..`, `policy.rs`). A pattern can also give a field another name,
`Caller { id: caller, .. }`, which reads like a type annotation, so
Portitor avoids it.

```rust
if matches!(mode, Mode::Validate(_)) { /* ... */ }
```

`matches!(value, pattern)` is `true` if the value fits the pattern: a
`match` with one case that answers yes or no (`policy.rs`;
`consumer.rs` checks `Transition::Request | Transition::Accept`).

```rust
while let Some(row) = rows.next()? {
    found.push(credential_from(row)?);
}
```

`while let` repeats while the pattern fits: here, "while there is
another row" (`portitor-identity/src/store.rs`). `JtiCache` uses it with a
let chain to drop expired token ids from the front of a sorted set.

## Building values

```rust
TokenFrame {
    jti: &new_uuid(),
    ..frame
}
```

*Struct update*: a new `TokenFrame` with its own `jti`, and every other
field copied from `frame` (`portitor-identity/src/sts.rs`). Tests often
write `..DidDocument::default()` for "all other fields empty".

```rust
let claims = serde_json::from_value::<ContractNegotiation>(state)
```

`::<T>` (the *turbofish*) tells a generic function which type to
produce, when nothing else in the line says it. Writing the type on the
variable does the same and is often easier to read:
`let claims: ContractNegotiation = serde_json::from_value(state)`.

```rust
let jwts: Result<Vec<String>, Error> = items.iter().map(parse).collect();
```

`collect()` into a `Result<Vec<_>, _>` gathers the values and stops at
the first error. It is short, but an early `return` inside the closure
then returns from the closure, not from the function, which reads
wrongly. Portitor writes a plain loop instead (`credentials_of` in
`credential.rs`).

## Closures: `|x| ...`

```rust
.map_err(|e| bad("", &consumer_pid, &e.to_string()))
```

`|e| ...` is a small function without a name. It takes `e` and returns
what follows. `|| ...` takes nothing. `move || ...` takes ownership of the
variables it uses, which background tasks need.

Closures are often passed to helpers on `Option` and `Result`:

| Helper | Plain words |
|--------|-------------|
| `x.map(\|v\| ...)` | If there is a value, change it. |
| `x.map_err(\|e\| ...)` | If it is an error, change the error. |
| `x.and_then(\|v\| ...)` | If there is a value, run a step that may fail or return nothing. |
| `x.ok_or_else(\|\| err)` | Turn `None` into the error `err`. |
| `x.unwrap_or_default()` | The value, or the empty default (`""`, `0`, ...). |
| `x.unwrap_or_else(\|\| ...)` | The value, or compute a replacement. |
| `x.is_some_and(\|v\| ...)` | There is a value, and the test holds for it. |
| `x.is_none_or(\|v\| ...)` | There is no value, or the test holds for it. |
| `x.filter(\|v\| ...)` | Keep the value only if the test holds. |
| `x.transpose()` | Swap `Option<Result<T>>` and `Result<Option<T>>`. |
| `.iter().any(\|v\| ...)` | At least one item passes the test. |
| `.into_iter().filter_map(\|v\| ...).collect()` | Keep the items the closure returns `Some` for, and gather them in a list. |

A function can take a closure as an argument: `change: impl
Fn(&mut Negotiation) -> Result<Write, Failure>` means "any function that
takes a negotiation it may change". The domain services use this for
their read, change, compare-and-write loop (`update`) and pass the change
in. That way the loop is written only once.

There are three kinds of function arguments. `Fn` may be called any
number of times and changes nothing it captured; `FnMut` may change
what it captured (so it is passed as `&mut`); `FnOnce` is called at most
once (`admit: impl FnOnce(&Claims) -> bool` in
`portitor-runtime/src/caller.rs`).

```rust
pub type SignCredentials<'a> = dyn FnMut(&[u64]) -> Result<SignedRequest, String> + 'a;

fn issue(&self, /* ... */ sign: &mut SignCredentials<'_>) -> Result<IssueOutcome, StoreError>;
```

A `type` alias gives a long function type a name. `SignCredentials` is
"a function that gets the chosen status list positions and returns the
signed credentials". The issuer's store calls it in the middle of its
transaction, after it has picked the positions and before it writes
anything, so a position is used only if the credentials are written
(`portitor-issuer/src/store.rs`). `dyn` because the store is a port: it
takes any such function, chosen while the program runs.

Never write `.unwrap()` outside tests. It stops the program when the
value is missing, and the linter refuses it.

## Traits: ports and adapters

A `trait` lists methods that a type promises to have, like an interface.
Every port (ADR 0004) is a trait, for example `NegotiationStore`, and
every adapter implements it (`impl NegotiationStore for
SqliteNegotiations`).

```rust
pub struct ProviderService<S, D, C, E> { /* ... */ }
impl<S: NegotiationStore, D: Decider, C: DatasetStore, E: Environment> ProviderService<S, D, C, E>
```

The service is *generic*. `S` is "some type that implements
`NegotiationStore`". The domain crates never name an adapter.

`dyn NegotiationStore` is "a value of some type that implements
`NegotiationStore`, decided while the program runs". The connector picks
its adapters at start (in memory for tests, SQLite for real use), so it
keeps each one as `Shared<dyn Port + Send + Sync>`. `Shared` wraps an
`Arc` pointer. See `ports.rs`, which explains why the wrapper exists and
holds all the `Any...` names.

```rust
fn scopes(&self, _out: &Self::Out) -> Vec<String> {
    Vec::new()
}
```

A trait method can have a body: a *default*. A type that implements the
trait may write its own version or keep the default. The connector's
`Outbox` trait answers "no extra scopes" by default; the consumer's
outboxes write their own (`outbox.rs`, `consumer.rs`). A name starting
with `_` says the default does not use that argument.

```rust
fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, StoreError>
fn to_json(value: &impl serde::Serialize) -> Result<String, StoreError>
```

A generic helper says what it needs of its type: `T: DeserializeOwned`
is "any type serde can read from JSON", `&impl Serialize` "a borrowed
value of any type serde can write" (`portitor-issuer/src/store.rs`). A
struct can be generic too: `NewCredential<'a, C>` holds `claims: &'a C`,
and `sign_credential<C: Serialize>` accepts it for any claims that
serialize to JSON (`portitor-dcp/src/issuance.rs`).

```rust
authenticate(headers, audience, registered, &*issuer.directory).await
```

`issuer.directory` is an `Arc<dyn Directory>`, a shared pointer. `*`
follows the pointer to the directory and `&` borrows it, so `&*` gives
the `&dyn Directory` that `authenticate` asks for, without copying or
taking the pointer (`portitor-issuer/src/requests.rs`).

```rust
pub fn subject_ids(&self) -> impl Iterator<Item = &str> {
```

`impl Iterator<Item = &str>` as a return type: "something you can loop
over that gives `&str` values". The exact type is long and does not
matter to the caller, who writes `for id in credential.subject_ids()`
(`portitor-dcp/src/credential.rs`; `CredentialTypes::iter` in
`policy/credentials.rs`).

`use base64::Engine as _;` brings a trait into scope without a name:
its methods (here `B64.encode(...)` and `.decode(...)`) can be called,
but the name `Engine` is not used in the file. Rust only lets you call a
trait's methods when the trait is in scope.

`Arc::clone(store) as _` (in `Ports::use_sqlite`) makes a new pointer to
the same store. `as _` lets the compiler turn it into the `dyn` type the
field expects.

## Sharing between threads: `Arc` and `Mutex`

- `Arc<T>` is a pointer that many owners share. `Arc::clone` copies the
  pointer, not the value.
- `Mutex<T>` lets one thread at a time change `T`. `lock()` waits for
  your turn.
- `lock().unwrap_or_else(PoisonError::into_inner)` keeps going even if
  another thread panicked while it held the lock. Each place that does
  this says in a comment why it is safe there.
- `lock()` returns a *guard*; the lock is held until the guard is
  dropped. `let _one_at_a_time = ...lock()...;` keeps the guard in a
  named variable, so the lock is held until the end of the function
  (`refresh` in `portitor-issuer/src/status_lists.rs`). `let _ =
  ...lock()...;` would drop it, and free the lock, at once: the leading
  `_` in a name keeps the value, the bare `_` does not.
- `Send` and `Sync` in a type mean "safe to move to, or share with,
  another thread". The web server needs them.
- `mutex.try_lock()` takes the lock only if it is free, and does not
  wait. `let Ok(_running) = self.busy.try_lock() else { ... return }`
  skips a harvest run when another one is going on (`Harvester::run` in
  `portitor-connector/src/harvest.rs`): a timer tick that comes during a
  long run is dropped, not queued.

### A snapshot swapped as a whole: `RwLock<Arc<View>>`

```rust
pub struct ReadCopy(Arc<RwLock<Arc<View>>>);

fn view(&self) -> Arc<View> {
    Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
}
```

`RwLock` lets many readers in at once, or one writer. The value inside
is itself an `Arc`, so a reader holds the lock only to copy that
pointer, then works on its own snapshot without any lock. A harvest run
builds a whole new `View` and swaps the pointer in one write
(`ReadCopy::replace` in `portitor-connector/src/harvest/copy.rs`). A
request never sees half a run, and a slow catalog request never blocks
the next run. The old snapshot is freed when its last reader drops it.

## `SQLite` transactions

```rust
let tx = conn.transaction()?;
let Some(holder_did) = holder_if_received(&tx, issuer_pid)? else {
    return Ok(IssueOutcome::NotReceived);
};
/* ... more checks, then the writes ... */
tx.commit()?;
```

A transaction groups reads and writes so they happen all together or
not at all. In `rusqlite`, a transaction that is dropped without
`commit()` is rolled back: an early `return` or a `?` leaves the file as
it was (`SqliteStore::issue` in `portitor-issuer/src/store.rs`).

`query_row(...)` fails when no row is found. `.optional()?` (from
`rusqlite::OptionalExtension`) turns "no row" into `None` and keeps
other errors as errors: `Option<(String, String)>` is "the row, if there
is one".

## Printing for logs: `Debug`

`#[derive(Debug)]` prints every field. Types that hold secrets or large
values write `Debug` by hand instead:

```rust
impl std::fmt::Debug for DcpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DcpVerifier")
            .field("participant_id", &self.participant_id)
            .finish_non_exhaustive()
    }
}
```

It prints the fields named and `..` for the rest
(`finish_non_exhaustive`), so a key or token never reaches a log
(`auth/dcp.rs`; `SigningKey` in `portitor-dcp/src/keys.rs` prints only
its public key's thumbprint).

## `async`, `.await` and background tasks

`async fn` returns a task that runs when someone `.await`s it. While it
waits on the network, the thread does other work. `tokio::spawn(task)`
runs a task in the background. The outbox uses it to send DSP messages
after the HTTP answer has gone out.

`BoxFuture<'a, T>` (`portitor-runtime/src/lib.rs`) is a boxed task that
finishes later with a `T`. Every port with async methods returns one:
the `Sender`, the connector's `CallerVerifier` and `Prover`, the
`Directory` of the identity component and the issuer. Its comment explains why these traits
cannot use `async fn` directly. Read `BoxFuture<'a, Result<Value,
String>>` as "later, a `Value` or an error". (`AuthFuture` in the
connector is another name for the same thing.)

```rust
tokio::select! {
    _ = tokio::signal::ctrl_c() => {}
    _ = term.recv() => {}
}
```

`tokio::select!` waits for several tasks at once and goes on with the
first that finishes; the others are dropped. Here: stop on Ctrl-C or on
SIGTERM, whichever comes first (`portitor-runtime/src/serve.rs`).

```rust
async fn within_deadline<T>(
    &self,
    what: &str,
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, String>
```

A function can take a task as an argument: `impl Future<Output = X>` is
"a task that finishes with an `X`, not started yet". `T` is any type:
the helper does not care what the task produces. Here it runs `work`
with a time limit (`tokio::time::timeout`), and the connector wraps
every caller check in it (`auth/dcp.rs`).

```rust
tokio::select! {
    () = issuer.outbox.notified() => {}
    () = tokio::time::sleep(wait) => {}
}
```

`tokio::sync::Notify` is a doorbell between tasks: `notify_one()` rings
it, `notified()` waits for a ring. The issuer's outbox sleeps until the
next delivery is due, or until a newly issued request rings
(`portitor-issuer/src/delivery.rs`, `issue.rs`).

## Lifetimes: `'a`

`fn post<'a>(&'a self, url: &'a str, ...) -> BoxFuture<'a, ...>` says "the
returned task borrows `self` and `url`, so it must not outlive them".
Lifetimes don't change what the code does. They let the compiler check
borrows.

A struct can borrow too:

```rust
pub struct TokenFrame<'a> {
    pub audience: &'a str,
    pub jti: &'a str,
    /* ... */
}
```

"A `TokenFrame` holds borrowed text, so it must not outlive the strings
it points to" (`portitor-dcp/src/holder.rs`; also `Jws<'a>`, which keeps a
slice of the token it was read from, and `Signer<'a>` in `keys.rs`). It saves copying
the text for a value that only lives during one call.

## Errors in a `Box`

Many connector functions return `Result<T, Box<Failure>>`. A `Failure`
carries a whole DSP error message, and boxing it keeps every `Result`
small. Clippy's `result_large_err` lint asks for this. Read
`Box<Failure>` as `Failure`.

## Attributes and `derive`

- `#[derive(Debug, Clone, PartialEq)]` asks the compiler to write the
  usual methods: printing for logs, copying, comparing.
- `#[serde(rename_all = "camelCase")]` and `#[serde(rename = "@type")]`
  map Rust field names to JSON names. `skip_serializing_if =
  "Option::is_none"` leaves out empty fields.
- `#[serde(deny_unknown_fields)]`: refuse JSON with a field the type
  does not have, instead of ignoring it (the management APIs' request
  types, so a typo is an error).
- `#[serde(default)]`: a missing field gets its empty default (`[]`,
  `""`, `false`); `default = "pull_format"` calls that function instead
  (`portitor-connector/src/management.rs`).
- `#[serde(flatten)]`: the fields of this value sit at the same level
  as the others in the JSON, not inside a field of their own (`Dataset`
  keeps every other metadata property this way, `portitor-dsp/src/lib.rs`).
- `#[serde(untagged)]` on an enum: try each variant in turn and take the
  first that fits the JSON. `Relationship` in `did.rs` is a key id string
  or a whole key object.
- `#[serde(tag = "kty")]`: the JSON field `kty` says which variant it is
  (`Jwk`: `"EC"` or `"RSA"`).
- `#[serde(deserialize_with = "one_audience")]`: read this field with
  the named function instead of the default (`Claims::aud` in
  `id_token.rs` accepts a string or a list of one).
- `Messages {}` instead of `Messages` in an enum read by serde:
  `deny_unknown_fields` refuses extra fields only in variants written
  with braces, so `{"type": "messages", "extra": 1}` is an error
  (`Role` in `portitor-dcp/src/bundle.rs`). The empty braces are on
  purpose.
- `serde_json::value::RawValue`: JSON kept as the exact text it was read
  from, and written out unchanged. `sign_manifest` in
  `portitor-dcp/src/bundle.rs` signs the manifest's bytes this way, so
  the signature covers exactly the file that is published, not a copy
  that serde wrote again (with other spaces or field order).
- `#[must_use]`: the caller should use the return value.
- `#[cfg(test)]`: compiled only for tests. `#[cfg(feature = "tck")]`:
  compiled only in the DSP TCK build.
- `#[allow(clippy::...)]`: switches off one lint here. A comment says
  why.

## Macros: `name!(...)`

A name with `!` is a macro: code that writes code at compile time.
`format!`, `vec!` and `tracing::info!` come from libraries. Portitor
defines four: `type_tag!`, `pid_message!` and `process_ack!` in
`portitor-dsp/src/lib.rs`, and `type_name!` in
`portitor-dcp/src/message.rs`. They declare the many DSP and DCP message
types without copying the same fields into each one. Each has a comment
with an example of what it writes. (A few test files define small macros
of their own, for example `schema!`.)

Some macros are written as attributes, `#[name]` or `#[name(...)]`, and
rewrite the item below them:

- `#[tokio::main]` on `async fn main` starts the async runtime and runs
  `main` in it (each `main.rs`).
- `#[utoipa::path(post, path = "/v1/credential-requests", ...)]` on a
  handler describes it for the OpenAPI document; it does not change
  what the handler does (`management.rs`).
- `#[derive(ToSchema)]` writes the OpenAPI schema of a request or answer
  type, as `#[derive(Serialize)]` writes its JSON.

## Web handlers (axum)

```rust
pub(crate) async fn token(
    State(identity): State<Arc<Identity>>,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Response {
```

axum fills each argument of a handler from the request (an
*extractor*): `State(identity)` from the router's shared state, `Form`
from the form body. Normally a body that cannot be read is refused by
axum itself, with its own answer. Taking `Result<Form<...>, ...>`
instead lets the handler see the failure and answer in the format the
API needs (here the STS error list, `portitor-identity/src/sts.rs`).

## Small things

- `let _ = x;` ignores a result on purpose. A comment says why that is
  safe.
- `impl Trait` in an argument (`var: impl Fn(&str) -> Option<OsString>`)
  means "any type that implements `Trait`".
- `pub(crate)` is visible inside this crate only.
- `Self` is the type the `impl` is for.
- `x.wrapping_add(1)` adds one and wraps around at the maximum instead of
  stopping the program. Used for version counters.
- `cond.then_some(value)`: `Some(value)` if `cond` is true, else
  `None` (`status_url` in `portitor-identity/src/issuance.rs`).
- `a.saturating_sub(b)` stops at 0 instead of going below;
  `1_u64.checked_shl(n)` is `1 << n`, or `None` when `n` is too large
  (`retry_delay` in `portitor-issuer/src/delivery.rs`).
- `[Profile; 2]` is a list of exactly two `Profile`s, fixed when the
  program is built (`PROFILES` in `status_lists.rs`).
- `env!("CARGO_PKG_VERSION")` is the crate's version from `Cargo.toml`,
  read when the program is built (the `OpenAPI` documents).
- `!` on an integer flips every bit, it is not "not": `!0u32` is
  `0xFFFF_FFFF` (CRC-32 in `gzip.rs`). On a `bool`, `!` is "not".
- `static BOOLEAN: LazyLock<Option<Regex>> = LazyLock::new(|| ...)`: a
  value built the first time it is used, then shared by every thread for
  the rest of the program (the XSD patterns in
  `portitor-shacl/src/lexical.rs`). A regular expression is compiled
  once, not on every check.
- `list.sort_by_cached_key(f)` sorts by `f(item)` but calls `f` only
  once per item; `sort_by_key` may call it many times. Worth it when the
  key is costly to make, such as the text of an RDF term
  (`portitor-shacl/src/validate.rs`, which sorts so that reports come
  out in the same order every time).
- `Option` values can be compared, and `None` counts as smaller than any
  `Some`, so `a.max(b)` of two `Option`s picks a `Some` over a `None`.
  That is easy to misread, so Portitor spells it out with a `match`
  (`later` and `earlier` in `credential.rs`).
