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
this twice, for a `Result` inside a `Result`. `main.rs` waits for a
background task, which can fail, and then for the server's own result,
which can fail too.

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
- `Send` and `Sync` in a type mean "safe to move to, or share with,
  another thread". The web server needs them.

## `async`, `.await` and background tasks

`async fn` returns a task that runs when someone `.await`s it. While it
waits on the network, the thread does other work. `tokio::spawn(task)`
runs a task in the background. The outbox uses it to send DSP messages
after the HTTP answer has gone out.

`SendFuture<'a>` (`http_client.rs`) is a boxed task. Its comment explains
why the `Sender` trait cannot use `async fn` directly.

## Lifetimes: `'a`

`fn post<'a>(&'a self, url: &'a str, ...) -> SendFuture<'a>` says "the
returned task borrows `self` and `url`, so it must not outlive them".
Lifetimes don't change what the code does. They let the compiler check
borrows.

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

## Small things

- `let _ = x;` ignores a result on purpose. A comment says why that is
  safe.
- `impl Trait` in an argument (`var: impl Fn(&str) -> Option<OsString>`)
  means "any type that implements `Trait`".
- `pub(crate)` is visible inside this crate only.
- `Self` is the type the `impl` is for.
- `x.wrapping_add(1)` adds one and wraps around at the maximum instead of
  stopping the program. Used for version counters.
