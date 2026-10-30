# Splitting rs-matter into crates

This document describes how `rs-matter` is to be split into several crates, and in which order.
It addresses issue #559: rust-analyzer is hard to use on `rs-matter` itself, because every
`cargo check` re-checks the code generated from the Matter IDL.

The split has two goals:

- Make type-checking after an edit much faster, so that working on `rs-matter` with
  rust-analyzer is comfortable again. This is the main goal, and the measure of success.
- Make the boundaries inside `rs-matter` clearer and enforce them through crate
  dependencies.

## 1. The problem

`rs-matter-codegen` generates about 775K lines (29 MB) of cluster code, which `rs-matter`
includes from its `build.rs` output. The hand-written code is about 170K lines. As measured in
#559, about 86% of what rustc type-checks is generated, and a re-check after any edit takes
about 40 s. Most of that time is incremental-compilation bookkeeping, which grows with the
number of function bodies in the crate. The floor cannot drop while the generated code and
the hand-written code live in the same crate.

The fix is to put the generated code into its own crate, with as few crates as possible
depending on it. Doing so requires untangling the dependencies between the generated code
and the rest of `rs-matter`. While doing that, the rest of `rs-matter` is split along lines
that make sense on their own, rather than into just "the minimum below the generated code"
and "everything else".

Out of scope:

- Error handling. `Error` and `ErrorCode` stay as they are, shared by all crates. Per-crate
  error types are a separate topic.
- Splitting transport, secure channel, sessions, fabrics, ACL, fail-safe and BDX from each
  other (see section 7).
- Behaviour changes. The split moves code and changes some APIs; it does not change what the
  stack does on the wire.
- Separate versions per crate, at least initially. All `rs-matter-*` crates keep sharing one
  version, as `rs-matter`, `rs-matter-macros` and `rs-matter-codegen` do today
  (`version.workspace = true`), and they are released together. A breaking change in any
  one crate is a breaking change for all of them, including crates that did not change at
  all. Independent semantic versioning per crate can be introduced later, if it is ever
  needed.

## 2. What the generated code needs

Each generated cluster module has two halves.

The **handler half** (types, builders, metadata, `ClusterHandler` / `ClusterAsyncHandler`,
the handler adaptors) needs:

- `tlv` and `error`;
- the data model traits and types: `Handler`, `AsyncHandler`, the operation contexts,
  `Reply`, `Cluster`, `Attribute`, `Command`, `Access`, `Quality`, the event emitter traits;
- a few small IM items: the ID and unit aliases (`EndptId`, `FabricIndex`, `Percent`, ...),
  `EventPriority`, the event TLV writer.

The **client half** (request builders on `CmdDataArrayBuilder` and friends, response views,
`<Cluster>ClientView`, `<Cluster>Client`) needs the IM message encoding, and today also
`im::client::ImClient`, `InvokeSender`, `InvokeRespChunk` and `transport::exchange::Exchange`.
It is about 29% of the generated code. It uses only three `ImClient` entry points
(`read_with`, `write_with`, `invoke_with`), two methods on the response chunks (`response`,
`complete`), and one `impl <Cluster>Client for Exchange` per cluster.

The handler half does not need `Exchange` or `Matter` in any generated code. It reaches them
only through the operation context traits, which today expose `matter()` and `exchange()`.
Sections 3 and 4 remove those two links.

## 3. The client half: the `ImTransaction` trait

A trait next to the IM message encoding replaces the concrete `Exchange` in the generated
client code:

```rust
pub trait ImTransaction: Sized {
    type ReadSender: TLVBuilderParent;
    type WriteSender: TLVBuilderParent;
    type InvokeSender: TLVBuilderParent;
    type ReadChunk: ReadChunk;
    type WriteResp: WriteRespHandle;
    type InvokeChunk: InvokeChunk;

    fn read_with<B>(self, build: B)
        -> impl Future<Output = Result<Self::ReadChunk, Error>> + MaybeSend
    where
        B: FnMut(ReadReqBuilder<Self::ReadSender>) -> Result<Self::ReadSender, Error> + MaybeSend;

    // `write_with` and `invoke_with` have the same shape
}

pub trait InvokeChunk: Sized {
    fn response(&self) -> Result<Option<InvokeResp<'_>>, Error>;
    fn complete(self) -> impl Future<Output = Result<Option<Self>, Error>> + MaybeSend;
}
// `ReadChunk` and `WriteRespHandle` follow the same pattern
```

The generated client code becomes generic over it:

```rust
pub struct OnOffClientView<T> { tx: T }
impl<T: ImTransaction> OnOffClientView<T> { pub async fn off(self, endpoint: EndptId) -> ... }
pub trait OnOffClient: ImTransaction { fn on_off(self) -> OnOffClientView<Self> { ... } }
impl<T: ImTransaction> OnOffClient for T {}
pub struct ArmFailSafeResponseHandle<C> { chunk: C }
```

`Exchange` implements `ImTransaction` once, forwarding to the existing free functions in
`im::client`. The full `ImClient` (senders, subscribe, group invoke) stays as it is.

Call sites such as `exchange.on_off().off(1).await` do not change. Code that names
`OnOffClientView<'a>`, `<Cluster>Client<'a>` or the response handles changes, because the
lifetime parameter becomes a type parameter. Flash size should not change, because
`Exchange` is the only implementation; this needs to be confirmed with `bloat-check`.

The returned futures carry `+ MaybeSend`, so that the generic generated `async fn`s can be
proven `Send` with the `send-sync` feature. This is the main risk: the higher-ranked closure
bounds over `T::InvokeSender` may hit rustc limitations. The `send_sync` test and the
work-stealing example show this quickly.

## 4. The handler half: `Matter` and `Exchange` in the contexts

### What the hand-written handlers use them for

19 hand-written handler files call `ctx.matter()`, `ctx.exchange()` or `ctx.accessor()`: all
root-endpoint clusters, plus Scenes, Thermostat and WebRTC Transport Provider. The calls
serve three different needs:

1. **Node state and services**, via `with_state` or `matter()`: the fabric table, the
   fail-safe, the PASE commissioning window, the basic information settings, the RTC,
   transport notifications (session removed, groups changed, commissioning window changed),
   the device attestation and basic information data, the reboot count and boot reason,
   and opening exchanges to peers. This is the same for every operation.
2. **The session the operation arrived on**, via `ctx.exchange().id().session(...)`: PASE
   vs CASE (13 calls), the attestation challenge, the peer node ID, comparing the session
   with the fail-safe or commissioning window opener, and `upgrade_fabric_idx` after AddNOC.
   This differs per operation, but all that is needed to find the session is the
   `ExchangeId`, a 4-byte value.
3. **The `Accessor`**: 18 of 21 calls only read `fab_idx()`, which `ctx.attr()` and
   `ctx.cmd()` already carry. The other three are the ACL handler (peer node ID and auth
   mode) and two admin-privilege checks (Groupcast, ICD Management).

### The change

- The context traits drop `HandlerContext::matter()`, `OperationContext::exchange()` and
  `OperationContext::accessor()`, and gain `OperationContext::exchange_id() -> ExchangeId`.
- `ExchangeId` moves next to the context traits as a plain value. The methods that resolve
  it against `Matter` (`session`, `with_state`, `accessor`; they already take `&Matter` as a
  parameter) become an extension trait on the node side.
- Everything else stays in the contexts: `crypto()`, `kv()`, `metadata()`, `handler()`,
  `buffers()`, `im_stats()`, `notify_fabric_removed()`, `broadcast_lifecycle()`, the change
  notifiers and the event emitters. Only the trait signatures must be free of node types; the
  implementations (`ReadContextInstance` and so on) keep using `Matter` internally. A
  capability can therefore stay in the context as long as it is expressed with types from the
  base crates.
- The system handlers receive `&'a Matter<'a>` when they are built: `root_handler`, the
  `eth/wifi/thread_*_handler` functions and builders, and the standalone handlers (Groups,
  Groupcast, ICD Management, Time Synchronization, OTA Requestor and Provider, Diagnostic
  Logs). `Matter` already exists at that point, because it is passed to
  `InteractionModel::new` next to them. The cost is one pointer per system handler.

The call sites change mechanically:

| Today | After |
|---|---|
| `ctx.exchange().with_state(\|s\| ..)` | `ctx.exchange_id().with_state(self.matter, \|s\| ..)` |
| `ctx.exchange().id().session(&mut state.sessions)` | `ctx.exchange_id().session(&mut state.sessions)` |
| `ctx.matter()`, `ctx.exchange().matter()` | `self.matter` |
| `ctx.accessor()?.fab_idx()?` | `ctx.cmd().fab_idx` / `ctx.attr().fab_idx` |
| other `ctx.accessor()` | `ctx.exchange_id().accessor(self.matter, ..)` |

### The three handlers outside the root endpoint

- **Thermostat** only needs the node's UTC time. A small `utc_time()` accessor in
  `HandlerContext` keeps it free of `Matter`.
- **Scenes** only needs to know whether endpoint E is in group G on fabric F. It receives a
  narrow trait object for this when it is built, defined in `dm-base` and implemented by the
  node.
- **WebRTC Transport Provider** opens exchanges to the requestor and needs the peer node ID,
  so it is built with `&Matter` like the system handlers. An `ImInitiator` trait next to
  `ImTransaction` (open an IM transaction to a fabric/node pair) could remove this later.

The `ReportContext` used by `ReportDataHandler` (the controller side) is not used by
generated code and keeps its `exchange()`.

## 5. Crates

Every crate also depends on `utils`; the table leaves it out after the first row. Line
counts are hand-written lines in the current code.

| Crate | Contents | Lines | Depends on | Used by |
|---|---|---|---|---|
| `rs-matter-utils` | `utils`, without the zbus proxies; `Error`, `ErrorCode` (unchanged) as its `error` module | 8.5K | - | all |
| `rs-matter-tlv` | TLV | 9.1K | - | all below |
| `rs-matter-crypto` | `Crypto` traits, canonical types, rand, backends (by feature), group key derivation | 6.7K | tlv | cert, pairing, dm-base, node, im, dm, onboard |
| `rs-matter-cert` | operational certificates, x509 and CSR, attestation (DAC chain, CD, trust store), `DeviceAttestation` | 7.7K | tlv, crypto | node, dm, onboard |
| `rs-matter-pairing` | QR, manual code and NFC payloads, QR scanning, `BasicCommData` and the passcode types | 2.6K | tlv, crypto | node |
| `rs-matter-im-base` | IM message encoding, protocol constants and opcodes, IDs, `ImTransaction` | 6.9K | tlv | dm-base, dm-clusters, node, im, dm, onboard |
| `rs-matter-dm-base` | data model metadata (`Node`, `Endpoint`, `Cluster`, ...), access, dataver, `Handler` / `AsyncHandler`, context traits, `Reply`, change notifiers, event writer, `LifecycleOp`, `ImStats`, `ExchangeId`, persistence traits | 6.5K | tlv, im-base, crypto | dm-clusters, node, im, dm, onboard |
| `rs-matter-dm-clusters` | generated: types, builders, metadata, handler traits, adaptors, client views; owns the codegen `build.rs` | (775K generated) | tlv, im-base, dm-base | dm, onboard |
| `rs-matter-node` | `Matter` and the node state, transport (exchange, session, MRP, UDP, TCP, BTP, mDNS, OS backends), secure channel, fabrics, ACL, fail-safe, handover, BDX, OTA image, the IM client over `Exchange`, the PICS JSON output | 55K | tlv, crypto, cert, pairing, im-base, dm-base | im, dm, onboard |
| `rs-matter-im` | the IM engine: `InteractionModel`, subscriptions, event queue, invoker, path expansion, busy handling, the responders, the context implementations | 12K | tlv, crypto, im-base, dm-base, node | rs-matter |
| `rs-matter-dm` | all cluster handlers (root endpoint and application), the root endpoint composition, the network commissioning drivers (including NetworkManager, wpa_supplicant and OTBR), `TimeSyncClient` | 60K | tlv, crypto, cert, im-base, dm-base, dm-clusters, node | rs-matter |
| `rs-matter-onboard` | the commissioner | 1.4K | tlv, crypto, cert, im-base, dm-base, dm-clusters, node | rs-matter |
| `rs-matter` | facade; re-exports the crates above under the existing paths | - | all | applications |

`rs-matter-macros` and `rs-matter-codegen` stay as they are.

Only `rs-matter-dm` and `rs-matter-onboard` depend on the generated crate. `rs-matter-node`
and `rs-matter-im` type-check in parallel with it, and an edit to them never re-checks it.

Notes:

- `im-base` and `im`, and `dm-base` and `dm`, pair up: the base crate holds the traits and
  types, the other one the implementation.
- `onboard` uses the generated clients (General Commissioning and Operational Credentials)
  to drive commissioning, so it depends on `dm-clusters` by necessity.
- `crypto` uses `tlv` only so that `CryptoSensitive<N>` implements `FromTLV` / `ToTLV`. This
  lets key material be a field of TLV-persisted structs (fabrics, group key sets, CASE
  resumption records, ICD client registrations, handover data) while it is still cleared on
  drop. The dependency can be removed by giving those structs hand-written TLV impls.
- `rs-matter-pairing` and `rs-matter-onboard` are optional; both could stay in `node`.
- The facade keeps today's paths. In particular, `rs_matter_dm::clusters::on_off` re-exports
  the generated `rs_matter_dm_clusters::on_off::*` next to the handler, as the current
  `dm::clusters::on_off` module does with `decl::on_off::*`.

## 6. Moves needed so that the crate graph has no cycles

Node state that is defined in handler modules today moves to `node`:

- `BasicInfoConfig` and `BasicInfoSettings` (module `basic_info`). `ProductAppearance`
  stays in `BasicInfoConfig`, with small node enums for the finish and the color, so that
  the root endpoint builders keep their signatures. The area type of the device location
  (94 values) is stored as its `u8` value; the handler converts it back.
- `Rtc` (module `rtc`). `UtcTime` is already in `utils`, next to `epoch`.
- `IcdAdvertisement` (module `icd`).
- The Groupcast testing bridge (module `groupcast`).
- `Networks`, `NetworksError`, `WirelessCreds`, the functions that load, store and remove
  networks, and the Thread dataset reader `ThreadTLV` (module `networks`).
  `WirelessCreds::check_match` becomes `NetworkType::check_creds`, because `NetworkType`
  stays with the Network Commissioning handler.
- `BootReason`, next to `Matter`.

The modules keep their old paths through re-exports from the handler modules, for example
`dm::clusters::basic_info::BasicInfoConfig`.

`DeviceAttestation` moves to `cert`, and `BasicCommData` moves to `pairing`. Pairing takes
the vendor and product IDs instead of `BasicInfoConfig`, and the conversion of a QR payload
into an mDNS filter moves to `node`.

The node stops using generated types:

- The ACL table keeps its own entry and enum types (it already has its own `AuthMode`). The
  conversions to and from the generated `AccessControlEntryStruct` move to the ACL handler.
- The node defines its own small enums where it stores a value today typed with a generated
  enum: boot reason, ICD operating mode, multicast address policy, regulatory location type,
  time granularity and time source, product finish and color, and the Groupcast testing
  enums. The values are the same, so persisted data does not change. The handlers in `dm`
  map between the two with plain functions, since `dm` is the only crate that sees both.
- Cluster, attribute and event IDs used for change notifications and events become plain
  constants: Administrator Commissioning, Operational Credentials, Basic Information
  (`ConfigurationVersion`), Time Synchronization (the clock's attributes and its
  `MissingTrustedTimeSource` event), and the StartUp, ShutDown and BootReason events the
  IM engine emits.
- The Linux Wi-Fi and Thread drivers (`transport::network::wifi::{nm, wpa_supp}`,
  `transport::network::thread::otbr`) implement the Network Commissioning and diagnostics
  traits. They move to `dm`, next to those traits, as `dm::networks::wifi::{nm, wpa_supp}`
  and `dm::networks::thread::otbr`.

The data model types stop depending on code above them:

- The conversion between `Privilege` and the generated `AccessControlEntryPrivilegeEnum`
  moves to `dm`.
- The auxiliary ACL feature lookup in `dm/types/node.rs` uses constants instead of the
  generated Access Control metadata.
- The use of `Accessor` in wildcard path expansion moves to the IM engine.
- The root endpoint metadata macros in `dm/types/cluster.rs` move to `dm`.

Smaller items:

- `MessageMeta` moves to the IM encoding; `IMBuffer` and its size constant move to the data
  model types.
- The `ExchangeHandler` trait stays on the node side, because the secure channel and BDX
  implement it. The responders that combine IM, secure channel and BDX move to `im`.
- The event TLV writer and `EVENT_DATA_TAG` move to the data model types; the event queue
  stays in `im`. `ImStats` and `DeviceLoad` move to the data model types.
- `From<bluer::Error> for Error` must live next to `Error` because of the orphan rule, so
  `utils` gets an optional `bluer` dependency, enabled by the node's `bluer` feature. The
  other conversions (`std::io::Error`, `PoisonError`, `SystemTimeError`, `num_enum`) need
  only a `std` feature.
- `Error` and `ErrorCode` are a module of `utils` rather than a crate of their own. They are
  expected to go away with the per-crate errors, and a separate crate would be published
  only to be retired soon after. Nothing depends on them without also depending on `utils`.
- The test device data (`dm::devices::test`) goes to `node`, because it includes a
  `BasicInfoConfig` and a `BasicCommData`. The test DAC private key, which the test crypto
  setup needs, moves to `crypto`.
- The application clusters' unit tests record events with the IM engine's event queue
  (`dm::clusters::app::test_util`). `dm` gets `im` as a dev-dependency for this. There is no
  cycle, because `im` does not depend on `dm`.

## 7. What is not split

Transport, secure channel, sessions, fabrics, ACL, fail-safe and BDX form one dependency
cycle around `Matter`. `Exchange` holds `&Matter`, and `Matter` holds the transport and all
session, fabric, fail-safe and PASE state. `Exchange::initiate` runs the CASE initiator. The
secure channel talks over exchanges and writes the session and fabric tables. The OTA and
Diagnostic Logs clusters use BDX. Separating these needs an `Exchange` that does not know
`Matter`, which is a redesign that #559 does not need. All of this code is hand-written, so
it checks quickly once it is in a crate of its own.

## 8. Mechanics

- **Features.** Each crate declares only the features it uses. `defmt` and `log` go on all
  crates. `send-sync` goes on `utils`, and Cargo's feature unification enables it
  everywhere. The sizing features go on `node`, except `kv-blob-store-*` and
  `large-buffers`, which go on `dm-base`. The crypto backends go on `crypto`. A feature of
  a crate is forwarded to the crates below it which have a feature of the same name. The
  facade forwards all current features, so existing `Cargo.toml` files keep working;
  `async-io`, which used to be the implicit feature of an optional dependency, is kept.
- **Default features.** Each crate has the defaults of the facade, as far as it has those
  features (e.g. `std` and `log`), so that `cargo test -p <crate>` works. The workspace
  entries of the crates turn the defaults off, so a crate never enables `std` in another
  one. The crates whose tests need a crypto backend get `rs-matter-crypto` with
  `rustcrypto` as a dev-dependency.
- **Dependencies.** All dependencies, external and internal, are listed in
  `[workspace.dependencies]` of the root `Cargo.toml`; the crates refer to them with
  `workspace = true` and add only their features.
- **Paths.** A crate that was one module (e.g. `tlv`) has that module as its root, and its
  `crate::tlv::` paths become `crate::`. Each crate imports its dependencies at its root
  under the names the code already uses (`use rs_matter_tlv as tlv;`), so the
  `crate::tlv::...` paths elsewhere do not change. Where a former module is split across
  crates, the crate above has a small module that puts the parts together: the `im`, `dm`
  and `utils` modules of `rs-matter-node` add the IM client, the test device and the zbus
  proxies to the re-exported base crates.
- **Logging macros.** Each crate gets its own copy of `fmt.rs`. A `#[macro_export]` macro
  evaluates `cfg(feature = ...)` in the crate that calls it, so one copy cannot serve all
  crates.
- **Derive macros.** The `proc_macro_crate` lookup in `rs-matter-macros` looks for
  `rs-matter-tlv` first, then for the `rs-matter` facade, and falls back to `crate::tlv`.
  The derives refer to the error type and to the `init` helpers through a hidden
  `rs_matter_tlv::__private` module, so they only need the path to the TLV crate.
- **Codegen paths.** The generated crate imports the base crates under the names `tlv`,
  `dm`, `im`, `error` and `utils`, and has its own `reexport` module, so the generated
  `crate::tlv::...` paths keep working. The generated clusters import the global types
  with `use super::globals::*`, which works both in the generated crate and in the old
  `decl` module, so no new codegen parameter is needed.
- **Generation at build time.** The generated source is too large for crates.io, so
  `rs-matter-dm-clusters` keeps generating it from its `build.rs`. The build time of the
  firmware, which `utils::epoch` needs, is captured by a `build.rs` of `rs-matter-utils`.
- **Coherence.** A crate cannot implement a trait of another crate for a type of a third
  one, nor add inherent methods to a type of another crate. The conversions from the
  errors of `zbus` and BlueR move to `utils`, behind features of the same names.
  The ones from the `domain` (mDNS) and `zeroconf` errors become plain functions used with
  `map_err`. The inherent methods of the handlers on generated types become extension
  traits (`NetworkCommissioningStatusMap` and `AttributeValuePairPush` are public, as
  other modules use them). The TLV methods of `WriteBuf` move into its `TLVWrite` impl.
- **Tests.** The test helpers that tests of other crates used move next to what they test
  (`persist::MemKvBlobStore` and `MemKv`, behind `std`), or are written out in those tests
  (a `Matter` of the test device, the test fabric indices, an ICAC minted with
  `CertGenerator`). The handlers' tests use the IM engine's event queue through a
  dev-dependency of `rs-matter-dm` on `rs-matter-im`, and the `pics` test of
  `rs-matter-node` uses the generated Identify metadata through a dev-dependency on
  `rs-matter-dm-clusters`; neither is a cycle.
- **Exported macros.** The root endpoint macros of `rs-matter-dm` expand to
  `$crate::dm::...` paths, so that crate has a hidden public `dm` module that puts the
  data model types and its own modules together. The facade re-exports the macros of
  `rs-matter-dm-base`, `rs-matter-tlv` and `rs-matter-dm` at its root, as before.

## 9. Order of work

### Step 1: inside the current crate

No new crates yet. Each item compiles and passes the tests on its own.

1. `ImTransaction`, the generic generated client code, and the implementation for
   `Exchange` (section 3). Update the codegen golden test.
2. The context change: `exchange_id()`, `utc_time()`, the `ExchangeId` extension trait,
   `&Matter` for the system handlers, the group membership trait for Scenes (section 4).
3. The moves of section 6: the node state, the node's own enums and constants, the drivers,
   and the data model types' links to code above them.
4. A module-level dependency check that maps each module to its future crate and confirms
   that the resulting crate graph has no cycles. This was a script, removed in step 2,
   once the crates and their dependencies took over the check.

This step contains all the design decisions and can be reviewed on its own.

### Step 2: extract the crates, bottom up

`utils`, `tlv`, `crypto`, `cert`, `pairing`; then `im-base`, `dm-base`; then
`dm-clusters` (with `build.rs`); then `node`, `im`, `dm`, `onboard`; the facade last.

`pics` (`Matter::write_pics_json`) went to `node` rather than to `dm`: it adds methods to
`Matter` and uses only the node and the data model types.

### Step 3: tooling and measurement

Update CI, `xtask` (copyright, integration tests), `bloat-check`, the README and the
CHANGELOG. Measure check times against the table in #559, and flash size with
`bloat-check`.

What changed:

- **CI.** The clippy steps of `rs-matter` run without `--no-deps`, so that the `rs-matter-*`
  crates, which are its path dependencies, are linted with each feature set too. The Test
  step runs the tests of all the crates of the workspace, except the examples, the test
  binaries, the code generator and the macros, which have steps of their own. It passes the
  features of `rs-matter` (`--features rs-matter/<feature>`), which forwards them to the
  other crates. Miri runs the same unit tests as before, now named by crate: those of
  `utils`, `tlv`, `dm-base` (without the file I/O of `persist`), `im` (without the
  responders), `dm`, and the IM client and the transport of `node`.
- **Coverage.** Measured over the workspace in the same way. `xtask coverage` groups the
  files by crate and module (`node/transport`, `dm/clusters`, ...), and the report uses
  depth 2, which gives about the rows of depth 1 before the split.
- **`xtask copyright`** needs no change: it finds the crates from the tracked `Cargo.toml`
  files.
- **Publishing.** The publishing workflows list the new crates, in the order in which they
  have to be published.
- **`bloat-check`** depends on the facade, as before; its lockfile gains the new crates.
- **README.** A section lists the crates.

## 10. Expected effect

An edit to `node`, `im` or `dm` no longer re-checks the generated code. #559 estimates
single-digit seconds for such re-checks. An edit to `dm-base`, `im-base`, `tlv` or `utils`
still re-checks the generated crate, but those crates change less often. A clean
build takes about as long as today in total, with some crates building in parallel.

How to measure, before and after the split:

- Use the command rust-analyzer runs on save (`cargo check --workspace --all-targets`
  with the default settings), since that is what the goal is about.
- Time a re-check after a one-line edit in a file of `node`, of `im` and of `dm`, and after
  only touching a file, as in the table in #559. These are the common cases when working
  on `rs-matter`, and they should drop to a few seconds.
- Time the same after an edit in `dm-base` and in `tlv`, to know the cost of the less
  common cases.
- Note that `--workspace --all-targets` also re-checks the crates that depend on the edited
  one, including the examples and the tests, so those count too.

### Measured

On an 8-thread Intel i7-6700 with 32 GB, `CARGO_BUILD_JOBS=4`, default features,
incremental checks. "Before" is 14baec09 (the commit before step 1), "after" is the split.
Each row is the time of a re-check after touching a file, after adding a function to it, and
after removing the function again, in seconds.

`cargo check --workspace --all-targets` (what rust-analyzer runs on save):

| Edited file in | Before | After |
|---|---|---|
| `node` (`fabric.rs`) | 52.7 / 54.1 / 55.6 | 5.9 / 9.2 / 8.9 |
| `im` (`subscriptions.rs`) | 50.2 / 52.3 / 53.4 | 4.8 / 4.7 / 4.7 |
| `dm` (`clusters/app/on_off.rs`) | 52.3 / 54.0 / 51.8 | 4.9 / 6.3 / 6.1 |
| `dm-base` (`cluster.rs`) | 51.4 / 53.2 / 52.6 | 46.4 / 48.4 / 49.4 |
| `tlv` (`read.rs`) | 48.9 / 54.0 / 54.9 | 46.5 / 43.1 / 45.1 |
| nothing (no-op check) | 3.8 | 0.3 |

`cargo check -p rs-matter`, as in the table of #559, after an edit in the node:

| | Before | After |
|---|---|---|
| `fabric.rs` | 37.7 / 43.1 / 35.3 | 3.4 / 3.1 / 3.0 |

An edit outside of the generated crate and the crates below it now re-checks in about 3 to
9 seconds instead of about 50. An edit in `dm-base` or `tlv` still re-checks the generated
crate, and stays at about 45 seconds. A first check of the generated crate alone takes about
1 minute 50 seconds.

Flash: `.text` of `bloat-check`, release build (fat LTO, one codegen unit), in bytes:

| Target | Before (14baec09) | After step 1 (fc37533a) | After the split |
|---|---|---|---|
| thumbv6m | 305,984 | 306,288 (+304) | 308,316 (+2,028) |
| thumbv7em | 288,120 | 288,556 (+436) | 289,828 (+1,272) |
| riscv32imac | 383,770 | 384,436 (+666) | 386,722 (+2,286) |

The split itself adds 0.4% to 0.6%. A comparison of the symbols on thumbv7em shows no single
cause: about 280 bytes more of the code LLVM outlines, several copies of small TLV helpers
that one crate had once (e.g. `TLVValueType::from_u8` five times), and small differences in
inlining in the large responders. `#[inline]` and generic functions get a copy in each crate
that uses them, and LTO does not merge the identical copies it does not inline. Identical
code folding in the linker (`-C link-arg=--icf=all` with `lld`) could remove those copies;
this was not tried.

## 11. Possible follow-ups

- **Split the generated crate into shared, server and client parts.** Shares of the
  generated code: shared types and IDs 39%, server (handler traits, adaptors, metadata) 32%,
  client 29%. The shared part would depend only on `tlv` and `im-base`, the server part on
  `dm-base`, the client part on `im-base`. Server and client would then type-check in
  parallel, shortening the longest chain to about 71% of today's, and an edit to `dm-base`
  would re-check only the server part. Nothing would be skipped in a normal build, because
  `dm` uses two generated clients. The generated event helpers (`<Event>::emit_for`) would
  need to move to the server part as an extension trait or free functions.
- **Remove `crypto`'s use of `tlv`** (see section 5).
- **Move the OS backends** (zbus proxies, BlueZ and bluer, Avahi, systemd-resolved,
  zeroconf, astro-dnssd; about 12K lines) to a crate above `node`.
- **An `ImInitiator` trait**, so that the WebRTC Transport Provider handler no longer needs
  `&Matter`.
- **Per-crate error types** (a separate issue).
