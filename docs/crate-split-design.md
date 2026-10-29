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

Every crate also depends on `error` and `utils`; the table leaves those two out after the
first rows. Line counts are hand-written lines in the current code.

| Crate | Contents | Lines | Depends on | Used by |
|---|---|---|---|---|
| `rs-matter-error` | `Error`, `ErrorCode` (unchanged) | 0.5K | - | all |
| `rs-matter-utils` | `utils`, without the zbus proxies | 8K | error | all except error |
| `rs-matter-tlv` | TLV | 9.1K | - | all below |
| `rs-matter-crypto` | `Crypto` traits, canonical types, rand, backends (by feature), group key derivation | 6.7K | tlv | cert, pairing, dm-base, node, im, dm, onboard |
| `rs-matter-cert` | operational certificates, x509 and CSR, attestation (DAC chain, CD, trust store), `DeviceAttestation` | 7.7K | tlv, crypto | node, dm, onboard |
| `rs-matter-pairing` | QR, manual code and NFC payloads, QR scanning, `BasicCommData` and the passcode types | 2.6K | tlv, crypto | node |
| `rs-matter-im-base` | IM message encoding, protocol constants and opcodes, IDs, `ImTransaction` | 6.9K | tlv | dm-base, dm-clusters, node, im, dm, onboard |
| `rs-matter-dm-base` | data model metadata (`Node`, `Endpoint`, `Cluster`, ...), access, dataver, `Handler` / `AsyncHandler`, context traits, `Reply`, change notifiers, event writer, `LifecycleOp`, `ImStats`, `ExchangeId`, persistence traits | 6.5K | tlv, im-base, crypto | dm-clusters, node, im, dm, onboard |
| `rs-matter-dm-clusters` | generated: types, builders, metadata, handler traits, adaptors, client views; owns the codegen `build.rs` | (775K generated) | tlv, im-base, dm-base | dm, onboard |
| `rs-matter-node` | `Matter` and the node state, transport (exchange, session, MRP, UDP, TCP, BTP, mDNS, OS backends), secure channel, fabrics, ACL, fail-safe, handover, BDX, OTA image, the IM client over `Exchange` | 55K | tlv, crypto, cert, pairing, im-base, dm-base | im, dm, onboard |
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
- `From<bluer::Error> for Error` must live in the error crate because of the orphan rule. The
  error crate gets an optional `bluer` dependency, enabled by the node's `bluer` feature. The
  other conversions (`std::io::Error`, `PoisonError`, `SystemTimeError`, `num_enum`) need
  only a `std` feature.
- `Error` implements the `embedded-io-async` error trait. The error crate is below `utils`,
  so it depends on `embedded-io-async` directly, as the one exception to using it through
  `utils::io`. This is acceptable because the error crate is expected to be redesigned, and
  likely to go away, with the per-crate errors.
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
  `large-buffers`, which go on `dm-base`. The crypto backends go on `crypto`. The facade
  forwards all current features, so existing `Cargo.toml` files keep working.
- **Logging macros.** Each crate gets its own copy of `fmt.rs`. A `#[macro_export]` macro
  evaluates `cfg(feature = ...)` in the crate that calls it, so one copy cannot serve all
  crates.
- **Derive macros.** The `proc_macro_crate` lookup in `rs-matter-macros` learns
  `rs-matter-tlv`, and keeps the `rs-matter` facade and `crate` as fallbacks.
- **Codegen paths.** The generated crate re-exports the base crates as `tlv`, `dm`, `im`,
  `error` and `reexport` modules, so the generated `crate::tlv::...` paths keep working.
  Only the cross-cluster `crate::dm::clusters::decl::...` paths need a new codegen
  parameter.
- **Generation at build time.** The generated source is too large for crates.io, so
  `rs-matter-dm-clusters` keeps generating it from its `build.rs`.

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
   that the resulting crate graph has no cycles: `xtask/scripts/crate_split_deps.py`.

This step contains all the design decisions and can be reviewed on its own.

### Step 2: extract the crates, bottom up

`error`, `utils`, `tlv`, `crypto`, `cert`, `pairing`; then `im-base`, `dm-base`; then
`dm-clusters` (with `build.rs`); then `node`, `im`, `dm`, `onboard`; the facade last.

### Step 3: tooling and measurement

Update CI, `xtask` (copyright, integration tests), `bloat-check`, the README and the
CHANGELOG. Measure check times against the table in #559, and flash size with
`bloat-check`.

## 10. Expected effect

An edit to `node`, `im` or `dm` no longer re-checks the generated code. #559 estimates
single-digit seconds for such re-checks. An edit to `dm-base`, `im-base`, `tlv`, `utils` or
`error` still re-checks the generated crate, but those crates change less often. A clean
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
