using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Dotrino
{
    /// <summary>
    /// A connection to the proxy that STAYS UP and where EVERYTHING GOES SEALED — and binary.
    /// The port of dotrino-native's <c>SealedSession</c>, itself the counterpart of
    /// <c>WebSocketProxyClient</c> with <c>requireSealed: true</c>:
    ///
    ///  - reconnects by itself, re-identifies and re-announces its encryption key (signed) every
    ///    time: a dropped socket never leaves the game deaf in silence;
    ///  - after <see cref="FailsBeforeFailover"/> failures in a row on one proxy it moves to the next;
    ///  - what arrives UNSEALED is dropped and reported (<see cref="Warn"/>), in both directions;
    ///  - what arrives sealed comes with <c>SenderEncPub</c>: the game checks it against who it claims to be.
    ///
    /// Callbacks run on the <see cref="SynchronizationContext"/> that was current when it was
    /// created — in Unity, the main thread, so handlers may touch GameObjects.
    ///
    /// The direct road is plugged in with <see cref="UseDirect"/> (WebRTC: Dotrino.Unity.WebRTC).
    /// Without it everything goes through the proxy, the last step of the ladder. Bluetooth is not
    /// here.
    /// </summary>
    public sealed class SealedSession : IDisposable
    {
        public const int FailsBeforeFailover = 3;
        const int MaxBackoffMs = 30_000;

        public sealed class Received
        {
            /// <summary>Who the proxy or the greeting says it is — trust it only after checking <see cref="SenderEncPub"/>.</summary>
            public string FromToken, FromPubkey;
            public JsonObject Payload;
            public string SenderEncPub;
            public bool Queued;
            public long? QueuedAt;
            /// <summary>By which road it came: <c>proxy</c> or <c>direct</c> (the WebRTC channel).</summary>
            public string Via;
        }

        /// <summary><c>connecting</c> | <c>online</c> | <c>offline</c> | <c>closed</c>; <see cref="Url"/> is the proxy in use.</summary>
        public sealed class Status
        {
            public string State, Url, Reason;
            public override string ToString() => State + " " + Url + (Reason != null ? " (" + Reason + ")" : "");
        }

        readonly IReadOnlyList<string> _urls;
        readonly IDeviceKeys _keys;
        readonly Func<JsonObject, Task<string>> _sign;
        readonly SynchronizationContext _ctx;
        readonly CancellationTokenSource _stop = new CancellationTokenSource();
        public readonly string App;
        public readonly IdentitySealing Sealing;
        volatile ProxyConnection _conn;
        volatile IDirectTransport _direct;
        Task _loop;
        int _urlIndex;
        TaskCompletionSource<bool> _online = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        public event Action<Received> Message;
        public event Action<Status> StatusChanged;
        public event Action<ProxyConnection.Event> TransportEvent;
        /// <summary>Every time the session is (again) online and identified: re-greet, flush an outbox…</summary>
        public event Action Online;
        public event Action<string, Exception> Warn;

        public Status Current { get; private set; }
        public string Url => _urls[_urlIndex % _urls.Count];
        public bool IsOnline => Current?.State == "online";
        public string Token => _conn?.Token;
        public string Publickey => _keys.Publickey;

        /// <param name="sign">Signs for the identity (canonical data → signature). Default: <paramref name="keys"/> signs directly.</param>
        public SealedSession(IReadOnlyList<string> urls, IDeviceKeys keys, string app, Func<JsonObject, Task<string>> sign = null)
        {
            if (urls == null || urls.Count == 0) throw new ArgumentException("at least one proxy url");
            _urls = urls;
            _keys = keys ?? throw new ArgumentNullException(nameof(keys));
            App = app ?? throw new ArgumentNullException(nameof(app));
            _sign = sign ?? (d => keys.Sign(Canonical.Stringify(d)));
            _ctx = SynchronizationContext.Current;
            Sealing = new IdentitySealing(keys, app);
            Current = new Status { State = "connecting", Url = urls[0] };
        }

        void Raise(Action a)
        {
            if (_ctx == null) { try { a(); } catch (Exception) { } return; }
            _ctx.Post(_ => { try { a(); } catch (Exception) { } }, null);
        }

        void SetStatus(Status s)
        {
            Current = s;
            Raise(() => StatusChanged?.Invoke(s));
        }

        void OnWarn(string what, Exception e) => Raise(() => Warn?.Invoke(what, e));

        /// <summary>Starts the loop. Returns at once; <see cref="AwaitOnline"/> waits for the first connection.</summary>
        public void Start()
        {
            if (_loop != null) return;
            _loop = Task.Run(Loop);
        }

        async Task Loop()
        {
            int fails = 0;
            while (!_stop.IsCancellationRequested)
            {
                string u = Url;
                SetStatus(new Status { State = "connecting", Url = u });
                var c = new ProxyConnection(u, App);
                try
                {
                    await c.Connect().ConfigureAwait(false);
                    c.Message += inc => _ = Deliver(c, inc);
                    c.TransportEvent += e =>
                    {
                        // A peer that left takes its direct channel with it (tokens are not reused).
                        if (e is ProxyConnection.PeerGone g) _direct?.Close(g.Token);
                        Raise(() => TransportEvent?.Invoke(e));
                    };
                    c.Signal += (from, msg) => _direct?.HandleSignal(from, msg);
                    await c.IdentifyAs(_keys.Publickey, _sign).ConfigureAwait(false);
                    _conn = c;
                    // Without my key announced nobody can seal to me.
                    try { await c.AnnounceEncPub(_keys.Publickey, _keys.EncPub, _sign).ConfigureAwait(false); }
                    catch (Exception e) { OnWarn("could not announce my encryption key", e); }
                    if (_direct != null) _ = EnableTurn(c, _direct);
                    fails = 0;
                    SetStatus(new Status { State = "online", Url = u });
                    _online.TrySetResult(true);
                    Raise(() => Online?.Invoke());
                    string why = await c.Ended.ConfigureAwait(false);
                    _conn = null;
                    _online = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    if (_stop.IsCancellationRequested) break;
                    SetStatus(new Status { State = "offline", Url = u, Reason = why });
                }
                catch (Exception e)
                {
                    _conn = null;
                    c.Dispose();
                    if (_stop.IsCancellationRequested) break;
                    fails++;
                    SetStatus(new Status { State = "offline", Url = u, Reason = e.Message });
                    OnWarn("connection to " + u + " failed", e);
                    if (fails >= FailsBeforeFailover && _urls.Count > 1) { _urlIndex++; fails = 0; }
                }
                try { await Task.Delay(Math.Min(MaxBackoffMs, 1000 << Math.Min(fails, 5)), _stop.Token).ConfigureAwait(false); }
                catch (TaskCanceledException) { break; }
            }
            SetStatus(new Status { State = "closed", Url = Url });
        }

        /// <summary>Waits until online, or until <paramref name="timeoutMs"/> passes.</summary>
        public async Task<bool> AwaitOnline(int timeoutMs = 15_000)
        {
            if (IsOnline) return true;
            var t = _online.Task;
            return await Task.WhenAny(t, Task.Delay(timeoutMs)).ConfigureAwait(false) == t || IsOnline;
        }

        public void Dispose()
        {
            _stop.Cancel();
            _conn?.Dispose();
        }

        /// <summary>
        /// Plugs in the DIRECT ROAD. From then on, what goes by token prefers an open channel, and
        /// the first message to someone opens one underneath. TURN credentials are asked after
        /// every identify.
        /// </summary>
        public void UseDirect(IDirectTransport d)
        {
            _direct = d ?? throw new ArgumentNullException(nameof(d));
            d.Bind(
                () => _conn?.Token,
                (to, msg) => { var c = _conn; if (c != null) _ = c.SendSignal(to, msg).ContinueWith(_ => { }, TaskScheduler.Default); },
                (from, text) =>
                {
                    var c = _conn;
                    if (c == null) return;
                    JsonObject payload;
                    try { payload = JsonValue.Parse(text).Obj; } catch (FormatException) { return; }
                    if (payload != null) _ = Deliver(c, new ProxyConnection.Incoming { From = from, Payload = payload }, "direct");
                },
                (from, bytes) =>
                {
                    var c = _conn;
                    if (c == null) return;
                    ProxyConnection.Incoming inc;
                    try { inc = ProxyConnection.IncomingPackage(from, null, bytes); }
                    catch (DotrinoException e) { OnWarn("dropped a direct message that does not unpack (" + e.Code + ")", e); return; }
                    if (inc != null) _ = Deliver(c, inc, "direct");
                });
            var live = _conn;
            if (live != null) _ = EnableTurn(live, d);
        }

        /// <summary>Where <paramref name="token"/> goes now (<see cref="IDirectTransport.Route"/>); null = the proxy.</summary>
        public string RouteOf(string token) => _direct?.Route(token);

        /// <summary>TURN for the direct road, in front of the default STUN. A proxy without TURN leaves STUN only: not an error.</summary>
        async Task EnableTurn(ProxyConnection c, IDirectTransport d)
        {
            try
            {
                var servers = await c.TurnCredentials(_keys.Publickey, _sign).ConfigureAwait(false);
                if (servers.Count > 0) { servers.AddRange(IceServer.DefaultStun); d.SetIceServers(servers); }
            }
            catch (Exception e) { OnWarn("could not get TURN credentials", e); }
        }

        ProxyConnection Live() => _conn ?? throw new DotrinoException("not connected to the proxy", "disconnected");

        async Task Deliver(ProxyConnection c, ProxyConnection.Incoming inc, string via = "proxy")
        {
            var bin = inc.Packed != null && BinPack.IsBinSealed(inc.Packed) ? inc.Packed : null;
            if (bin == null && !Sealing.IsSealed(inc.Payload))
            {
                OnWarn("dropped a message that arrived unsealed", null);
                return;
            }
            (JsonObject payload, string sender) opened;
            try { opened = bin != null ? await Sealing.OpenBinary(bin).ConfigureAwait(false) : await Sealing.Open(inc.Payload).ConfigureAwait(false); }
            catch (Exception) { return; }   // sealed to somebody else, or tampered with: staying quiet is the point
            var m = new Received
            {
                FromToken = inc.From, FromPubkey = inc.FromPubkey ?? (inc.From != null ? c.PubkeyOfToken(inc.From) : null),
                Payload = opened.payload, SenderEncPub = opened.sender, Queued = inc.Queued, QueuedAt = inc.QueuedAt, Via = via,
            };
            Raise(() => Message?.Invoke(m));
        }

        /// <summary>The encryption key of an identity, VERIFIED against its signature. Throws with <c>Code</c>.</summary>
        public Task<string> EncPubOf(string publickey) => Live().EncPubOf(publickey);

        public string PubkeyOfToken(string token) => _conn?.PubkeyOfToken(token);

        /// <summary>
        /// Sealed, BY PUBKEY (live, or the proxy's 24 h offline queue). <paramref name="recipientEncPubs"/>:
        /// every key of the person; empty = the one their identity announced. To the SAME app on
        /// their side.
        /// </summary>
        public async Task SendSealed(string pubkey, JsonObject payload, IReadOnlyList<string> recipientEncPubs = null, bool quiet = false)
        {
            var c = Live();
            var keys = recipientEncPubs != null && recipientEncPubs.Count > 0 ? recipientEncPubs : new[] { await c.EncPubOf(pubkey).ConfigureAwait(false) };
            await c.SendByPubkey(pubkey, await Sealing.SealBinary(payload, keys).ConfigureAwait(false), quiet, App).ConfigureAwait(false);
        }

        /// <summary>
        /// Sealed, BY TOKEN (live). Knowing whose it is, a dead token (they restarted) sends the SAME
        /// envelope to their queue. Empty keys = the one announced by the identity behind that token.
        /// </summary>
        public async Task SendSealedTo(string token, JsonObject payload, IReadOnlyList<string> recipientEncPubs = null, string peerPubkey = null)
        {
            var c = Live();
            string pk = peerPubkey ?? c.PubkeyOfToken(token);
            IReadOnlyList<string> keys = recipientEncPubs;
            if (keys == null || keys.Count == 0)
            {
                if (pk == null) throw new DotrinoException("nobody has said whose this token is — greet it first", "no-peer-identity");
                keys = new[] { await c.EncPubOf(pk).ConfigureAwait(false) };
            }
            byte[] sealedBytes = await Sealing.SealBinary(payload, keys).ConfigureAwait(false);
            var d = _direct;
            if (d != null && d.SendBinary(token, sealedBytes)) return;
            // Knowing whose it is, a dead token (they restarted) sends the SAME envelope to the queue.
            if (pk != null) await c.SendToOrElse(token, sealedBytes, () => _ = c.SendByPubkey(pk, sealedBytes, toApp: App)).ConfigureAwait(false);
            else await c.SendTo(new[] { token }, sealedBytes).ConfigureAwait(false);
            // And try to go direct for the next one, without waiting for anybody.
            d?.Upgrade(token);
        }

        public Task<(string code, long expiresAt)> RequestPairingCode(long? ttlMs = null) => Live().RequestPairingCode(ttlMs);
        public Task<string> RedeemPairingCode(string code) => Live().RedeemPairingCode(code);

        /// <summary>WHOSE IS THIS TOKEN: greets it and waits for its answer. Does not authenticate, and does not need to: what follows goes sealed to the key that identity announced signed.</summary>
        public async Task<string> WhoIs(string token, int timeoutMs = 10_000)
        {
            var c = Live();
            string known = c.PubkeyOfToken(token);
            if (known != null) return known;
            var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            Action<ProxyConnection.Event> h = e => { if (e is ProxyConnection.PeerIdentity p && p.Token == token) tcs.TrySetResult(p.Publickey); };
            c.TransportEvent += h;
            try
            {
                await c.HelloTo(token).ConfigureAwait(false);
                return await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs)).ConfigureAwait(false) == tcs.Task ? tcs.Task.Result : null;
            }
            finally { c.TransportEvent -= h; }
        }
    }
}
