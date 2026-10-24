using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Dotrino
{
    /// <summary>
    /// ONE connection to the proxy, speaking the same frames as <c>@dotrino/proxy-client</c>
    /// (<c>src/client.js</c>) — the port of dotrino-native's <c>ProxyConnection</c>:
    /// <c>connected</c> gives the token, <c>identify</c> binds my key, a directed message goes
    /// <c>{ to_publickey }</c> and arrives as <c>{ type:'message', from }</c>.
    ///
    /// EVERY MESSAGE LEAVES BINARY: a binary frame whose body is the package of the payload
    /// (<see cref="BinPack"/>), or a binary sealed envelope. Only the transport's control frames
    /// (the greeting) stay text. A proxy without binary frames gets nothing:
    /// <c>no-binary-support</c>, said.
    ///
    /// It does not reconnect by itself (<see cref="SealedSession"/> does). A dead socket fails
    /// every pending request with its reason instead of leaving it to time out. Events fire on
    /// the receive thread.
    /// </summary>
    public sealed class ProxyConnection : IDisposable
    {
        public const string HelloTag = "__cc_hello__";
        /// <summary>The direct road's signalling (<see cref="IDirectTransport"/>): a control frame, never for the app.</summary>
        public const string RtcTag = "__cc_rtc__";
        /// <summary>What this library understands, said in the greeting (<c>SPEAKS</c> of the JS client).</summary>
        public static readonly string[] SpeaksList = { "binary" };

        static readonly Regex AppName = new Regex("^[a-z0-9][a-z0-9-]{0,31}$");

        /// <summary>A directed message: who sent it (token and, if identified, key) and its payload.</summary>
        public sealed class Incoming
        {
            public string From, FromPubkey;
            public JsonObject Payload;
            /// <summary>It waited in the proxy's offline queue (and since when, ms).</summary>
            public bool Queued;
            public long? QueuedAt;
            /// <summary>The package it came in, when it came binary; a binary sealed envelope is opened from here.</summary>
            public BinPack.Packed Packed;
        }

        public abstract class Event { }
        public sealed class PeerGone : Event { public string Token, Channel; }
        public sealed class Joined : Event { public string Channel, Token; }
        public sealed class Left : Event { public string Channel, Token; }
        public sealed class PeerIdentity : Event { public string Token, Publickey; }
        /// <summary>Something arrived that is not a frame or package this library knows (<c>bad-frame</c>, <c>bad-pack</c>).</summary>
        public sealed class Undecodable : Event { public string Code, Reason; }

        readonly string _url;
        public readonly string App;
        readonly ClientWebSocket _ws = new ClientWebSocket();
        readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);
        readonly CancellationTokenSource _cts = new CancellationTokenSource();
        readonly TaskCompletionSource<string> _connected = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly TaskCompletionSource<string> _ended = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> _pending = new ConcurrentDictionary<string, TaskCompletionSource<JsonObject>>();
        readonly ConcurrentDictionary<string, string> _tokenPubkeys = new ConcurrentDictionary<string, string>();
        readonly ConcurrentDictionary<string, HashSet<string>> _tokenSpeaks = new ConcurrentDictionary<string, HashSet<string>>();
        readonly ConcurrentDictionary<string, byte> _helloSent = new ConcurrentDictionary<string, byte>();
        readonly ConcurrentDictionary<string, (string token, long at, Action onGone)> _tokenWatch = new ConcurrentDictionary<string, (string, long, Action)>();
        readonly ConcurrentDictionary<string, string> _encPubs = new ConcurrentDictionary<string, string>();
        int _nextId;

        public event Action<Incoming> Message;
        public event Action<Event> TransportEvent;
        /// <summary>A signalling frame of the direct road arrived from a token (goes to <see cref="IDirectTransport.HandleSignal"/>).</summary>
        public event Action<string, JsonObject> Signal;

        public string Closed { get; private set; }
        public string Token { get; private set; }
        /// <summary>The proxy node this connection lives on, from <c>connected</c>.</summary>
        public string Node { get; private set; }
        /// <summary>What this proxy says it can do (<c>caps</c>), or null for a proxy older than that.</summary>
        public IReadOnlyList<string> Caps { get; private set; }
        /// <summary>The identity I identified as; the greeting says it.</summary>
        public string MyPublickey { get; private set; }

        /// <summary>The audience that goes inside <c>identify</c>: the proxy URL without trailing slashes.</summary>
        public string Audience => _url.TrimEnd('/');

        /// <summary>Completes when this connection dies, with the reason.</summary>
        public Task<string> Ended => _ended.Task;

        /// <param name="app">WHICH app this connection is (<c>autoball</c>…): the proxy rings and hands queued messages only to it.</param>
        public ProxyConnection(string url, string app = null)
        {
            if (app != null && !AppName.IsMatch(app)) throw new ArgumentException($"app: \"{app}\" is not a valid app name");
            _url = url ?? throw new ArgumentNullException(nameof(url));
            App = app;
            _ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
        }

        static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public async Task<string> Connect(int timeoutMs = 10_000)
        {
            using (var t = new CancellationTokenSource(timeoutMs))
            using (var both = CancellationTokenSource.CreateLinkedTokenSource(t.Token, _cts.Token))
            {
                try { await _ws.ConnectAsync(new Uri(_url), both.Token).ConfigureAwait(false); }
                catch (Exception e) { Die("transport: " + e.Message); throw new DotrinoException("could not connect to " + _url + ": " + e.Message, "disconnected"); }
            }
            _ = Task.Run(ReceiveLoop);
            var done = await Task.WhenAny(_connected.Task, Task.Delay(timeoutMs)).ConfigureAwait(false);
            if (done != _connected.Task) { Die("no connected frame in " + timeoutMs + " ms"); throw new DotrinoException("the proxy did not say connected", "timeout"); }
            return await _connected.Task.ConfigureAwait(false);
        }

        async Task ReceiveLoop()
        {
            var buf = new byte[64 * 1024];
            try
            {
                while (_ws.State == WebSocketState.Open)
                {
                    using (var ms = new MemoryStream())
                    {
                        WebSocketReceiveResult r;
                        do
                        {
                            r = await _ws.ReceiveAsync(new ArraySegment<byte>(buf), _cts.Token).ConfigureAwait(false);
                            if (r.MessageType == WebSocketMessageType.Close)
                            {
                                Die("closed: " + (int?)r.CloseStatus + " " + r.CloseStatusDescription);
                                return;
                            }
                            ms.Write(buf, 0, r.Count);
                        } while (!r.EndOfMessage);
                        byte[] data = ms.ToArray();
                        if (r.MessageType == WebSocketMessageType.Text) Handle(Encoding.UTF8.GetString(data));
                        else HandleBinary(data);
                    }
                }
                Die("closed: " + _ws.State);
            }
            catch (Exception e) { Die("transport: " + e.Message); }
        }

        public void Close()
        {
            if (Closed == null && _ws.State == WebSocketState.Open)
            {
                try { _ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None).Wait(2000); } catch (Exception) { }
            }
            Die("closed by us");
        }

        public void Dispose()
        {
            Close();
            _ws.Dispose();
        }

        void Die(string reason)
        {
            lock (_pending)
            {
                if (Closed != null) return;
                Closed = reason;
            }
            _cts.Cancel();
            _ended.TrySetResult(reason);
            var e = new DotrinoException(reason, "disconnected");
            _connected.TrySetException(e);
            foreach (var p in _pending.Values) p.TrySetException(e);
            _pending.Clear();
        }

        void Emit(Event e)
        {
            var h = TransportEvent;
            if (h == null) return;
            foreach (Action<Event> l in h.GetInvocationList()) { try { l(e); } catch (Exception) { } }
        }

        void Deliver(Incoming inc)
        {
            var h = Message;
            if (h == null) return;
            foreach (Action<Incoming> l in h.GetInvocationList()) { try { l(inc); } catch (Exception) { } }
        }

        void Forget(string token)
        {
            // The token dies with the connection and is never reused: what it said is forgotten.
            _tokenPubkeys.TryRemove(token, out _);
            _helloSent.TryRemove(token, out _);
            _tokenSpeaks.TryRemove(token, out _);
        }

        void Complete(string id, JsonObject o)
        {
            if (id != null && _pending.TryRemove(id, out var p)) p.TrySetResult(o);
        }

        void Handle(string text)
        {
            JsonObject o;
            try { o = JsonValue.Parse(text).Obj; } catch (FormatException) { return; }
            if (o == null) return;
            string type = o["type"]?.Str, id = o["id"]?.Str;
            switch (type)
            {
                case "connected":
                    string t = (o["instance"] ?? o["token"])?.Str;
                    if (t == null) { Die("connected without a token"); return; }
                    Token = t;
                    Node = o["node"]?.Str;
                    if (o["caps"] is JsonArray caps) { var l = new List<string>(); foreach (var c in caps) if (c.Str != null) l.Add(c.Str); Caps = l; }
                    _connected.TrySetResult(t);
                    break;
                case "message":
                    var raw = o["message"];
                    JsonObject payload = raw as JsonObject;
                    if (payload == null && raw is JsonString s) { try { payload = JsonValue.Parse(s.Value).Obj; } catch (FormatException) { } }
                    if (payload == null) return;
                    string from = o["from"]?.Str;
                    // The greeting is the transport's: it is answered here and never reaches the app.
                    if (payload["t"]?.Str == HelloTag) { if (from != null) OnHello(from, payload); return; }
                    // The direct road's signalling is a transport control frame too: to WebRTC, not the app.
                    if (payload["t"]?.Str == RtcTag) { if (from != null) { try { Signal?.Invoke(from, payload); } catch (Exception) { } } return; }
                    Deliver(new Incoming
                    {
                        From = from, FromPubkey = o["from_publickey"]?.Str, Payload = payload,
                        Queued = o["queued"] is JsonBool q && q.Value, QueuedAt = o["queued_at"]?.Long,
                    });
                    break;
                case "disconnected":
                    string gone = o["token"]?.Str;
                    if (gone == null) return;
                    Forget(gone);
                    Emit(new PeerGone { Token = gone, Channel = o["channel"]?.Str });
                    Complete(id, o);
                    break;
                case "joined":
                    if (o["channel"]?.Str != null && o["token"]?.Str != null) Emit(new Joined { Channel = o["channel"].Str, Token = o["token"].Str });
                    break;
                case "left":
                    if (o["channel"]?.Str != null && o["token"]?.Str != null) Emit(new Left { Channel = o["channel"].Str, Token = o["token"].Str });
                    break;
                case "message_sent":
                    if (id != null && _tokenWatch.TryRemove(id, out var w) && o["failed"] is JsonArray failed)
                    {
                        foreach (var f in failed)
                        {
                            if (f.Str != w.token) continue;
                            Forget(w.token);
                            Emit(new PeerGone { Token = w.token });
                            try { w.onGone(); } catch (Exception) { }
                        }
                    }
                    Complete(id, o);
                    break;
                case "error":
                    if (id != null && _pending.TryRemove(id, out var p))
                        p.TrySetException(new DotrinoException(o["error"]?.Str ?? "proxy error", o["code"]?.Str ?? "proxy-error"));
                    break;
                default:
                    Complete(id, o);
                    break;
            }
        }

        /// <summary>A BINARY frame: the usual header and the message raw. What does not open is dropped and said, never guessed.</summary>
        void HandleBinary(byte[] raw)
        {
            Incoming inc;
            try
            {
                var (o, body) = BinPack.DecodeFrame(raw);
                if (o["type"]?.Str != "message") return;
                inc = IncomingPackage(o["from"]?.Str, o["from_publickey"]?.Str, body, o["queued"] is JsonBool q && q.Value, o["queued_at"]?.Long);
            }
            catch (DotrinoException e) { Emit(new Undecodable { Code = e.Code, Reason = e.Message }); return; }
            if (inc != null) Deliver(inc);
        }

        /// <summary>A message that arrived as a PACKAGE. A binary sealed envelope keeps its references; anything else reaches the app with its bytes as base64.</summary>
        public static Incoming IncomingPackage(string from, string fromPubkey, byte[] body, bool queued = false, long? queuedAt = null)
        {
            var p = BinPack.Unpack(body);
            var payload = (BinPack.IsBinSealed(p) ? p.Json : p.Resolved()) as JsonObject;
            if (payload == null) return null;
            return new Incoming { From = from, FromPubkey = fromPubkey, Payload = payload, Queued = queued, QueuedAt = queuedAt, Packed = p };
        }

        void Live()
        {
            if (Closed != null) throw new DotrinoException(Closed, "disconnected");
            if (_ws.State != WebSocketState.Open) throw new DotrinoException("not connected", "disconnected");
        }

        async Task SendRaw(byte[] data, WebSocketMessageType type)
        {
            Live();
            await _sendLock.WaitAsync().ConfigureAwait(false);
            try { await _ws.SendAsync(new ArraySegment<byte>(data), type, true, _cts.Token).ConfigureAwait(false); }
            catch (Exception e) when (!(e is DotrinoException)) { Die("transport: " + e.Message); throw new DotrinoException("could not send: " + e.Message, "disconnected"); }
            finally { _sendLock.Release(); }
        }

        Task SendText(JsonObject frame) => SendRaw(Encoding.UTF8.GetBytes(frame.ToString()), WebSocketMessageType.Text);

        /// <summary>A message: <paramref name="header"/> is the frame without <c>message</c>, <paramref name="body"/> the package that goes raw.</summary>
        Task SendBinary(JsonObject header, byte[] body)
        {
            Live();
            if (Caps == null || !((List<string>)Caps).Contains("binary"))
                throw new DotrinoException("this proxy does not take binary frames (it needs websocket-proxy >= 1.6.0)", "no-binary-support");
            return SendRaw(BinPack.EncodeFrame(header, body), WebSocketMessageType.Binary);
        }

        /// <summary>A request with an <c>id</c> whose answer comes back with the same <c>id</c>.</summary>
        async Task<JsonObject> Request(JsonObject frame, int timeoutMs = 10_000)
        {
            string id = "req_" + Interlocked.Increment(ref _nextId);
            var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pending[id] = tcs;
            try
            {
                var f = frame.Clone();
                f.Set("id", id);
                await SendText(f).ConfigureAwait(false);
                var done = await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs)).ConfigureAwait(false);
                if (done != tcs.Task) throw new DotrinoException(frame["type"]?.Str + ": no answer in " + timeoutMs + " ms", "timeout");
                return await tcs.Task.ConfigureAwait(false);
            }
            finally { _pending.TryRemove(id, out _); }
        }

        /// <summary>Binds this connection to my key. The token is the challenge of this connection and goes inside what is signed; <c>aud</c> says who it is meant for.</summary>
        public Task Identify(IDeviceKeys keys) => IdentifyAs(keys.Publickey, d => keys.Sign(Canonical.Stringify(d)));

        /// <summary><c>identifyAs</c> of the JS client: <paramref name="publickey"/> signs (with <paramref name="sign"/>, over the canonical data) that it is behind this connection.</summary>
        public async Task IdentifyAs(string publickey, Func<JsonObject, Task<string>> sign)
        {
            string t = Token ?? throw new DotrinoException("identify before connecting", "disconnected");
            var data = new JsonObject { { "op", "identify" }, { "aud", Audience }, { "publickey", publickey }, { "token", t }, { "ts", NowMs() } };
            var frame = new JsonObject { { "type", "identify" }, { "data", data }, { "signature", await sign(data).ConfigureAwait(false) } };
            if (App != null) frame.Set("app", App);
            await Request(frame).ConfigureAwait(false);
            MyPublickey = publickey;
        }

        // ---------- the greeting ----------

        /// <summary>«This token is this identity» (<c>helloTo</c>): a control frame, in the clear on purpose — it only carries a PUBLIC key the proxy already bound at identify.</summary>
        public Task HelloTo(string to)
        {
            string me = MyPublickey ?? throw new DotrinoException("helloTo: identify first", "not-identified");
            if (to == Token) return Task.CompletedTask;
            _helloSent[to] = 1;
            var speaks = new JsonArray();
            foreach (var s in SpeaksList) speaks.Add(s);
            return SendText(new JsonObject
            {
                { "to", new JsonArray { to } },
                { "message", new JsonObject { { "t", HelloTag }, { "publickey", me }, { "speaks", speaks } }.ToString() },
            });
        }

        void OnHello(string from, JsonObject msg)
        {
            string pk = msg["publickey"]?.Str;
            if (string.IsNullOrEmpty(pk)) return;
            // A TOKEN DOES NOT CHANGE OWNER: a second greeting with another identity is an attempt
            // to get sealed to someone else. The first one stands.
            if (_tokenPubkeys.TryGetValue(from, out var before) && !Delegation.SamePubkey(before, pk)) return;
            _tokenPubkeys[from] = pk;
            var speaks = new HashSet<string>();
            if (msg["speaks"] is JsonArray a) foreach (var s in a) if (s.Str != null && speaks.Count < 32) speaks.Add(s.Str);
            _tokenSpeaks[from] = speaks;
            if (!_helloSent.ContainsKey(from) && MyPublickey != null) _ = HelloTo(from).ContinueWith(_ => { }, TaskScheduler.Default);
            Emit(new PeerIdentity { Token = from, Publickey = pk });
        }

        /// <summary>Whether the connection behind <paramref name="token"/> said it understands <paramref name="feature"/>; null: it has not greeted.</summary>
        public bool? Speaks(string token, string feature = "binary") => _tokenSpeaks.TryGetValue(token, out var s) ? s.Contains(feature) : (bool?)null;

        /// <summary>Whose this token is, if someone said it. Does not authenticate.</summary>
        public string PubkeyOfToken(string token) => _tokenPubkeys.TryGetValue(token, out var pk) ? pk : null;

        // ---------- sending ----------

        /// <summary>A control frame of the direct road, as TEXT: the JS client only reads signalling as text.</summary>
        public Task SendSignal(string to, JsonObject payload) =>
            SendText(new JsonObject { { "to", new JsonArray { to } }, { "message", payload.ToString() } });

        static JsonObject ToTokens(IEnumerable<string> tokens)
        {
            var a = new JsonArray();
            foreach (var t in tokens) a.Add(t);
            return new JsonObject { { "to", a } };
        }

        /// <summary>A message to connection tokens, as its package.</summary>
        public Task SendTo(IEnumerable<string> tokens, JsonObject payload) => SendBinary(ToTokens(tokens), BinPack.Pack(payload));
        public Task SendTo(IEnumerable<string> tokens, byte[] body) => SendBinary(ToTokens(tokens), body);

        /// <summary>
        /// To ONE token, but a dead token does not swallow the message: when the proxy answers
        /// <c>message_sent</c> with it in <c>failed</c>, <paramref name="onGone"/> runs (send the same
        /// thing by pubkey, to the queue) and <see cref="PeerGone"/> is emitted.
        /// </summary>
        public Task SendToOrElse(string token, byte[] body, Action onGone)
        {
            long now = NowMs();
            foreach (var kv in _tokenWatch) if (now - kv.Value.at > 15_000) _tokenWatch.TryRemove(kv.Key, out _);
            string id = "msg_" + Interlocked.Increment(ref _nextId);
            _tokenWatch[id] = (token, now, onGone);
            try { return SendBinary(new JsonObject { { "to", new JsonArray { token } }, { "id", id } }, body); }
            catch (Exception) { _tokenWatch.TryRemove(id, out _); throw; }
        }

        /// <summary>
        /// A directed message to a key: live if they are connected, otherwise the proxy's 24 h
        /// queue. <paramref name="quiet"/>: queued without ringing. <paramref name="ephemeral"/>: real
        /// time only. <paramref name="toApp"/>: WHICH app of theirs it is for.
        /// </summary>
        public Task SendByPubkey(string to, byte[] body, bool quiet = false, string toApp = null, bool ephemeral = false)
        {
            var h = new JsonObject { { "to_publickey", new JsonArray { to } } };
            if (quiet) h.Set("quiet", true);
            if (ephemeral) h.Set("ephemeral", true);
            if (toApp != null) h.Set("app", toApp);
            return SendBinary(h, body);
        }

        public Task SendByPubkey(string to, JsonObject payload, bool quiet = false, string toApp = null, bool ephemeral = false) =>
            SendByPubkey(to, BinPack.Pack(payload), quiet, toApp, ephemeral);

        // ---------- channels ----------

        /// <summary><c>buildSignedChannel</c>: the entry is signed by the TRANSPORT key of this app, not by the identity.</summary>
        static async Task<JsonObject> SignedChannel(string name, IDeviceKeys transport)
        {
            var data = new JsonObject { { "name", name }, { "publickey", transport.Publickey } };
            return new JsonObject { { "data", data }, { "signature", await transport.Sign(Canonical.Stringify(data)).ConfigureAwait(false) } };
        }

        public async Task Publish(string channel, IDeviceKeys transport) =>
            await Request(new JsonObject { { "type", "publish" }, { "channel", await SignedChannel(channel, transport).ConfigureAwait(false) } }).ConfigureAwait(false);

        public async Task Unpublish(string channel, IDeviceKeys transport) =>
            await Request(new JsonObject { { "type", "unpublish" }, { "channel", await SignedChannel(channel, transport).ConfigureAwait(false) } }).ConfigureAwait(false);

        // ---------- encryption keys ----------

        /// <summary>
        /// ANNOUNCE MY ENCRYPTION KEY: a short statement signed by the identity I identified as;
        /// the proxy keeps it and hands it to whoever asks, who checks the signature. The proxy is
        /// the mailbox, not the authority.
        /// </summary>
        public async Task AnnounceEncPub(string publickey, string encPub, Func<JsonObject, Task<string>> sign)
        {
            var data = new JsonObject
            {
                { "v", 1 }, { "op", "encpub" }, { "aud", "dotrino:encpub" },
                { "publickey", publickey }, { "encpub", encPub }, { "ts", NowMs() },
            };
            await Request(new JsonObject { { "type", "encpub" }, { "data", data }, { "signature", await sign(data).ConfigureAwait(false) } }).ConfigureAwait(false);
            _encPubs[publickey] = encPub;
        }

        /// <summary>
        /// THE ENCRYPTION KEY OF AN IDENTITY, verified against that identity — or it throws with
        /// <c>no-encpub</c>, <c>encpub-unverified</c> or <c>no-encpub-support</c>. Never null, never «send anyway».
        /// </summary>
        public async Task<string> EncPubOf(string publickey)
        {
            if (_encPubs.TryGetValue(publickey, out var known)) return known;
            if (Caps != null && !((List<string>)Caps).Contains("encpub")) throw new DotrinoException("this proxy does not serve encryption keys", "no-encpub-support");
            var res = await Request(new JsonObject { { "type", "enc-lookup" }, { "publickeys", new JsonArray { publickey } } }).ConfigureAwait(false);
            JsonObject statement = null;
            if (res["keys"] is JsonArray keys)
                foreach (var k in keys) if (k is JsonObject ko && Delegation.SamePubkey(ko["data"]?["publickey"]?.Str, publickey)) { statement = ko; break; }
            if (statement == null) throw new DotrinoException("no encryption key announced for that identity", "no-encpub");
            string encPub = ReadEncPubStatement(statement, publickey);
            _encPubs[publickey] = encPub;
            return encPub;
        }

        static string ReadEncPubStatement(JsonObject statement, string publickey)
        {
            var data = statement["data"] as JsonObject;
            string sig = statement["signature"]?.Str;
            if (data == null || sig == null) throw new DotrinoException("encpub statement: malformed", "encpub-unverified");
            if (data["v"]?.Long != 1 || data["op"]?.Str != "encpub") throw new DotrinoException("encpub statement: not an announcement", "encpub-unverified");
            if (data["aud"]?.Str != "dotrino:encpub") throw new DotrinoException("encpub statement: wrong audience", "encpub-unverified");
            if (!Delegation.SamePubkey(data["publickey"]?.Str, publickey)) throw new DotrinoException("encpub statement: announces another identity", "encpub-unverified");
            string encPub = data["encpub"]?.Str ?? throw new DotrinoException("encpub statement: no key", "encpub-unverified");
            JsonValue jwk;
            try { jwk = JsonValue.Parse(encPub); } catch (FormatException) { jwk = null; }
            if (jwk?["kty"]?.Str != "EC" || jwk["crv"]?.Str != "P-256") throw new DotrinoException("encpub statement: not a P-256 public JWK", "encpub-unverified");
            if (!Crypto.Verify(data["publickey"].Str, data, sig))
                throw new DotrinoException("encpub statement: bad signature — the key is not bound to that identity", "encpub-unverified");
            return encPub;
        }

        // ---------- TURN ----------

        /// <summary><c>getTurnCredentials</c>: temporary ICE servers from the proxy for the direct road. Empty when it has no TURN.</summary>
        public async Task<List<IceServer>> TurnCredentials(string publickey, Func<JsonObject, Task<string>> sign)
        {
            var data = new JsonObject { { "op", "turn-credentials" }, { "publickey", publickey }, { "ts", NowMs() } };
            var res = await Request(new JsonObject { { "type", "turn-credentials" }, { "data", data }, { "signature", await sign(data).ConfigureAwait(false) } }).ConfigureAwait(false);
            var list = new List<IceServer>();
            if (!(res["enabled"] is JsonBool en && en.Value) || !(res["iceServers"] is JsonArray servers)) return list;
            foreach (var e in servers)
            {
                var urls = new List<string>();
                if (e["urls"] is JsonString one) urls.Add(one.Value);
                else if (e["urls"] is JsonArray many) foreach (var u in many) if (u.Str != null) urls.Add(u.Str);
                if (urls.Count > 0) list.Add(new IceServer(urls.ToArray(), e["username"]?.Str, e["credential"]?.Str));
            }
            return list;
        }

        // ---------- the short code people read out ----------

        /// <summary><c>requestPairingCode</c>: 6 characters that point to THIS connection, expire in minutes and burn when used.</summary>
        public async Task<(string code, long expiresAt)> RequestPairingCode(long? ttlMs = null)
        {
            var f = new JsonObject { { "type", "pair-code" } };
            if (ttlMs != null) f.Set("ttlMs", ttlMs.Value);
            var res = await Request(f).ConfigureAwait(false);
            string code = res["code"]?.Str ?? throw new DotrinoException("pair-code: no code in the answer", "pair-code-failed");
            return (code, res["expiresAt"]?.Long ?? 0);
        }

        /// <summary><c>redeemPairingCode</c>: the token behind someone's code. It does NOT say whose it is — greet it.</summary>
        public async Task<string> RedeemPairingCode(string code)
        {
            var res = await Request(new JsonObject { { "type", "pair-redeem" }, { "code", code } }).ConfigureAwait(false);
            string instance = res["instance"]?.Str;
            if (!(res["ok"] is JsonBool ok && ok.Value) || instance == null)
                throw new DotrinoException(res["error"]?.Str ?? "that code is not valid", "pair-invalid");
            return instance;
        }
    }
}
