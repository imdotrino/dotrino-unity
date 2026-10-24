using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Unity.WebRTC;
using UnityEngine;

namespace Dotrino
{
    /// <summary>
    /// THE DIRECT ROAD in Unity: the <c>WebRTCManager</c> of <c>@dotrino/proxy-client</c> over
    /// <c>com.unity.webrtc</c>, the port of dotrino-native's <c>WebRtcDirect</c>. One peer
    /// connection + one data channel (<c>cc</c>, ordered) per remote token; the peer with the
    /// GREATER token opens the channel and makes the offer, the one with the smaller token is the
    /// «polite» one (it yields on an offer collision), exactly as the JS.
    ///
    /// Everything runs on Unity's MAIN THREAD: com.unity.webrtc completes its operations there
    /// (they are coroutines), and the negotiation state of a peer must not be touched from two
    /// threads. Calls from any thread are queued to a hidden runner.
    /// </summary>
    public sealed class UnityWebRtcDirect : IDirectTransport, IDisposable
    {
        sealed class Peer
        {
            public readonly string Remote;
            public RTCPeerConnection Pc;
            public RTCDataChannel Dc;
            public bool MakingOffer, Negotiating, Failed, HasRemote;   // RemoteDescription throws while there is none
            public readonly List<RTCIceCandidateInit> Pending = new List<RTCIceCandidateInit>();
            public Peer(string remote) { Remote = remote; }
        }

        sealed class Runner : MonoBehaviour
        {
            public readonly ConcurrentQueue<Action> Queue = new ConcurrentQueue<Action>();
            void Update() { while (Queue.TryDequeue(out var a)) { try { a(); } catch (Exception e) { Debug.LogWarning("dotrino-webrtc: " + e); } } }
        }

        readonly Runner _runner;
        readonly ConcurrentDictionary<string, Peer> _peers = new ConcurrentDictionary<string, Peer>();
        IReadOnlyList<IceServer> _iceServers = IceServer.DefaultStun;
        Func<string> _selfToken = () => null;
        Action<string, JsonObject> _signalSend = (_, __) => { };
        Action<string, string> _deliver = (_, __) => { };
        Action<string, byte[]> _deliverBinary = (_, __) => { };

        /// <summary>Who may make me negotiate (null = anyone who can reach me, like the JS default).</summary>
        public Func<string, bool> AcceptFrom;
        public event Action<string, Exception> Warn;
        public event Action<string> Opened;

        /// <summary>Create it on the main thread (it adds a hidden GameObject that runs the negotiation).</summary>
        public UnityWebRtcDirect()
        {
            var go = new GameObject("dotrino-webrtc") { hideFlags = HideFlags.HideAndDontSave };
            UnityEngine.Object.DontDestroyOnLoad(go);
            _runner = go.AddComponent<Runner>();
            _runner.StartCoroutine(WebRTC.Update());
        }

        void Main(Action a) => _runner.Queue.Enqueue(a);
        void OnWarn(string what, Exception e) { try { Warn?.Invoke(what, e); } catch (Exception) { } }

        bool Polite(Peer p) { string self = _selfToken(); return self != null && string.CompareOrdinal(self, p.Remote) < 0; }

        public void Bind(Func<string> selfToken, Action<string, JsonObject> signalSend, Action<string, string> deliver, Action<string, byte[]> deliverBinary)
        {
            _selfToken = selfToken; _signalSend = signalSend; _deliver = deliver; _deliverBinary = deliverBinary;
        }

        public void SetIceServers(IReadOnlyList<IceServer> servers) { if (servers != null && servers.Count > 0) Main(() => _iceServers = servers); }

        public bool IsOpen(string token) => _peers.TryGetValue(token, out var p) && p.Dc != null && p.Dc.ReadyState == RTCDataChannelState.Open;

        public string Route(string token)
        {
            if (!_peers.TryGetValue(token, out var p)) return null;
            if (p.Dc != null && p.Dc.ReadyState == RTCDataChannelState.Open) return "webrtc";
            return p.Failed ? "failed" : p.Negotiating ? "connecting" : null;
        }

        public bool SendBinary(string token, byte[] bytes)
        {
            if (!_peers.TryGetValue(token, out var p) || p.Dc == null || p.Dc.ReadyState != RTCDataChannelState.Open) return false;
            try { p.Dc.Send(bytes); return true; }
            catch (Exception e) { OnWarn("webrtc send to " + token, e); return false; }
        }

        public void Upgrade(string token) => Main(() => StartNegotiation(PeerOf(token)));

        void StartNegotiation(Peer p)
        {
            if (p.Negotiating || p.Failed || IsOpen(p.Remote)) return;
            p.Negotiating = true;
            try
            {
                if (p.Pc == null) CreatePc(p);
                // The side with the greater token opens the channel; the other gets it (OnDataChannel).
                string self = _selfToken();
                if (self == null || p.Dc != null) return;
                int cmp = string.CompareOrdinal(self, p.Remote);
                if (cmp > 0) Attach(p, p.Pc.CreateDataChannel("cc", new RTCDataChannelInit { ordered = true }));
                // THE ONE THAT DOES NOT CREATE THE CHANNEL HAS TO ASK FOR IT (`kind: 'start'` of the
                // JS): with no new channel there is nothing to negotiate, so if the smaller token
                // wanted to go direct the other side would never know.
                else if (cmp < 0) Signal(p, new JsonObject { { "kind", "start" } });
            }
            catch (Exception e) { OnWarn("webrtc start with " + p.Remote, e); Fail(p); }
        }

        public void HandleSignal(string from, JsonObject msg) => Main(() =>
        {
            if (AcceptFrom != null && !AcceptFrom(from)) return;
            try { OnSignal(PeerOf(from), msg); }
            catch (Exception e) { OnWarn("webrtc signal from " + from, e); }
        });

        public void Close(string token) => Main(() =>
        {
            if (!_peers.TryRemove(token, out var p)) return;
            try { p.Dc?.Close(); } catch (Exception) { }
            try { p.Pc?.Close(); } catch (Exception) { }
        });

        public void CloseAll() { foreach (var t in _peers.Keys) Close(t); }

        public void Dispose()
        {
            CloseAll();
            Main(() => UnityEngine.Object.Destroy(_runner.gameObject));
        }

        // ---------- internals (all on the main thread) ----------

        Peer PeerOf(string token) => _peers.GetOrAdd(token, t => new Peer(t));

        void Signal(Peer p, JsonObject body)
        {
            var m = new JsonObject { { "t", ProxyConnection.RtcTag } };
            foreach (var kv in body) m.Set(kv.Key, kv.Value);
            _signalSend(p.Remote, m);
        }

        static JsonObject SdpJson(RTCSessionDescription d) => new JsonObject
        {
            { "kind", "sdp" },
            { "sdp", new JsonObject { { "type", d.type.ToString().ToLowerInvariant() }, { "sdp", d.sdp } } },
        };

        RTCPeerConnection CreatePc(Peer p)
        {
            var servers = new RTCIceServer[_iceServers.Count];
            for (int i = 0; i < servers.Length; i++)
                servers[i] = new RTCIceServer
                {
                    urls = _iceServers[i].Urls, username = _iceServers[i].Username, credential = _iceServers[i].Credential,
                    credentialType = RTCIceCredentialType.Password,
                };
            var cfg = new RTCConfiguration { iceServers = servers };
            var pc = new RTCPeerConnection(ref cfg);
            pc.OnIceCandidate = c => Signal(p, new JsonObject
            {
                { "kind", "ice" },
                { "candidate", new JsonObject { { "candidate", c.Candidate }, { "sdpMid", c.SdpMid }, { "sdpMLineIndex", c.SdpMLineIndex ?? 0 } } },
            });
            pc.OnConnectionStateChange = s => { if (s == RTCPeerConnectionState.Failed || s == RTCPeerConnectionState.Closed) Fail(p); };
            pc.OnDataChannel = dc => Attach(p, dc);
            pc.OnNegotiationNeeded = () => _runner.StartCoroutine(MakeOffer(p));
            p.Pc = pc;
            return pc;
        }

        IEnumerator MakeOffer(Peer p)
        {
            var pc = p.Pc;
            if (pc == null) yield break;
            p.MakingOffer = true;
            var offer = pc.CreateOffer();
            yield return offer;
            if (offer.IsError) { p.MakingOffer = false; OnWarn("webrtc offer: " + offer.Error.message, null); yield break; }
            var desc = offer.Desc;
            var set = pc.SetLocalDescription(ref desc);
            yield return set;
            p.MakingOffer = false;
            if (set.IsError) { OnWarn("webrtc set local: " + set.Error.message, null); yield break; }
            Signal(p, SdpJson(pc.LocalDescription));
        }

        void OnSignal(Peer p, JsonObject msg)
        {
            var pc = p.Pc ?? CreatePc(p);
            switch (msg["kind"]?.Str)
            {
                case "start":
                    // The other wants to go direct and the channel is ours to create. Only the
                    // greater token answers it, so a `start` never bounces.
                    string self = _selfToken();
                    if (self != null && string.CompareOrdinal(self, p.Remote) > 0 && p.Dc == null)
                    {
                        p.Negotiating = false;
                        StartNegotiation(p);
                    }
                    break;
                case "sdp":
                    string type = msg["sdp"]?["type"]?.Str, text = msg["sdp"]?["sdp"]?.Str;
                    if (type == null || text == null) return;
                    bool collision = type == "offer" && (p.MakingOffer || pc.SignalingState != RTCSignalingState.Stable);
                    if (!Polite(p) && collision) return;   // the impolite side ignores a colliding offer
                    _runner.StartCoroutine(Remote(p, type, text));
                    break;
                case "ice":
                    var c = msg["candidate"];
                    string cand = c?["candidate"]?.Str;
                    if (cand == null) return;
                    var init = new RTCIceCandidateInit { candidate = cand, sdpMid = c["sdpMid"]?.Str ?? "0", sdpMLineIndex = (int?)(c["sdpMLineIndex"]?.Long ?? 0) };
                    if (!p.HasRemote) p.Pending.Add(init);
                    else pc.AddIceCandidate(new RTCIceCandidate(init));
                    break;
            }
        }

        IEnumerator Remote(Peer p, string type, string text)
        {
            var pc = p.Pc;
            var desc = new RTCSessionDescription { type = type == "offer" ? RTCSdpType.Offer : type == "answer" ? RTCSdpType.Answer : RTCSdpType.Pranswer, sdp = text };
            var set = pc.SetRemoteDescription(ref desc);
            yield return set;
            if (set.IsError) { OnWarn("webrtc set remote: " + set.Error.message, null); yield break; }
            p.HasRemote = true;
            foreach (var c in p.Pending) pc.AddIceCandidate(new RTCIceCandidate(c));
            p.Pending.Clear();
            if (type != "offer") yield break;
            var answer = pc.CreateAnswer();
            yield return answer;
            if (answer.IsError) { OnWarn("webrtc answer: " + answer.Error.message, null); yield break; }
            var a = answer.Desc;
            var setLocal = pc.SetLocalDescription(ref a);
            yield return setLocal;
            if (setLocal.IsError) { OnWarn("webrtc set local: " + setLocal.Error.message, null); yield break; }
            Signal(p, SdpJson(pc.LocalDescription));
        }

        void Attach(Peer p, RTCDataChannel dc)
        {
            p.Dc = dc;
            dc.OnOpen = () => { p.Negotiating = false; try { Opened?.Invoke(p.Remote); } catch (Exception) { } };
            // A channel that closes is tried again with the next message (JS: webrtc_close).
            dc.OnClose = () => { if (_peers.TryGetValue(p.Remote, out var cur) && cur == p) { _peers.TryRemove(p.Remote, out _); try { p.Pc?.Close(); } catch (Exception) { } } };
            // com.unity.webrtc hands both text and binary messages as bytes; a package starts with
            // its magic byte (0xB1), so the text messages of an older JS client are told apart.
            dc.OnMessage = bytes =>
            {
                if (BinPack.IsPacked(bytes)) _deliverBinary(p.Remote, bytes);
                else _deliver(p.Remote, System.Text.Encoding.UTF8.GetString(bytes));
            };
        }

        void Fail(Peer p) { p.Failed = true; p.Negotiating = false; }
    }
}
