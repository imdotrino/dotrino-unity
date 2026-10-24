using System;
using System.Collections.Generic;

namespace Dotrino
{
    /// <summary>
    /// THE DIRECT ROAD (WebRTC direct, WebRTC through TURN), as the <c>WebRTCManager</c> of
    /// <c>@dotrino/proxy-client</c> and dotrino-native's <c>DirectTransport</c>. The core does not
    /// carry libwebrtc (~10 MB per architecture): a game that wants it installs
    /// <c>com.unity.webrtc</c> and gets <c>UnityWebRtcDirect</c> from the Dotrino.Unity.WebRTC assembly.
    ///
    /// Wire-compatible with the JS: signalling goes through the proxy as
    /// <c>{ t: '__cc_rtc__', kind: 'sdp' | 'ice', … }</c>; the data channel is <c>cc</c>, ordered,
    /// opened by the peer with the greater token. Never blocks: the first message goes by the
    /// proxy and the channel is negotiated underneath.
    /// </summary>
    public interface IDirectTransport
    {
        /// <summary>Wiring, set by <see cref="SealedSession.UseDirect"/>: my token, how to signal, where arrivals go.</summary>
        void Bind(Func<string> selfToken, Action<string, JsonObject> signalSend, Action<string, string> deliver, Action<string, byte[]> deliverBinary);

        /// <summary>A package as a binary message over the open channel to <paramref name="token"/>. False = there is none; use the proxy.</summary>
        bool SendBinary(string token, byte[] bytes);

        /// <summary>Starts negotiating with <paramref name="token"/> if not already (best effort: no wait, no error).</summary>
        void Upgrade(string token);

        /// <summary>A signalling frame (<c>t == RtcTag</c>) that arrived from <paramref name="from"/> through the proxy.</summary>
        void HandleSignal(string from, JsonObject msg);

        bool IsOpen(string token);

        /// <summary>Where <paramref name="token"/> goes NOW: <c>direct</c> / <c>turn</c> / <c>webrtc</c> / <c>connecting</c> / <c>failed</c>, or null (the proxy).</summary>
        string Route(string token);

        void Close(string token);
        void CloseAll();

        /// <summary>ICE servers for the NEXT connections (TURN credentials + STUN).</summary>
        void SetIceServers(IReadOnlyList<IceServer> servers);
    }

    public sealed class IceServer
    {
        public readonly string[] Urls;
        public readonly string Username, Credential;
        public IceServer(string[] urls, string username = null, string credential = null) { Urls = urls; Username = username; Credential = credential; }

        /// <summary><c>DEFAULT_ICE_SERVERS</c> of the JS client.</summary>
        public static readonly IReadOnlyList<IceServer> DefaultStun = new[]
        {
            new IceServer(new[] { "stun:stun.l.google.com:19302" }),
            new IceServer(new[] { "stun:stun1.l.google.com:19302" }),
            new IceServer(new[] { "stun:global.stun.twilio.com:3478" }),
        };
    }
}
