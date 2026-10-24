using System;
using System.Collections;
using System.Threading.Tasks;
using Dotrino;
using UnityEngine;

// Dos sesiones en el mismo proceso, cada una con su WebRTC, por el proxio de producción: el primer
// mensaje va por el proxio, el canal se abre por debajo, y el segundo tiene que llegar por él.
public class DirectTest : MonoBehaviour
{
    const string Url = "wss://proxy.dotrino.com";
    int _failed;

    [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
    static void Boot() => new GameObject("test").AddComponent<DirectTest>();

    void Log(string s) => Debug.Log("DOTRINO-TEST " + s);
    void Check(bool ok, string what) { if (!ok) _failed++; Log((ok ? "ok   " : "FAIL ") + what); }

    IEnumerator Start()
    {
        var ka = SoftwareKeys.Generate();
        var kb = SoftwareKeys.Generate();
        var a = new SealedSession(new[] { Url }, ka, "autoball");
        var b = new SealedSession(new[] { Url }, kb, "autoball");
        var da = new UnityWebRtcDirect();
        var db = new UnityWebRtcDirect();
        da.Warn += (w, e) => Log("warn a: " + w + " " + e?.Message);
        db.Warn += (w, e) => Log("warn b: " + w + " " + e?.Message);
        a.UseDirect(da);
        b.UseDirect(db);
        SealedSession.Received got = null;
        b.Message += m => got = m;
        a.Start(); b.Start();

        yield return Wait(Task.WhenAll(a.AwaitOnline(), b.AwaitOnline()), 20);
        Check(a.IsOnline && b.IsOnline, "both online");
        yield return Wait(a.WhoIs(b.Token), 10);

        var first = a.SendSealedTo(b.Token, new JsonObject { { "op", "kickoff" } });
        yield return Wait(first, 10);
        for (int i = 0; i < 100 && got == null; i++) yield return new WaitForSeconds(0.1f);
        Check(got != null && got.Payload["op"].Str == "kickoff", "first message arrived");
        Check(got != null && got.Via == "proxy", "first message came by the proxy (got " + got?.Via + ")");

        for (int i = 0; i < 200 && a.RouteOf(b.Token) != "webrtc"; i++) yield return new WaitForSeconds(0.1f);
        Check(a.RouteOf(b.Token) == "webrtc", "the channel opened underneath (route " + a.RouteOf(b.Token) + ")");

        got = null;
        yield return Wait(a.SendSealedTo(b.Token, new JsonObject { { "op", "goal" } }), 10);
        for (int i = 0; i < 100 && got == null; i++) yield return new WaitForSeconds(0.1f);
        Check(got != null && got.Payload["op"].Str == "goal", "second message arrived");
        Check(got != null && got.Via == "direct", "second message came direct, not by the proxy (got " + got?.Via + ")");
        Check(got != null && got.SenderEncPub == ka.EncPub, "it is sealed by a");

        Log("done " + _failed);
        a.Dispose(); b.Dispose(); da.Dispose(); db.Dispose();
        yield return new WaitForSeconds(0.5f);
        Application.Quit(_failed == 0 ? 0 : 1);
    }

    IEnumerator Wait(Task t, float seconds)
    {
        float until = Time.realtimeSinceStartup + seconds;
        while (!t.IsCompleted && Time.realtimeSinceStartup < until) yield return null;
        if (t.IsFaulted) Log("task failed: " + t.Exception?.GetBaseException().Message);
    }
}
