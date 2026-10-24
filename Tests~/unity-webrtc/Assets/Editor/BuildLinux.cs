using UnityEditor;
using UnityEditor.SceneManagement;

static class BuildLinux
{
    static void Run()
    {
        var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);
        EditorSceneManager.SaveScene(scene, "Assets/Main.unity");
        PlayerSettings.runInBackground = true;
        var r = BuildPipeline.BuildPlayer(new[] { "Assets/Main.unity" }, "Build/wtest.x86_64", BuildTarget.StandaloneLinux64, BuildOptions.None);
        UnityEngine.Debug.Log("BUILD " + r.summary.result + " errors " + r.summary.totalErrors);
        if (r.summary.result != UnityEditor.Build.Reporting.BuildResult.Succeeded) EditorApplication.Exit(1);
    }
}
