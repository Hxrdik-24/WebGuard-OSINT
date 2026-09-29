package com.example.ipfinder;

import android.content.Context;
import android.content.SharedPreferences;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import org.json.JSONObject;

import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * JS <-> Java bridge. Every call needs the per-page-load token that only the injected dashboard closure
 * knows, so scripts of the visited page cannot use the bridge. All operations are passive public
 * lookups and are re-validated in OsintService.
 */
final class OsintBridge {
    private final WebView web;
    private final SharedPreferences prefs;
    private final ExecutorService pool = Executors.newFixedThreadPool(4);
    private volatile String token = "";

    OsintBridge(Context ctx, WebView web) {
        this.web = web;
        this.prefs = ctx.getSharedPreferences("osint", Context.MODE_PRIVATE);
    }

    void newSession() { token = UUID.randomUUID().toString().replace("-", ""); }
    String token() { return token; }
    private boolean ok(String t) { return t != null && !token.isEmpty() && token.equals(t); }

    @JavascriptInterface
    public void request(String t, int id, String op, String paramsJson) {
        if (!ok(t)) return;
        final String tokenAtRequest = t;
        pool.execute(() -> {
            try {
                JSONObject result = OsintService.run(op, new JSONObject(paramsJson));
                reply(tokenAtRequest, id, true, result.toString());
            } catch (Exception e) {
                reply(tokenAtRequest, id, false, e.getMessage() == null ? "Request failed" : e.getMessage());
            }
        });
    }

    @JavascriptInterface
    public String getPosition(String t) {
        if (!ok(t) || !prefs.contains("left")) return "";
        return "{\"left\":" + prefs.getFloat("left", 0) + ",\"top\":" + prefs.getFloat("top", 0) + "}";
    }

    @JavascriptInterface
    public void setPosition(String t, double left, double top) {
        if (ok(t)) prefs.edit().putFloat("left", (float) left).putFloat("top", (float) top).apply();
    }

    @JavascriptInterface
    public void clearCache(String t) { if (ok(t)) OsintService.clearCache(); }

    private void reply(String t, int id, boolean ok, String payload) {
        if (!t.equals(token)) return; // page changed meanwhile
        String js = "(function(f){f&&f(" + id + "," + ok + "," + JSONObject.quote(payload) + ")})(window['__osint_" + t + "'])";
        web.post(() -> web.evaluateJavascript(js, null));
    }
}
