package com.example.ipfinder;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.ProgressBar;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/** Address bar -> WebView -> floating OSINT button -> dashboard (same UI as the Chrome extension). */
public class MainActivity extends AppCompatActivity {
    // Same load order as the extension's content_scripts list.
    private static final String[] SCRIPTS = {
            "utils/validators.js", "utils/formatters.js", "utils/http.js",
            "modules/headers.js", "modules/security.js", "modules/technology.js", "modules/robots.js",
            "modules/sitemap.js", "modules/metadata.js", "modules/resources.js", "modules/report.js",
            "ui/dashboard.js"
    };

    private WebView web;
    private EditText address;
    private ProgressBar progress;
    private OsintBridge bridge;
    private String bundle; // all shared JS + platform adapter, with __TOKEN__ placeholder

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_main);
        web = findViewById(R.id.web);
        address = findViewById(R.id.address);
        progress = findViewById(R.id.progress);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSafeBrowsingEnabled(true);

        bridge = new OsintBridge(this, web);
        web.addJavascriptInterface(bridge, "OsintNative");

        // No onReceivedSslError override: invalid certificates are rejected (TLS is never bypassed).
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                String sc = r.getUrl().getScheme();
                return !("https".equals(sc) || "http".equals(sc)); // block intent:, file:, etc.
            }
            @Override public void onPageStarted(WebView v, String url, Bitmap icon) {
                address.setText(url);
                bridge.newSession();
            }
            @Override public void onPageFinished(WebView v, String url) {
                if (url != null && url.startsWith("http")) inject();
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public void onProgressChanged(WebView v, int p) {
                progress.setProgress(p);
                progress.setVisibility(p < 100 ? View.VISIBLE : View.GONE);
            }
        });

        address.setOnEditorActionListener((v, a, e) -> { go(address.getText().toString()); return true; });
        findViewById(R.id.go).setOnClickListener(v -> go(address.getText().toString()));

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (web.canGoBack()) web.goBack();
                else { setEnabled(false); getOnBackPressedDispatcher().onBackPressed(); }
            }
        });

        go("https://duckduckgo.com");
    }

    private void go(String input) {
        String q = input.trim();
        if (q.isEmpty()) return;
        String url;
        if (q.matches("(?i)^https?://.+")) url = q;
        else if (!q.contains(" ") && q.contains(".")) url = "https://" + q;
        else url = "https://duckduckgo.com/?q=" + android.net.Uri.encode(q);
        web.loadUrl(url);
        web.requestFocus();
    }

    private void inject() {
        try {
            if (bundle == null) bundle = buildBundle();
            web.evaluateJavascript(bundle.replace("__TOKEN__", bridge.token()), null);
        } catch (Exception ignored) { }
    }

    private String buildBundle() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (String f : SCRIPTS) sb.append(read("osint/" + f)).append("\n;\n");
        String css = JSONObject.quote(read("osint/style.css"));
        sb.append(read("android-platform.js").replace("__CSS__", css));
        return sb.toString();
    }

    private String read(String asset) throws Exception {
        try (InputStream in = getAssets().open(asset)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toString("UTF-8");
        }
    }
}
