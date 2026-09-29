package com.example.ipfinder;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Java port of the extension's background modules (dns, ip, asn, geo, whois, certificates, subdomains).
 * Same operations, same JSON shapes, same public APIs, so dashboard.js works unchanged.
 */
final class OsintService {
    private OsintService() {}

    private static final String DOH = "https://cloudflare-dns.com/dns-query";
    private static final String GEO = "https://ipwho.is/";
    private static final String ASN = "https://stat.ripe.net/data/prefix-overview/data.json";
    private static final String RDAP = "https://rdap.org/domain/";
    private static final String CT = "https://crt.sh/";
    private static final long MIN = 60_000L;
    private static final int MAX_BODY = 16 * 1024 * 1024;

    private static final Set<String> MULTI_TLD = new HashSet<>(Arrays.asList(
            "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "co.nz",
            "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "co.za", "com.br", "com.cn", "com.mx",
            "com.tr", "com.sg", "com.hk", "com.tw", "co.kr", "com.ar", "com.ua", "co.il", "com.my",
            "com.ph", "com.pk", "com.eg"));
    private static final String[] NON_PUBLIC = {".local", ".localhost", ".internal", ".lan", ".home",
            ".home.arpa", ".intranet", ".corp", ".private", ".test", ".invalid"};
    private static final Map<String, Integer> TYPES = new HashMap<>();
    static {
        TYPES.put("A", 1); TYPES.put("NS", 2); TYPES.put("CNAME", 5); TYPES.put("SOA", 6);
        TYPES.put("PTR", 12); TYPES.put("MX", 15); TYPES.put("TXT", 16); TYPES.put("AAAA", 28);
    }
    private static final String[] DNS_LIST = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"};

    // ---------------- dispatch ----------------
    static JSONObject run(String op, JSONObject p) throws Exception {
        switch (op) {
            case "dns": return dns(domain(p));
            case "ipv4": return ips(domain(p), "A");
            case "ipv6": return ips(domain(p), "AAAA");
            case "rdns": return rdns(p.getJSONArray("ips"));
            case "asn": return asn(ip(p));
            case "geo": return geo(ip(p));
            case "rdap": return rdap(domain(p));
            case "certs": return certs(domain(p));
            case "subdomains": return subdomains(domain(p));
            default: throw new IllegalArgumentException("Unknown operation");
        }
    }

    // ---------------- validation ----------------
    private static String domain(JSONObject p) {
        String d = p.optString("domain", "").toLowerCase(Locale.ROOT);
        if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (!isPublicDomain(d)) throw new IllegalArgumentException("Not a public domain name");
        return d;
    }

    private static String ip(JSONObject p) { return assertPublicIp(p.optString("ip", "")); }

    static boolean isValidHostname(String h) {
        if (h.isEmpty() || h.length() > 253) return false;
        String[] labels = h.split("\\.", -1);
        if (labels.length < 2) return false;
        for (String l : labels) if (!l.matches("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")) return false;
        return !labels[labels.length - 1].matches("^\\d+$");
    }

    static boolean isPublicDomain(String h) {
        if (!isValidHostname(h) || isV4(h)) return false;
        for (String s : NON_PUBLIC) if (h.endsWith(s)) return false;
        return true;
    }

    private static boolean isV4(String s) { return s.matches("^(\\d{1,3})(\\.\\d{1,3}){3}$"); }

    static String assertPublicIp(String s) {
        boolean literal = isV4(s) || (s.contains(":") && s.matches("^[0-9a-fA-F:]+$")); // never triggers a DNS lookup
        if (!literal) throw new IllegalArgumentException("Not a public IP address");
        try {
            InetAddress a = InetAddress.getByName(s);
            byte[] b = a.getAddress();
            boolean priv = a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                    || a.isSiteLocalAddress() || a.isMulticastAddress();
            if (b.length == 4) {
                int x = b[0] & 255, y = b[1] & 255;
                priv |= x == 0 || x >= 224 || (x == 100 && y >= 64 && y <= 127) || (x == 198 && (y == 18 || y == 19));
            } else {
                priv |= (b[0] & 0xFE) == 0xFC || (b[0] == 0 && b[1] == 0) || s.toLowerCase(Locale.ROOT).startsWith("2001:db8");
            }
            if (priv) throw new IllegalArgumentException("Not a public IP address");
            return a.getHostAddress().equals(s) ? s : s.toLowerCase(Locale.ROOT);
        } catch (java.net.UnknownHostException e) {
            throw new IllegalArgumentException("Not a public IP address");
        }
    }

    static String rootDomain(String host) {
        String[] l = host.split("\\.");
        int tld = l.length >= 2 && MULTI_TLD.contains(l[l.length - 2] + "." + l[l.length - 1]) ? 2 : 1;
        if (l.length <= tld) return host;
        return String.join(".", Arrays.copyOfRange(l, l.length - (tld + 1), l.length));
    }

    // ---------------- http + cache ----------------
    private static final ConcurrentHashMap<String, Object[]> CACHE = new ConcurrentHashMap<>();

    static void clearCache() { CACHE.clear(); }

    @SuppressWarnings("unchecked")
    private static <T> T cached(String key, long ttl, Callable<T> fn) throws Exception {
        Object[] e = CACHE.get(key);
        if (e != null && (long) e[0] > System.currentTimeMillis()) return (T) e[1];
        T v = fn.call();
        if (CACHE.size() > 500) CACHE.clear();
        CACHE.put(key, new Object[]{System.currentTimeMillis() + ttl, v});
        return v;
    }

    /** Returns JSONObject/JSONArray, or null on HTTP 404. Never sends cookies. */
    private static Object getJson(String url, String accept, int timeoutMs) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(timeoutMs);
        c.setReadTimeout(timeoutMs);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("Accept", accept);
        c.setRequestProperty("User-Agent", "IPFinder-OSINT/2.0");
        try {
            int code = c.getResponseCode();
            if (code == 404) return null;
            if (code >= 400) throw new java.io.IOException("HTTP " + code);
            try (InputStream in = c.getInputStream()) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[16384];
                int n, total = 0;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_BODY) throw new java.io.IOException("Response too large");
                    out.write(buf, 0, n);
                }
                return new JSONTokener(out.toString("UTF-8")).nextValue();
            }
        } finally {
            c.disconnect();
        }
    }

    private static String enc(String s) throws Exception { return URLEncoder.encode(s, "UTF-8"); }

    // ---------------- operations ----------------
    private static List<String> dnsAnswers(String name, String type) throws Exception {
        if (!TYPES.containsKey(type)) throw new IllegalArgumentException("Unsupported DNS type");
        return cached("dns:" + type + ":" + name, 5 * MIN, () -> {
            Object o = getJson(DOH + "?name=" + enc(name) + "&type=" + type, "application/dns-json", 8000);
            if (!(o instanceof JSONObject) || !((JSONObject) o).has("Status")) throw new java.io.IOException("Unexpected response format");
            JSONArray ans = ((JSONObject) o).optJSONArray("Answer");
            List<String> out = new ArrayList<>();
            for (int i = 0; ans != null && i < ans.length(); i++) {
                JSONObject a = ans.getJSONObject(i);
                if (a.optInt("type") != TYPES.get(type)) continue;
                String d = a.optString("data");
                out.add("TXT".equals(type) ? d.replaceAll("^\"|\"$", "") : d);
            }
            return out;
        });
    }

    private static JSONObject dns(String domain) throws Exception {
        JSONObject records = new JSONObject(), errors = new JSONObject();
        for (String t : DNS_LIST) {
            try { records.put(t, new JSONArray(dnsAnswers(domain, t))); }
            catch (Exception e) { records.put(t, new JSONArray()); errors.put(t, String.valueOf(e.getMessage())); }
        }
        if (errors.length() == DNS_LIST.length) throw new java.io.IOException("DNS service unreachable");
        return new JSONObject().put("domain", domain).put("records", records).put("errors", errors);
    }

    private static JSONObject ips(String domain, String type) throws Exception {
        JSONArray out = new JSONArray();
        for (String a : dnsAnswers(domain, type)) {
            if ("A".equals(type) ? isV4(a) : a.contains(":")) out.put(a);
        }
        return new JSONObject().put("domain", domain).put("ips", out);
    }

    private static String ptrName(String ip) {
        if (isV4(ip)) {
            String[] o = ip.split("\\.");
            return o[3] + "." + o[2] + "." + o[1] + "." + o[0] + ".in-addr.arpa";
        }
        String[] parts = ip.toLowerCase(Locale.ROOT).split("::", -1);
        List<String> h = parts[0].isEmpty() ? new ArrayList<>() : new ArrayList<>(Arrays.asList(parts[0].split(":")));
        List<String> t = parts.length > 1 && !parts[1].isEmpty() ? Arrays.asList(parts[1].split(":")) : new ArrayList<>();
        StringBuilder hex = new StringBuilder();
        List<String> all = new ArrayList<>(h);
        if (parts.length > 1) for (int i = 0; i < 8 - h.size() - t.size(); i++) all.add("0");
        all.addAll(t);
        for (String x : all) hex.append(("0000" + x).substring(x.length()));
        StringBuilder r = new StringBuilder();
        for (int i = hex.length() - 1; i >= 0; i--) r.append(hex.charAt(i)).append('.');
        return r + "ip6.arpa";
    }

    private static JSONObject rdns(JSONArray input) throws Exception {
        LinkedHashSet<String> list = new LinkedHashSet<>();
        for (int i = 0; i < input.length() && list.size() < 6; i++) list.add(assertPublicIp(input.getString(i)));
        JSONArray results = new JSONArray();
        for (String ip : list) {
            JSONObject r = new JSONObject().put("ip", ip);
            JSONArray ptr = new JSONArray();
            try { for (String s : dnsAnswers(ptrName(ip), "PTR")) ptr.put(s.replaceAll("\\.$", "")); }
            catch (Exception e) { r.put("error", String.valueOf(e.getMessage())); }
            results.put(r.put("ptr", ptr));
        }
        return new JSONObject().put("results", results);
    }

    private static JSONObject asn(String ip) throws Exception {
        return cached("asn:" + ip, 30 * MIN, () -> {
            Object o = getJson(ASN + "?resource=" + enc(ip), "application/json", 10000);
            if (!(o instanceof JSONObject) || !"ok".equals(((JSONObject) o).optString("status"))) throw new java.io.IOException("Unexpected response format");
            JSONObject d = ((JSONObject) o).getJSONObject("data");
            JSONArray asns = d.optJSONArray("asns");
            JSONObject first = asns != null && asns.length() > 0 ? asns.getJSONObject(0) : null;
            JSONObject block = d.optJSONObject("block");
            String desc = block == null ? null : (block.optString("desc", "").isEmpty() ? block.optString("name", null) : block.optString("desc"));
            return new JSONObject().put("ip", ip)
                    .put("asn", first == null ? JSONObject.NULL : "AS" + first.optLong("asn"))
                    .put("holder", first == null ? JSONObject.NULL : first.optString("holder"))
                    .put("prefix", d.optString("resource", null))
                    .put("description", desc == null || desc.isEmpty() ? JSONObject.NULL : desc);
        });
    }

    private static JSONObject geo(String ip) throws Exception {
        return cached("geo:" + ip, 30 * MIN, () -> {
            Object o = getJson(GEO + enc(ip), "application/json", 10000);
            if (!(o instanceof JSONObject)) throw new java.io.IOException("Unexpected response format");
            JSONObject j = (JSONObject) o;
            if (!j.optBoolean("success", true)) throw new java.io.IOException(j.optString("message", "Geolocation lookup failed"));
            JSONObject c = j.optJSONObject("connection") == null ? new JSONObject() : j.getJSONObject("connection");
            JSONObject tz = j.optJSONObject("timezone");
            return new JSONObject().put("ip", j.optString("ip")).put("country", j.opt("country"))
                    .put("countryCode", j.opt("country_code")).put("region", j.opt("region")).put("city", j.opt("city"))
                    .put("latitude", j.opt("latitude")).put("longitude", j.opt("longitude"))
                    .put("timezone", tz == null ? JSONObject.NULL : tz.opt("id"))
                    .put("isp", c.opt("isp")).put("org", c.opt("org"))
                    .put("asn", c.has("asn") ? "AS" + c.optLong("asn") : JSONObject.NULL).put("domain", c.opt("domain"));
        });
    }

    private static JSONObject rdap(String domain) throws Exception {
        String root = rootDomain(domain);
        Object o = cached("rdap:" + root, 360 * MIN, () -> {
            Object r = getJson(RDAP + enc(root), "application/rdap+json, application/json", 12000);
            return r == null ? JSONObject.NULL : r;
        });
        if (!(o instanceof JSONObject)) return new JSONObject().put("domain", root).put("found", false);
        JSONObject j = (JSONObject) o;

        Map<String, String> ev = new HashMap<>();
        JSONArray events = j.optJSONArray("events");
        for (int i = 0; events != null && i < events.length(); i++) {
            JSONObject e = events.getJSONObject(i);
            ev.put(e.optString("eventAction"), e.optString("eventDate", null));
        }
        String registrar = null;
        JSONArray ents = j.optJSONArray("entities");
        for (int i = 0; ents != null && i < ents.length() && registrar == null; i++) {
            JSONObject e = ents.getJSONObject(i);
            JSONArray roles = e.optJSONArray("roles");
            if (roles == null || !roles.toString().contains("registrar")) continue;
            JSONArray vc = e.optJSONArray("vcardArray");
            JSONArray props = vc != null && vc.length() > 1 ? vc.optJSONArray(1) : null;
            for (int k = 0; props != null && k < props.length(); k++) {
                JSONArray p = props.optJSONArray(k);
                if (p != null && "fn".equals(p.optString(0))) { registrar = p.optString(3, null); break; }
            }
        }
        String reg = ev.get("registration");
        Object age = JSONObject.NULL;
        try { if (reg != null) age = (System.currentTimeMillis() - Instant.parse(reg).toEpochMilli()) / 86_400_000L; } catch (Exception ignored) { }
        return new JSONObject().put("domain", root).put("found", true)
                .put("registrar", registrar == null ? JSONObject.NULL : registrar)
                .put("registered", reg == null ? JSONObject.NULL : reg)
                .put("updated", ev.get("last changed") == null ? JSONObject.NULL : ev.get("last changed"))
                .put("expires", ev.get("expiration") == null ? JSONObject.NULL : ev.get("expiration"))
                .put("ageDays", age)
                .put("status", j.optJSONArray("status") == null ? new JSONArray() : j.getJSONArray("status"));
    }

    private static List<String> ctNames(String root, int[] certCount) throws Exception {
        Object[] r = cached("ct:" + root, 30 * MIN, () -> {
            Object o = getJson(CT + "?q=" + enc("%." + root) + "&output=json", "application/json", 25000);
            if (!(o instanceof JSONArray)) throw new java.io.IOException("Unexpected response format");
            JSONArray rows = (JSONArray) o;
            TreeSet<String> names = new TreeSet<>();
            for (int i = 0; i < rows.length(); i++) {
                JSONObject row = rows.getJSONObject(i);
                String all = row.optString("name_value", "") + "\n" + row.optString("common_name", "");
                for (String n : all.split("\n")) {
                    String s = n.trim().toLowerCase(Locale.ROOT).replaceFirst("^\\*\\.", "");
                    if (!s.isEmpty()) names.add(s);
                }
            }
            return new Object[]{rows.length(), new ArrayList<>(names)};
        });
        certCount[0] = (int) r[0];
        @SuppressWarnings("unchecked") List<String> names = (List<String>) r[1];
        return names;
    }

    private static JSONObject certs(String domain) throws Exception {
        String root = rootDomain(domain);
        int[] count = new int[1];
        List<String> names = ctNames(root, count);
        JSONArray out = new JSONArray();
        for (int i = 0; i < names.size() && i < 1000; i++) out.put(names.get(i));
        return new JSONObject().put("domain", root).put("certificateCount", count[0]).put("total", names.size()).put("names", out);
    }

    private static JSONObject subdomains(String domain) throws Exception {
        String root = rootDomain(domain);
        List<String> names = ctNames(root, new int[1]);
        JSONArray items = new JSONArray();
        int checked = 0;
        for (String n : names) {
            if (n.equals(root) || !n.endsWith("." + root) || !isValidHostname(n)) continue;
            if (items.length() >= 300) break;
            String status = "not checked";
            if (checked < 25) {
                checked++;
                try { status = dnsAnswers(n, "A").isEmpty() ? "no A record" : "resolves"; }
                catch (Exception e) { status = "unknown"; }
            }
            items.put(new JSONObject().put("name", n).put("source", "crt.sh (Certificate Transparency)").put("status", status));
        }
        return new JSONObject().put("domain", root).put("total", items.length()).put("checked", checked).put("items", items);
    }
}
