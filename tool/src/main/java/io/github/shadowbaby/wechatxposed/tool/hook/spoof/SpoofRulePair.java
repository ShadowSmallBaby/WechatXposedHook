package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;


public final class SpoofRulePair {
    public final String hooksVersion;
    public final String profileVersion;
    public final String hostVersion;
    public final int hostVersionCode;
    public final String hostClientVersion;
    final JSONObject normalized;

    private SpoofRulePair(JSONObject hooks, JSONObject profile) throws Exception {
        hooksVersion = SpoofCodec.version(hooks);
        profileVersion = SpoofCodec.version(profile);
        String identity = text(hooks, "hooksId");
        if (!identity.matches("[0-9a-f]{64}") || !identity.equals(text(profile, "hooksId")))
            throw new IllegalArgumentException("Mismatched H/S pair");
        only(hooks, "bindings", "m", "hooksId", "VERSION");
        hostVersion = text(profile, "hostVersion");
        if (!hostVersion.matches("8\\.\\d+\\.\\d+")) throw new IllegalArgumentException("Host version");
        Object code = profile.opt("hostVersionCode");
        if (!(code instanceof Number n) || n.intValue() <= 0 || n.doubleValue() != n.intValue())
            throw new IllegalArgumentException("Host code");
        hostVersionCode = n.intValue();
        hostClientVersion = text(profile, "hostClientVersion");
        if (!hostClientVersion.matches("0x[0-9a-f]{8}")) throw new IllegalArgumentException("Host client version");
        JSONObject groups = new JSONObject();
        for (String kind : new String[]{"strings", "integers", "signatures", "calls", "properties"}) groups.put(kind, new JSONObject());
        var keys = profile.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (key.equals("hostVersion") || key.equals("hostVersionCode") || key.equals("hostClientVersion") || key.equals("VERSION") || key.equals("hooksId")) continue;
            if (!key.matches("[A-Za-z][A-Za-z0-9]*(\\.[A-Za-z][A-Za-z0-9]*)+")) throw new IllegalArgumentException("Non-semantic rule key");
            Object value = profile.opt(key);
            String kind;
            if (value instanceof String) kind = "strings";
            else if (value instanceof Number) kind = "integers";
            else if (value instanceof JSONObject rule) {
                if (rule.has("path")) kind = "properties";
                else if (rule.has("arguments")) kind = "calls";
                else if (rule.has("parameters")) kind = "signatures";
                else throw new IllegalArgumentException("Unknown rule object");
            } else throw new IllegalArgumentException("Invalid rule value");
            groups.getJSONObject(kind).put(key, value);
        }
        JSONObject bindings = hooks.getJSONObject("bindings");
        only(bindings, "clientVersionClass", "baseRequestFiller", "baseRequestFill", "chatConfigHub", "chatConfigGet");
        JSONObject entry = new JSONObject();
        for (String key : new String[]{"clientVersionClass", "baseRequestFiller", "baseRequestFill", "chatConfigHub", "chatConfigGet"})
            entry.put(key, reference(profile, text(bindings, key)));
        JSONArray methods = hooks.getJSONArray("m");
        if (methods.length() != 3) throw new IllegalArgumentException("Tablet hook contract");
        JSONArray tablet = new JSONArray();
        for (int i = 0; i < methods.length(); i++) {
            JSONObject method = methods.getJSONObject(i);
            only(method, "mh", "sig", "s", "exclude");
            String[] parts = text(method, "mh").split(",", -1);
            if (parts.length != 2) throw new IllegalArgumentException("mh owner,method");
            String sig = text(method, "sig");
            if (!sig.startsWith("#")) throw new IllegalArgumentException("sig reference");
            JSONObject item = new JSONObject().put("owner", reference(profile, parts[0]))
                    .put("method", reference(profile, parts[1])).put("signature", sig.substring(1));
            if (method.has("s")) {
                Object forced = method.opt("s");
                if (!(forced instanceof Boolean)) throw new IllegalArgumentException("s requires boolean");
                item.put("force", forced.toString());
            }
            if (method.has("exclude")) item.put("exclude", reference(profile, text(method, "exclude")));
            tablet.put(item);
        }
        entry.put("tablet", tablet).put("fingerprints", groups).put("hostClientVersion", hostClientVersion);
        normalized = new JSONObject().put("wxvers", new JSONObject().put(hostVersion, entry));
    }

    public static String pack(String hooks, String profile) {
        try { return new JSONObject().put("hooks", hooks).put("profile", profile).toString(); }
        catch (Exception error) { throw new IllegalArgumentException("Rule snapshot", error); }
    }

    public static SpoofRulePair decode(String snapshot) {
        try {
            if (snapshot == null || snapshot.length() > 2 * SpoofCodec.MAX_ENCODED + 128) throw new IllegalArgumentException("Pair bounds");
            JSONTokener tokener = new JSONTokener(snapshot);
            JSONObject pair = new JSONObject(tokener);
            if (tokener.nextClean() != 0 || pair.length() != 2) throw new IllegalArgumentException("Pair envelope");
            only(pair, "hooks", "profile");
            return new SpoofRulePair(SpoofCodec.decode(text(pair, "hooks")), SpoofCodec.decode(text(pair, "profile")));
        } catch (Exception error) { throw new IllegalArgumentException("Invalid H/S pair", error); }
    }

    public boolean matches(String name, int code) { return hostVersion.equals(name) && hostVersionCode == code; }

    private static String reference(JSONObject table, String ref) {
        if (!ref.startsWith("#")) throw new IllegalArgumentException("H requires # references");
        return text(table, ref.substring(1));
    }

    private static String text(JSONObject object, String key) {
        Object value = object.opt(key);
        if (!(value instanceof String text) || text.isEmpty()) throw new IllegalArgumentException(key);
        return text;
    }

    private static void only(JSONObject object, String... allowed) {
        java.util.Set<String> names = new java.util.HashSet<>(java.util.Arrays.asList(allowed));
        var keys = object.keys();
        while (keys.hasNext()) if (!names.contains(keys.next())) throw new IllegalArgumentException("Unknown H/S field");
    }
}
