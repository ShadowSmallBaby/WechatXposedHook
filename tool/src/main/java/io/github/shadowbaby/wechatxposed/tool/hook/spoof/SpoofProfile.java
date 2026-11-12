package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


public final class SpoofProfile {

    public static final class TabletEntry {
        public final String owner;
        public final String method;
        public final String signature;
        public final String exclude;

        public final String force;

        TabletEntry(String owner, String method, String param, String exclude,
                    String force) {
            this.owner = owner;
            this.method = method;
            this.signature = param;
            this.exclude = exclude;
            this.force = force;
        }
    }

    public final String versionName;
    public final String clientVersionClass;
    public final String baseRequestFiller;
    public final String baseRequestFill;
    public final String chatConfigHub;
    public final String chatConfigGet;
    public final List<TabletEntry> tablet;

    public final Map<String, String> fingerprintStrings;
    public final Map<String, Integer> fingerprintIntegers;
    public final Map<String, MemberRule> fingerprintSignatures;
    public final Map<String, MemberRule> fingerprintCalls;
    public final Map<String, PropertyRule> fingerprintProperties;

    private SpoofProfile(String versionName, String clientVersionClass,
                         String baseRequestFiller, String baseRequestFill,
                         String chatConfigHub, String chatConfigGet,
                         List<TabletEntry> tablet, JSONObject fingerprints) {
        this.versionName = versionName;
        this.clientVersionClass = clientVersionClass;
        this.baseRequestFiller = baseRequestFiller;
        this.baseRequestFill = baseRequestFill;
        this.chatConfigHub = chatConfigHub;
        this.chatConfigGet = chatConfigGet;
        this.tablet = Collections.unmodifiableList(tablet);
        this.fingerprintStrings = strings(fingerprints.optJSONObject("strings"));
        this.fingerprintIntegers = integers(fingerprints.optJSONObject("integers"));
        this.fingerprintSignatures = members(fingerprints.optJSONObject("signatures"), false);
        this.fingerprintCalls = members(fingerprints.optJSONObject("calls"), true);
        this.fingerprintProperties = properties(fingerprints);
        for (MemberRule rule : fingerprintSignatures.values()) validateBindings(rule);
        for (TabletEntry entry : tablet) {
            if (!fingerprintSignatures.containsKey(entry.signature)) throw new IllegalArgumentException("Unknown tablet signature");
        }
    }

    private void validateBindings(MemberRule rule) {
        if (!fingerprintIntegers.keySet().containsAll(rule.bindings.keySet())) throw new IllegalArgumentException("Unknown callback binding");
        for (MemberRule candidate : rule.alternatives) validateBindings(candidate);
    }

    public static SpoofProfile parse(String encoded, String versionName) {
        try {
            return parse(SpoofRulePair.decode(encoded).normalized, versionName);
        }
        catch (Throwable error) { return null; }
    }

    public static SpoofProfile parse(JSONObject root, String versionName) {
        if (root == null || versionName == null) return null;
        try {
            JSONObject wxvers = root.optJSONObject("wxvers");
            JSONObject entry = wxvers == null ? null : wxvers.optJSONObject(versionName);
            if (entry == null) return null;
            JSONObject fingerprints = entry.optJSONObject("fingerprints");
            if (fingerprints == null) return null;
            List<TabletEntry> tablet = parseTablet(entry.optJSONArray("tablet"));
            if (tablet.isEmpty()) return null;
            return new SpoofProfile(versionName,
                    required(entry, "clientVersionClass"),
                    required(entry, "baseRequestFiller"), required(entry, "baseRequestFill"),
                    required(entry, "chatConfigHub"),
                    required(entry, "chatConfigGet"), tablet, fingerprints);
        } catch (Throwable error) {
            return null;
        }
    }

    public boolean covers(SpoofProfile builtIn) {
        return builtIn != null
                && tablet.size() == builtIn.tablet.size()
                && fingerprintStrings.keySet().containsAll(builtIn.fingerprintStrings.keySet())
                && fingerprintIntegers.keySet().containsAll(builtIn.fingerprintIntegers.keySet())
                && fingerprintSignatures.keySet().containsAll(builtIn.fingerprintSignatures.keySet())
                && fingerprintCalls.keySet().containsAll(builtIn.fingerprintCalls.keySet())
                && fingerprintProperties.keySet().containsAll(builtIn.fingerprintProperties.keySet());
    }

    static SpoofProfile contractTemplate(String encoded) {
        if (encoded == null || encoded.isEmpty()) return null;
        try {
            JSONObject root = SpoofRulePair.decode(encoded).normalized;
            JSONObject wxvers = root.optJSONObject("wxvers");
            if (wxvers == null) return null;
            var names = wxvers.keys();
            while (names.hasNext()) {
                SpoofProfile template = parse(encoded, names.next());
                if (template != null) return template;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static String required(JSONObject object, String key) {
        Object value = object.opt(key);
        if (!(value instanceof String text) || text.isEmpty()) throw new IllegalArgumentException(key);
        return text;
    }

    private static Map<String, String> strings(JSONObject object) {
        if (object == null || object.length() == 0) throw new IllegalArgumentException("strings");
        Map<String, String> result = new LinkedHashMap<>();
        var keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            result.put(key, required(object, key));
        }
        return Collections.unmodifiableMap(result);
    }

    private static Map<String, Integer> integers(JSONObject object) {
        if (object == null || object.length() == 0) throw new IllegalArgumentException("integers");
        Map<String, Integer> result = new LinkedHashMap<>();
        var keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = object.opt(key);
            if (!(value instanceof Number n) || n.doubleValue() != n.intValue())
                throw new IllegalArgumentException(key);
            result.put(key, n.intValue());
        }
        return Collections.unmodifiableMap(result);
    }

    private static Map<String, MemberRule> members(JSONObject object, boolean call) {
        if (object == null || object.length() == 0) throw new IllegalArgumentException("members");
        Map<String, MemberRule> result = new LinkedHashMap<>();
        var keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            JSONObject descriptor = object.optJSONObject(key);
            if (descriptor == null) throw new IllegalArgumentException(key);
            result.put(key, MemberRule.parse(descriptor, call));
        }
        return Collections.unmodifiableMap(result);
    }

    private static Map<String, PropertyRule> properties(JSONObject fingerprints) {
        if (!fingerprints.has("properties")) return Collections.emptyMap();
        JSONObject object = fingerprints.optJSONObject("properties");
        if (object == null) throw new IllegalArgumentException("properties");
        Map<String, PropertyRule> result = new LinkedHashMap<>();
        var keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            JSONObject descriptor = object.optJSONObject(key);
            if (descriptor == null) throw new IllegalArgumentException(key);
            result.put(key, PropertyRule.parse(descriptor));
        }
        return Collections.unmodifiableMap(result);
    }

    private static List<TabletEntry> parseTablet(JSONArray array) {
        List<TabletEntry> entries = new ArrayList<>();
        if (array == null) {
            return entries;
        }
        for (int index = 0; index < array.length(); index++) {
            JSONObject item = array.optJSONObject(index);
            if (item == null) {
                continue;
            }
            String owner = item.optString("owner", "");
            String method = item.optString("method", "");
            if (owner.isEmpty() || method.isEmpty()) {
                continue;
            }
            entries.add(new TabletEntry(owner, method,
                    required(item, "signature"), item.optString("exclude", ""),
                    item.optString("force", "")));
        }
        return entries;
    }
}
