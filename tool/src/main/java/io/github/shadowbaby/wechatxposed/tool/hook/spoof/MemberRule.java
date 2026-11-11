package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


public final class MemberRule {
    public record Argument(int input, Object constant, String type) {}
    public final String name;
    public final List<String> parameters;
    public final String returns;
    public final Boolean isStatic;
    public final List<Argument> arguments;
    public final Map<String, Integer> bindings;
    public final List<MemberRule> alternatives;

    private MemberRule(JSONObject json, boolean call) {
        for (String field : new String[]{"parameters", "arguments", "alternatives"}) {
            if (json.has(field) && !(json.opt(field) instanceof JSONArray)) throw new IllegalArgumentException(field);
        }
        if (json.has("bindings") && !(json.opt("bindings") instanceof JSONObject)) throw new IllegalArgumentException("bindings");
        name = json.has("name") ? text(json, "name") : null;
        returns = json.has("returns") ? text(json, "returns") : null;
        if (name != null && !name.matches("[A-Za-z_$][A-Za-z0-9_$]*")) throw new IllegalArgumentException("member name");
        if (returns != null && !validType(returns)) throw new IllegalArgumentException("return type");
        if (json.has("static") && !(json.opt("static") instanceof Boolean)) throw new IllegalArgumentException("static");
        isStatic = json.has("static") ? (Boolean) json.opt("static") : null;
        parameters = types(json.optJSONArray("parameters"));
        if (!call && parameters == null) throw new IllegalArgumentException("hook parameters");
        List<Argument> inputs = new ArrayList<>();
        JSONArray args = json.optJSONArray("arguments");
        if (call && (name == null || name.isEmpty() || args == null || isStatic == null)) throw new IllegalArgumentException("call descriptor");
        if (args != null) {
            for (int i = 0; i < args.length(); i++) {
                JSONObject arg = object(args, i);
                if (arg.has("input") == arg.has("constant")) throw new IllegalArgumentException("argument source");
                if (arg.has("input")) {
                    inputs.add(new Argument(integer(arg.opt("input")), null, null));
                } else {
                    String type = text(arg, "type");
                    Object value = arg.opt("constant");
                    if (value == JSONObject.NULL) value = null;
                    if (value != null && !(value instanceof String || value instanceof Number || value instanceof Boolean)) throw new IllegalArgumentException("constant");
                    if (!(type.equals("null") || type.equals("boolean") || type.equals("int") || type.equals("long") || type.equals("java.lang.String"))) throw new IllegalArgumentException("constant type");
                    if ((type.equals("null") && value != null) || (type.equals("boolean") && !(value instanceof Boolean))
                            || (type.equals("java.lang.String") && !(value instanceof String))
                            || ((type.equals("int") || type.equals("long")) && !(value instanceof Number))) throw new IllegalArgumentException("constant value");
                    if (type.equals("int") && (!(value instanceof Integer || value instanceof Long)
                            || ((Number) value).longValue() != ((Number) value).intValue())) throw new IllegalArgumentException("int constant");
                    if (type.equals("long") && !(value instanceof Integer || value instanceof Long)) throw new IllegalArgumentException("long constant");
                    inputs.add(new Argument(-1, value, type));
                }
            }
            if (parameters != null && inputs.size() != parameters.size()) throw new IllegalArgumentException("call arity");
        }
        arguments = Collections.unmodifiableList(inputs);
        Map<String, Integer> indices = new LinkedHashMap<>();
        JSONObject bind = json.optJSONObject("bindings");
        if (bind != null) {
            var keys = bind.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                int index = integer(bind.opt(key));
                if (parameters == null || index >= parameters.size()) throw new IllegalArgumentException("binding outside signature");
                indices.put(key, index);
            }
        }
        bindings = Collections.unmodifiableMap(indices);
        List<MemberRule> variants = new ArrayList<>();
        JSONArray alternatives = json.optJSONArray("alternatives");
        if (alternatives != null) {
            if (alternatives.length() > 16) throw new IllegalArgumentException("too many alternatives");
            for (int i = 0; i < alternatives.length(); i++) {
                JSONObject variant = object(alternatives, i);
                if (variant.has("alternatives")) throw new IllegalArgumentException("nested alternatives");
                variants.add(new MemberRule(variant, call));
            }
        }
        this.alternatives = Collections.unmodifiableList(variants);
    }

    public static MemberRule parse(JSONObject json, boolean call) { return new MemberRule(json, call); }

    static List<String> types(JSONArray array) {
        if (array == null) return null;
        if (array.length() > 64) throw new IllegalArgumentException("signature size");
        List<String> values = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            Object item = array.opt(i);
            if (!(item instanceof String s) || !validType(s) || s.equals("void")) throw new IllegalArgumentException("parameter type");
            values.add(s);
        }
        return Collections.unmodifiableList(values);
    }

    private static JSONObject object(JSONArray array, int index) {
        JSONObject value = array.optJSONObject(index);
        if (value == null) throw new IllegalArgumentException("member object");
        return value;
    }

    private static boolean validType(String name) {
        return name.matches("@owner|[A-Za-z_$][A-Za-z0-9_$.]*(\\[\\])*");
    }

    private static String text(JSONObject json, String key) {
        Object value = json.opt(key);
        if (!(value instanceof String s)) throw new IllegalArgumentException(key);
        return s;
    }

    private static int integer(Object value) {
        if (!(value instanceof Number n) || n.intValue() < 0 || n.doubleValue() != n.intValue()) throw new IllegalArgumentException("argument index");
        return n.intValue();
    }
}
