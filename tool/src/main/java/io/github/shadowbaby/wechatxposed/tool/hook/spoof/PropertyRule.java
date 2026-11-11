package io.github.shadowbaby.wechatxposed.tool.hook.spoof;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public final class PropertyRule {
    public record Step(String field, MemberRule getter, MemberRule setter, String type, String runtimeType, Boolean isStatic, boolean inherited) {}
    public final List<Step> path;
    public final String valueType;
    public final List<PropertyRule> alternatives;

    private PropertyRule(JSONObject json, boolean nested, String logicalType) {
        JSONArray segments = json.optJSONArray("path");
        if (segments == null || segments.length() < 1 || segments.length() > 8) throw new IllegalArgumentException("property path size");
        valueType = json.has("valueType") ? type(json.opt("valueType")) : logicalType;
        if (nested && !java.util.Objects.equals(valueType, logicalType)) throw new IllegalArgumentException("property alternative logical type");
        List<Step> steps = new ArrayList<>();
        for (int i = 0; i < segments.length(); i++) {
            JSONObject step = segments.optJSONObject(i);
            if (step == null || step.has("field") == step.has("getter")) throw new IllegalArgumentException("property accessor");
            String field = step.has("field") ? name(step.opt("field")) : null;
            if (field != null && step.has("setter")) throw new IllegalArgumentException("field/setter conflict");
            MemberRule getter = step.has("getter") ? accessor(step.optJSONObject("getter"), false) : null;
            MemberRule setter = step.has("setter") ? accessor(step.optJSONObject("setter"), true) : null;
            if (setter != null && i != segments.length() - 1) throw new IllegalArgumentException("intermediate setter");
            String runtimeType = step.has("runtimeType") ? type(step.opt("runtimeType")) : null;
            if (runtimeType != null && i == segments.length() - 1) throw new IllegalArgumentException("terminal runtime type hint");
            Boolean isStatic = bool(step, "static");
            Boolean inherited = bool(step, "inherited");
            steps.add(new Step(field, getter, setter, step.has("type") ? type(step.opt("type")) : null, runtimeType,
                    isStatic, inherited == null || inherited));
        }
        path = Collections.unmodifiableList(steps);
        List<PropertyRule> variants = new ArrayList<>();
        if (json.has("alternatives")) {
            JSONArray array = json.optJSONArray("alternatives");
            if (nested || array == null || array.length() > 8) throw new IllegalArgumentException("property alternatives");
            for (int i = 0; i < array.length(); i++) {
                JSONObject variant = array.optJSONObject(i);
                if (variant == null) throw new IllegalArgumentException("property alternative object");
                variants.add(new PropertyRule(variant, true, valueType));
            }
        }
        alternatives = Collections.unmodifiableList(variants);
    }

    public static PropertyRule parse(JSONObject object) { return new PropertyRule(object, false, null); }

    private static MemberRule accessor(JSONObject object, boolean write) {
        if (object == null) throw new IllegalArgumentException("getter/setter descriptor");
        MemberRule rule = MemberRule.parse(object, true);
        if (rule.parameters == null || !rule.alternatives.isEmpty() || !rule.bindings.isEmpty())
            throw new IllegalArgumentException("property accessor signature");
        boolean hasValue = false;
        for (MemberRule.Argument argument : rule.arguments) {
            if (argument.input() >= 0) {
                if (!write || argument.input() != 0) throw new IllegalArgumentException("property accessor input");
                hasValue = true;
            }
        }
        if (write && !hasValue) throw new IllegalArgumentException("property setter value input");
        return rule;
    }

    private static String name(Object value) {
        if (!(value instanceof String s) || !s.matches("[A-Za-z_$][A-Za-z0-9_$]*")) throw new IllegalArgumentException("property field");
        return s;
    }

    private static String type(Object value) {
        if (!(value instanceof String s) || !s.matches("@owner|[A-Za-z_$][A-Za-z0-9_$.]*(\\[\\])*") || s.equals("void")) throw new IllegalArgumentException("property type");
        return s;
    }

    private static Boolean bool(JSONObject object, String key) {
        if (!object.has(key)) return null;
        if (!(object.opt(key) instanceof Boolean b)) throw new IllegalArgumentException(key);
        return b;
    }
}
