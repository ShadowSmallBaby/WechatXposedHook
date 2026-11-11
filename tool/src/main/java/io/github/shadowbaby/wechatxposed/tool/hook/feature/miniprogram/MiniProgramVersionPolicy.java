package io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram;

import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;


public final class MiniProgramVersionPolicy {
    private MiniProgramVersionPolicy() {}

    public record Page(String kind, String type) {
        public boolean upgrade() { return fp("mini.versionPolicy.upgrade.waerrpage").equals(kind) && fp("mini.versionPolicy.upgrade.upgrade").equals(type); }
    }

    public static Page page(Object value) {
        if (!(value instanceof String url) || url.isBlank()) return new Page("none", "none");
        try {

            URI uri = new URI(url.trim().replace(fp("mini.versionPolicy.uri.amp"), fp("mini.versionPolicy.uri.matcher1")));
            String scheme = uri.getScheme();
            boolean https = fp("mini.versionPolicy.https.https").equalsIgnoreCase(scheme);
            boolean http = fp("mini.versionPolicy.http.http").equalsIgnoreCase(scheme);
            if ((!https && !http) || uri.getUserInfo() != null
                    || !fp("mini.versionPolicy.page.mpWeixinQqCom").equalsIgnoreCase(uri.getHost())
                    || (uri.getPort() != -1 && uri.getPort() != (https ? 443 : 80)))
                return new Page("other", "none");
            if (!fp("mini.versionPolicy.page.mpWaerrpage").equals(uri.getPath())) return new Page(fp("mini.versionPolicy.page.officialOther"), "none");
            String type = null;
            if (uri.getRawQuery() != null) {
                for (String part : uri.getRawQuery().split(fp("mini.versionPolicy.page.matcher1"))) {
                    String[] pair = part.split(fp("mini.versionPolicy.pair.matcher1"), 2);
                    if (!fp("mini.versionPolicy.page.type").equals(decode(pair[0]))) continue;
                    if (type != null) return new Page(fp("mini.versionPolicy.page.waerrpage"), fp("mini.versionPolicy.page.ambiguous"));
                    type = pair.length == 2 ? decode(pair[1]) : "";
                }
            }

            String label = "other";
            if (type == null) label = "none";
            else for (String known : fp("mini.versionPolicy.labels").split(",")) {
                if (known.equals(type)) { label = type; break; }
            }
            return new Page(fp("mini.versionPolicy.page.waerrpage"), label);
        } catch (Throwable ignored) { return new Page(fp("mini.versionPolicy.page.invalid"), "none"); }
    }

    private static String decode(String value) throws java.io.UnsupportedEncodingException {
        return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
    }

    public static String reason(Object actionCode, Object url, Object message) {
        if (!(actionCode instanceof Number code)) return null;
        if (code.intValue() == fpInt("mini.versionPolicy.reason.second") && updateUrl(url)) return fp("mini.versionPolicy.reason.upgradePage");
        if (code.intValue() == fpInt("mini.versionPolicy.reason.third") && hostVersionAlert(message)) return fp("mini.versionPolicy.reason.hostVersionAlert");
        return null;
    }

    public static boolean updateUrl(Object value) {
        if (page(value).upgrade()) return true;
        if (!(value instanceof String url)) return false;
        try {
            URI uri = new URI(url.trim());
            if (!fp("mini.versionPolicy.updateUrl.https").equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                    || (uri.getPort() != -1 && uri.getPort() != 443)
                    || (!fp("mini.versionPolicy.updateUrl.supportWeixinQqCom").equalsIgnoreCase(uri.getHost())
                        && !fp("mini.versionPolicy.updateUrl.szsupportWeixinQqCom").equalsIgnoreCase(uri.getHost()))) return false;
            return fp("mini.versionPolicy.updateUrl.update").equals(uri.getPath()) || (uri.getPath() != null && uri.getPath().startsWith(fp("mini.versionPolicy.updateUrl.update2")));
        } catch (Throwable ignored) { return false; }
    }

    private static boolean hostVersionAlert(Object value) {
        if (!(value instanceof String message)) return false;
        String text = message.trim();

        for (String prefix : new String[]{fp("mini.versionPolicy.hostVersionAlert.matcher1"), fp("mini.versionPolicy.hostVersionAlert.second"), fp("mini.versionPolicy.hostVersionAlert.third"),
                fp("mini.versionPolicy.hostVersionAlert.fourth"), fp("mini.versionPolicy.hostVersionAlert.fifth")}) {
            if (text.startsWith(prefix) && (text.contains(fp("mini.versionPolicy.hostVersionAlert.sixth")) || text.contains(fp("mini.versionPolicy.hostVersionAlert.seventh")))) return true;
        }
        String english = text.toLowerCase(Locale.ROOT);
        return (english.startsWith(fp("mini.versionPolicy.hostVersionAlert.yourWechatVersionIsTooLow"))
                || english.startsWith(fp("mini.versionPolicy.hostVersionAlert.yourWechatVersionIsOutOfDate")))
                && (english.contains(fp("mini.versionPolicy.hostVersionAlert.update")) || english.contains(fp("mini.versionPolicy.hostVersionAlert.upgrade")));
    }
}
