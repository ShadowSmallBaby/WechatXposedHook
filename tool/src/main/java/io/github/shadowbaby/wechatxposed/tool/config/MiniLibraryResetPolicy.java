package io.github.shadowbaby.wechatxposed.tool.config;


public final class MiniLibraryResetPolicy {
    public static final String LIBRARY_ID = "@LibraryAppId";

    private MiniLibraryResetPolicy() {
    }

    public static int nextEpoch(int previousMode, int nextMode, int epoch) {
        int current = Math.max(0, epoch);
        return previousMode == 2 && nextMode >= 0 && nextMode <= 3 && nextMode != 2
                && current < Integer.MAX_VALUE ? current + 1 : current;
    }

    public static boolean pending(int mode, boolean global, int requested, int completed) {
        return mode >= 0 && mode <= 3 && mode != 2 && !global
                && requested > 0 && requested > completed;
    }

    public static boolean accepts(int requestVersion, int realVersion, int errType, int errCode,
                                  Integer ret, int target, String url, String md5) {
        return realVersion != 0 && requestVersion == realVersion && errType == 0 && errCode == 0
                && ret != null && ret == 0 && target > 0
                && url != null && (url.startsWith("https://") || url.startsWith("http://"))
                && md5 != null && !md5.isEmpty();
    }

    public static boolean removable(String appId, int debugType, int version, int target) {
        return LIBRARY_ID.equals(appId) && debugType == 0 && target > 0 && version > target;
    }
}
