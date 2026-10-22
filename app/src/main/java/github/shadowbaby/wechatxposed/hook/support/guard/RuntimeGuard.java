package github.shadowbaby.wechatxposed.hook.support.guard;

import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import java.io.BufferedReader;
import java.io.FileReader;

/**
 * 反调试 / 反注入的轻量检测。
 *
 * 只做扩展功能降级，不崩溃、不主动反 root/LSPosed：
 * - TracerPid 非 0：被 ptrace 跟踪；
 * - maps 出现 frida/gum/substrate 常见模块。
 *
 * 检测到后由 HookBootstrap 关闭扩展 dex 注入，基础包与聊天/钱包仍可用。
 */
public final class RuntimeGuard {

    private static volatile Boolean trusted;

    private RuntimeGuard() {
    }

    public static synchronized boolean verify() {
        Boolean cached = trusted;
        if (cached != null) {
            return cached;
        }
        if (BuildConfig.DEBUG) {
            trusted = true;
            return true;
        }
        boolean traced = tracerPid() > 0;
        boolean injected = mapsInjected();
        trusted = !traced && !injected;
        if (!trusted) {
            ModuleLogger.log("runtime guard: extension disabled"
                    + (traced ? " (tracer)" : "") + (injected ? " (injector)" : ""));
        }
        return trusted;
    }

    public static boolean isTrusted() {
        Boolean value = trusted;
        return value == null || value;
    }

    private static int tracerPid() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("TracerPid:")) {
                    continue;
                }
                return Integer.parseInt(line.substring(10).trim());
            }
        } catch (Throwable ignored) {
        }
        return 0;
    }

    private static boolean mapsInjected() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(java.util.Locale.US);
                if (lower.contains("frida")
                        || lower.contains("gum-js-loop")
                        || lower.contains("libsubstrate")
                        || lower.contains("substrate.so")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }
}
