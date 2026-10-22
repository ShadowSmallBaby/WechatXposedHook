package github.shadowbaby.wechatxposed.hook.support.pack;

import github.shadowbaby.wechatxposed.hook.loader.util.ModuleLogger;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;
import java.io.File;
import java.nio.file.Files;

/**
 * 功能包 `_s` 校验：只认可项目私钥签出的签名。
 *
 * 宿主并不会对 base/themes/donation/vidurlparser 这四个包做 `_s` 验签，
 * 因此在恢复完成后由本类主动校验。非项目签名会记录日志并删除 body/_s，
 * 下一次启动由 FeaturePackRestorer 从 APK 重新恢复。
 *
 * C（核心）与 L64（native loader）必须保留厂商签名：C 会被宿主二次校验，
 * L64 在 native 侧验签，换成项目签名会导致 core init 失败。
 */
public final class PackSignatureGuard {

    private PackSignatureGuard() {
    }

    public static void verifyInstalled(File filesDir) {
        String plan = Secret.packGuardPlan();
        if (plan == null) {
            ModuleLogger.log("pack signature: native verifier unavailable");
            return;
        }
        String[] parts = plan.split("\\|");
        if (parts.length < 3) {
            return;
        }
        File directory = new File(filesDir, parts[0]);
        for (int index = 1; index + 1 < parts.length; index += 2) {
            String name = parts[index];
            long expectedLength;
            try {
                expectedLength = Long.parseLong(parts[index + 1]);
            } catch (NumberFormatException error) {
                continue;
            }
            File body = new File(directory, name);
            File signatureFile = new File(directory, name + "_s");
            if (!body.isFile() || !signatureFile.isFile()
                    || body.length() != expectedLength) {
                continue;
            }
            try {
                byte[] data = Files.readAllBytes(body.toPath());
                byte[] signature = Files.readAllBytes(signatureFile.toPath());
                if (Secret.verifyPack(data, signature)) {
                    ModuleLogger.debug("pack signature: local ok");
                } else {
                    ModuleLogger.log("pack signature: local rejected");
                    body.delete();
                    signatureFile.delete();
                }
            } catch (Throwable error) {
                ModuleLogger.log(error);
            }
        }
    }
}
