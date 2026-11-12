package io.github.shadowbaby.wechatxposed.tool.hook.feature.miniprogram;

import android.content.Context;
import android.content.SharedPreferences;
import io.github.shadowbaby.wechatxposed.tool.config.MiniLibraryResetPolicy;
import io.github.shadowbaby.wechatxposed.tool.hook.config.RuntimeSettings;
import io.github.shadowbaby.wechatxposed.tool.hook.config.ToolSettings;
import io.github.shadowbaby.wechatxposed.shared.hook.HookCallback;
import io.github.shadowbaby.wechatxposed.shared.hook.HookFramework;
import io.github.shadowbaby.wechatxposed.shared.hook.HookParam;
import io.github.shadowbaby.wechatxposed.tool.hook.framework.ToolLogger;
import io.github.shadowbaby.wechatxposed.tool.hook.version.VersionWindow;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import static io.github.shadowbaby.wechatxposed.tool.hook.spoof.HostFingerprint.*;


public final class MiniProgramLibraryCleanup {
    private static final String CACHE = fp("mini.library.cleanup.cache.namespace");
    private static final String QUERY = fp("mini.library.cleanup.query.uri");
    private static final String LIB = MiniLibraryResetPolicy.LIBRARY_ID;
    private static MiniProgramLibraryCleanup instance;
    private final HookFramework framework;
    private final ClassLoader loader;
    private final SharedPreferences state;
    private final ScheduledExecutorService worker;
    private final IdentityHashMap<Object, Proof> proofs = new IdentityHashMap<>();
    private Proof inFlight;
    private Plan plan;
    private String attemptAccount = "", lastStatus = "";
    private int attemptEpoch, attempts;
    private long retryAfter, sequence;

    private record Account(String key, Object storage) {
    }

    private record Proof(Account account, int epoch, int requestVersion, long started) {
    }

    private static final class Plan {
        final Proof proof;
        final Object response;
        final int target;
        final int higherRecords;
        boolean callbackFinished;
        int commits;
        long retryAfter;

        Plan(Proof proof, Object response, int target, int higherRecords) {
            this.proof = proof;
            this.response = response;
            this.target = target;
            this.higherRecords = higherRecords;
        }
    }

    private MiniProgramLibraryCleanup(HookFramework framework, ClassLoader loader, Context context) {
        this(framework, loader, context, Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, fp("mini.library.cleanup.thread.wextoolMiniCleanup"));
            thread.setDaemon(true);
            return thread;
        }));
    }

    MiniProgramLibraryCleanup(HookFramework framework, ClassLoader loader, Context context,
                              ScheduledExecutorService worker) {
        this.framework = framework;
        this.loader = loader;
        state = context.getSharedPreferences(fp("mini.library.cleanup.miniProgramLibraryCleanup.wextoolMiniLibraryCleanup"), Context.MODE_PRIVATE);
        this.worker = worker;
    }

    public static synchronized void installMain(HookFramework framework, ClassLoader loader, Context context) {
        if (instance != null || context == null) return;
        MiniProgramLibraryCleanup cleanup = new MiniProgramLibraryCleanup(framework, loader, context);
        try {
            cleanup.installObservers();
            instance = cleanup;
            cleanup.worker.scheduleWithFixedDelay(cleanup::pollSafely, 1, 5, TimeUnit.SECONDS);
        } catch (Throwable ignored) {
            cleanup.worker.shutdown();
            ToolLogger.debug("mini cleanup: static contract unavailable");
        }
    }

    public static synchronized void onSettingsChanged() {
        if (instance != null) instance.worker.execute(instance::pollSafely);
    }

    void installObservers() throws ReflectiveOperationException {

        fpMethod(type(CACHE + fp("mini.library.cleanup.manifest.storage.class")), fp("mini.library.cleanup.manifest.cleanup.method"), "mini.library.cleanup.manifest.cleanup.signature");
        fpMethod(type(CACHE + fp("mini.library.cleanup.manifest.storage.class")), fp("mini.library.cleanup.manifest.enumerate.method"), "mini.library.cleanup.manifest.enumerate.signature");
        fpMethod(type(CACHE + fp("mini.library.cleanup.manifest.storage.class")), fp("mini.library.cleanup.manifest.lookup.method"), "mini.library.cleanup.manifest.lookup.signature");
        fpMethod(type(CACHE + fp("mini.library.cleanup.manifest.provider.class")), fp("mini.library.cleanup.manifest.provider.read.method"), "mini.library.cleanup.manifest.provider.read.signature");
        framework.hookMethod(fpMethod(type(fp("mini.library.cleanup.baseRequest.filler.class")), fp("mini.library.cleanup.baseRequest.fill.method"), "mini.library.cleanup.baseRequest.fill.signature"), new HookCallback() {
            @Override
            public void after(HookParam param) {
                try {
                    if (!param.hasThrowable()) captureRequest(param);
                } catch (Throwable ignored) {
                    status(fp("mini.library.cleanup.after.requestProofUnavailable"));
                }
            }
        });
        framework.hookMethod(fpMethod(type(CACHE + fp("mini.library.cleanup.query.callback.class")), fp("mini.library.cleanup.query.callback.method"), "mini.library.cleanup.query.callback.signature"), new HookCallback() {
            @Override
            public void before(HookParam param) {
                try {
                    captureResponse(param);
                } catch (Throwable ignored) {
                    status(fp("mini.library.cleanup.before.responseUnavailable"));
                }
            }

            @Override
            public void after(HookParam param) {
                synchronized (MiniProgramLibraryCleanup.this) {

                    Object request = fpRead(param.thisObject(), "mini.library.cleanup.query.callback.request");
                    Proof proof = proofs.remove(request);
                    if (plan != null && plan.proof == proof) {
                        if (param.hasThrowable()) plan = null;
                        else plan.callbackFinished = true;
                    }
                }
                worker.execute(MiniProgramLibraryCleanup.this::pollSafely);
            }
        });
    }

    private synchronized void captureRequest(HookParam param) {
        if (inFlight == null || !QUERY.equals(fpCall(framework, param.arg(fpInt("mini.library.cleanup.query.fill.sceneArg")), "mini.library.cleanup.scene.uri.read"))) return;
        Object request = fpRead(param.arg(fpInt("mini.library.cleanup.query.fill.wrapperArg")), "mini.library.cleanup.query.wrapper.payload");
        if (request == null || !fp("mini.library.cleanup.query.request.class").equals(request.getClass().getName())) return;
        if (proofs.size() >= 8) proofs.clear();
        proofs.put(request, new Proof(inFlight.account, inFlight.epoch,
                number(fpRead(param.arg(fpInt("mini.library.cleanup.query.clientVersion.zero")), "mini.library.cleanup.query.request.clientVersion"), 0), inFlight.started));
    }

    private synchronized void captureResponse(HookParam param) {
        Proof proof = proofs.get(fpRead(param.thisObject(), "mini.library.cleanup.query.callback.proofRequest"));
        if (proof == null || !current(proof, account(), RuntimeSettings.get())) return;
        Object result = param.arg(fpInt("mini.library.cleanup.query.callback.resultArg")), response = fpRead(result, "mini.library.cleanup.query.result.payload");
        Object base = response == null ? null : fpCall(framework, response, "mini.library.cleanup.response.baseResponse.read");
        Object ret = fpRead(base, "mini.library.cleanup.query.baseResponse.ret");
        int target = number(fpRead(response, "mini.library.cleanup.query.response.libraryVersion"), 0);
        if (!MiniLibraryResetPolicy.accepts(proof.requestVersion, VersionWindow.real(),
                number(fpRead(result, "mini.library.cleanup.query.result.errorType"), -1), number(fpRead(result, "mini.library.cleanup.query.result.errorCode"), -1),
                ret instanceof Number n ? n.intValue() : null, target,
                string(fpRead(response, "mini.library.cleanup.query.response.downloadUrl")), string(fpRead(response, "mini.library.cleanup.query.response.digest")))) {
            status(fp("mini.library.cleanup.captureResponse.queryRejected"));
            return;
        }

        Object values = fpCall(framework, proof.account.storage, "mini.library.cleanup.manifest.enumerate", LIB, 0);
        if (!(values instanceof List<?> rows) || rows.size() > 128) return;
        int high = 0;
        for (Object row : rows) if (removable(row, target)) high++;
        plan = new Plan(proof, response, target, high);
    }

    private void pollSafely() {
        try {
            poll();
        } catch (Throwable ignored) {
            status(fp("mini.library.cleanup.pollSafely.pendingHostUnavailable"));
        }
    }

    synchronized void poll() {
        ToolSettings settings = RuntimeSettings.get();
        Account account = account();
        if (account == null) return;
        int completed = state.getInt(account.key, 0);
        if (!MiniLibraryResetPolicy.pending(settings.miniProgramMode, settings.global,
                settings.miniLibraryResetEpoch, completed)) {
            plan = null;
            inFlight = null;
            proofs.clear();
            if (settings.miniLibraryResetEpoch > completed && settings.global) status(fp("mini.library.cleanup.poll.deferredGlobal"));
            return;
        }
        if (attemptEpoch != settings.miniLibraryResetEpoch || !attemptAccount.equals(account.key)) {
            attemptEpoch = settings.miniLibraryResetEpoch;
            attemptAccount = account.key;
            attempts = 0;
            retryAfter = 0;
            inFlight = null;
            plan = null;
            proofs.clear();
        }
        if (plan != null && current(plan.proof, account, settings) && plan.callbackFinished) {
            if (compatibleAvailable(account.storage, plan.target)) {
                if (plan.commits >= 3) {
                    attempts = 3;
                    plan = null;
                    inFlight = null;
                    status(fp("mini.library.cleanup.poll.pendingCleanupRetryExhausted"));
                    return;
                }
                if (now() < plan.retryAfter) return;
                Plan ready = plan;
                if (!RuntimeSettings.runIfCurrent(settings, () -> commit(ready))) status(fp("mini.library.cleanup.poll.settingsChanged"));
                return;
            }
            status("waiting-compatible-package target=" + plan.target);
            if (now() - plan.proof.started < 300_000L) return;
            plan = null;
        }
        if (inFlight != null && now() - inFlight.started < 60_000L) return;
        if (now() < retryAfter) return;
        if (attempts >= 3) {
            status(fp("mini.library.cleanup.poll.pendingRetryExhausted"));
            return;
        }
        if (!VersionWindow.ensure(framework, loader)) return;
        attempts++;
        inFlight = new Proof(account, settings.miniLibraryResetEpoch, 0, now());
        retryAfter = now() + (attempts == 1 ? 30_000L : 120_000L);
        status("query-real-version attempt=" + attempts);

        fpCall(framework, type(CACHE + fp("mini.library.cleanup.query.scene.class")), "mini.library.cleanup.query.submit", true, null);
    }

    private void commit(Plan ready) {
        if (!current(ready.proof, account(), RuntimeSettings.get())) return;
        ready.commits++;
        ready.retryAfter = now() + 30_000L;
        try {
            Object local = fpConstructor(type(fp("mini.library.cleanup.manifest.command.class")), "mini.library.cleanup.commit.constructor.signature").newInstance();
            fpWrite(local, "mini.library.cleanup.manifest.command.downloadUrl", fpRead(ready.response, "mini.library.cleanup.manifest.command.downloadUrl"));
            fpWrite(local, "mini.library.cleanup.manifest.command.digest", fpRead(ready.response, "mini.library.cleanup.manifest.command.digest"));
            fpWrite(local, "mini.library.cleanup.manifest.command.libraryVersion", ready.target);
            fpWrite(local, "mini.library.cleanup.manifest.command.action", 1);
            Object deleted = fpConstructor(type(fp("mini.library.cleanup.deleted.pIntClass")), "mini.library.cleanup.commit.constructor.signature").newInstance();
            Object result = fpCall(framework, ready.proof.account.storage, "mini.library.cleanup.manifest.cleanup", local, deleted);
            if (!Boolean.TRUE.equals(result)) {
                status(fp("mini.library.cleanup.commit.pendingManifestUpdateFailed"));
                return;
            }

            fpCall(framework, type(CACHE + fp("mini.library.cleanup.manifest.provider.write.class")), "mini.library.cleanup.manifest.provider.read");
            if (!current(ready.proof, account(), RuntimeSettings.get())) return;
            if (!state.edit().putInt(ready.proof.account.key, ready.proof.epoch).commit()) {
                status(fp("mini.library.cleanup.commit.pendingStateSaveFailed"));
                return;
            }
            status("completed target=" + ready.target + " manifests="
                    + number(fpRead(deleted, "mini.library.cleanup.manifest.cleanup.removedCount"), 0) + " higherBefore=" + ready.higherRecords
                    + " files=host-managed");
            plan = null;
            inFlight = null;
            proofs.clear();
        } catch (Throwable ignored) {
            status(fp("mini.library.cleanup.commit.pendingCleanupFailed"));
        }
    }

    private boolean compatibleAvailable(Object storage, int target) {
        Object asset = fpRead(type(CACHE + fp("mini.library.cleanup.embedded.reader.class")), "mini.library.cleanup.embedded.reader.instance");
        int embed = number(fpCall(framework, asset, "mini.library.cleanup.embedded.version.read"), 0);
        if (embed > 0 && target <= embed) return true;
        Object record = fpCall(framework, storage, "mini.library.cleanup.manifest.record.read", LIB, 0, target, new String[0]);
        if (record == null || !LIB.equals(fpRead(record, "mini.library.cleanup.manifest.row.appId"))
                || number(fpRead(record, "mini.library.cleanup.manifest.row.debugType"), -1) != 0
                || number(fpRead(record, "mini.library.cleanup.manifest.row.version"), -1) != target) return false;
        return Boolean.TRUE.equals(fpCall(framework, fpRead(type(CACHE + fp("mini.library.cleanup.package.verifier.class")), "mini.library.cleanup.package.verifier.instance"), "mini.library.cleanup.package.verify", record));
    }

    private Account account() {
        if (!Boolean.TRUE.equals(fpCall(framework, type(fp("mini.library.cleanup.account.kernel.class")), "mini.library.cleanup.account.initialize"))) return null;
        Object account = fpCall(framework, type(fp("mini.library.cleanup.account.kernel.class")), "mini.library.cleanup.account.read");
        String id = string(fpCall(framework, account, "mini.library.cleanup.account.id.read"));
        if (id == null || id.isEmpty() || fp("mini.library.cleanup.account.emptyId").equals(id)) return null;
        Object storage = fpCall(framework, type(fp("mini.library.cleanup.manifest.registry.class")), "mini.library.cleanup.manifest.registry.read");
        if (storage == null) return null;
        try {
            byte[] digest = MessageDigest.getInstance(fp("mini.library.cleanup.digest.sha256")).digest(id.getBytes(StandardCharsets.UTF_8));
            StringBuilder key = new StringBuilder(fp("mini.library.cleanup.key.done"));
            for (byte b : digest) key.append(String.format(java.util.Locale.ROOT, fp("mini.library.cleanup.account.digestByteFormat"), b & 255));
            return new Account(key.toString(), storage);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private boolean current(Proof proof, Account account, ToolSettings settings) {
        return account != null && proof.account.key.equals(account.key) && proof.account.storage == account.storage
                && proof.epoch == settings.miniLibraryResetEpoch
                && MiniLibraryResetPolicy.pending(settings.miniProgramMode, settings.global,
                proof.epoch, state.getInt(account.key, 0));
    }

    private static boolean removable(Object row, int target) {
        return MiniLibraryResetPolicy.removable(string(fpRead(row, "mini.library.cleanup.cleanup.row.appId")),
                number(fpRead(row, "mini.library.cleanup.cleanup.row.debugType"), -1), number(fpRead(row, "mini.library.cleanup.cleanup.row.version"), -1), target);
    }

    private Class<?> type(String name) {
        return framework.findClass(name, loader);
    }

    private static long now() {
        return System.nanoTime() / 1_000_000L;
    }

    private synchronized void status(String detail) {
        if (detail.equals(lastStatus)) return;
        lastStatus = detail;
        if (RuntimeSettings.get().log) ToolLogger.log("mini cleanup #" + (++sequence) + " phase=" + detail);
    }

    private static int number(Object value, int fallback) {
        return value instanceof Number n ? n.intValue() : fallback;
    }

    private static String string(Object value) {
        return value instanceof String s ? s : null;
    }

}
