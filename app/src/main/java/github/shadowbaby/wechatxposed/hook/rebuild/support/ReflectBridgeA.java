package github.shadowbaby.wechatxposed.hook.rebuild.support;

import android.content.Context;
import android.text.TextUtils;
import android.util.Base64;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import github.shadowbaby.wechatxposed.hook.rebuild.loader.ModuleLogger;
/* renamed from: c.۠۫۠  reason: contains not printable characters */
/* loaded from: classes.dex */
public final class ReflectBridgeA {

    /* renamed from: ۦۤۡ  reason: contains not printable characters */
    public static int unusedFlag;

    /* renamed from: ۖۘ۟  reason: not valid java name and contains not printable characters */
    public static int codePointAt(Object obj, int i) {
        return ((String) obj).codePointAt(i);
    }

    /* renamed from: ۖ۫ۨ  reason: not valid java name and contains not printable characters */
    public static Set hookAllConstructors(Object obj, Object obj2) {
        return XposedBridge.hookAllConstructors((Class) obj, (XC_MethodHook) obj2);
    }

    /* renamed from: ۗۗۚ  reason: not valid java name and contains not printable characters */
    public static boolean listAdd(Object obj, Object obj2) {
        return ((ArrayList) obj).add(obj2);
    }

    /* renamed from: ۗ۠ۙ  reason: not valid java name and contains not printable characters */
    public static String base64Encode(Object obj, int i) {
        return Base64.encodeToString((byte[]) obj, i);
    }

    /* renamed from: ۗۤۘ  reason: not valid java name and contains not printable characters */
    public static boolean boolValue(Object obj) {
        return ((Boolean) obj).booleanValue();
    }

    /* renamed from: ۗۨۤ  reason: not valid java name and contains not printable characters */
    public static boolean isEmptyCharSeq(Object obj) {
        return TextUtils.isEmpty((CharSequence) obj);
    }

    /* renamed from: ۗ۫۬  reason: not valid java name and contains not printable characters */
    public static void logString(Object obj) {
        XposedBridge.log((String) obj);
    }

    /* renamed from: ۘۚۥ  reason: not valid java name and contains not printable characters */
    public static StringBuilder appendChar(Object obj, char c2) {
        return ((StringBuilder) obj).append(c2);
    }

    /* renamed from: ۘۤۜ  reason: not valid java name and contains not printable characters */
    public static void invokeComponentHook(Object obj, Object obj2) {
        ((WxComponentHooks) obj).inject((ClassLoader) obj2);
    }

    /* renamed from: ۙۢۡ  reason: not valid java name and contains not printable characters */
    public static Class findClass(Object obj, Object obj2) {
        return XposedHelpers.findClass((String) obj, (ClassLoader) obj2);
    }

    /* renamed from: ۙۤۚ  reason: not valid java name and contains not printable characters */
    public static Context createPackageContext(Object obj, Object obj2, int i) throws android.content.pm.PackageManager.NameNotFoundException {
        return ((Context) obj).createPackageContext((String) obj2, i);
    }

    /* renamed from: ۙۥۙ  reason: not valid java name and contains not printable characters */
    public static String toString(Object obj) {
        return obj.toString();
    }

    /* renamed from: ۙۧۛ  reason: not valid java name and contains not printable characters */
    public static StringBuilder appendString(Object obj, Object obj2) {
        return ((StringBuilder) obj).append((String) obj2);
    }

    /* renamed from: ۛۗۡ  reason: not valid java name and contains not printable characters */
    public static String[] split(Object obj, Object obj2) {
        return ((String) obj).split((String) obj2);
    }

    /* renamed from: ۛۜۜ  reason: not valid java name and contains not printable characters */
    public static byte[] getBytes(Object obj) {
        return ((String) obj).getBytes();
    }

    /* renamed from: ۛۢ۫  reason: not valid java name and contains not printable characters */
    public static int length(Object obj) {
        return ((String) obj).length();
    }

    /* renamed from: ۛۤۜ  reason: not valid java name and contains not printable characters */
    public static String decodeXor(short[] sArr, int i, int i2, int i3) {
        char[] cArr = new char[i2];
        for (int i4 = 0; i4 < i2; i4++) {
            cArr[i4] = (char) (sArr[i + i4] ^ i3);
        }
        return new String(cArr);
    }

    /* renamed from: ۛ۫ۥ  reason: not valid java name and contains not printable characters */
    public static void setResult(Object obj, Object obj2) {
        ((XC_MethodHook.MethodHookParam) obj).setResult(obj2);
    }

    /* renamed from: ۜۖ۟  reason: not valid java name and contains not printable characters */
    public static int listSize(Object obj) {
        return ((ArrayList) obj).size();
    }

    /* renamed from: ۜ۠ۚ  reason: not valid java name and contains not printable characters */
    public static StringBuilder appendObject(Object obj, Object obj2) {
        return ((StringBuilder) obj).append(obj2);
    }

    /* renamed from: ۟ۚۖ  reason: not valid java name and contains not printable characters */
    public static Class findClassIfExists(Object obj, Object obj2) {
        return XposedHelpers.findClassIfExists((String) obj, (ClassLoader) obj2);
    }

    /* renamed from: ۟ۚۨ  reason: not valid java name and contains not printable characters */
    public static Iterator listIterator(Object obj) {
        return ((ArrayList) obj).iterator();
    }

    /* renamed from: ۠۟ۜ  reason: not valid java name and contains not printable characters */
    public static Object callMethod(Object obj, Object obj2, Object obj3) {
        return XposedHelpers.callMethod(obj, (String) obj2, (Object[]) obj3);
    }

    /* renamed from: ۠ۢۙ  reason: not valid java name and contains not printable characters */
    public static int intValue(Object obj) {
        return ((Integer) obj).intValue();
    }

    /* renamed from: ۡۨۡ  reason: not valid java name and contains not printable characters */
    public static Object iteratorNext(Object obj) {
        return ((Iterator) obj).next();
    }

    /* renamed from: ۢۙ۬  reason: not valid java name and contains not printable characters */
    public static int numericValue(char c2) {
        return Character.getNumericValue(c2);
    }

    /* renamed from: ۢۤ۠  reason: not valid java name and contains not printable characters */
    public static File getFilesDir(Object obj) {
        return ((Context) obj).getFilesDir();
    }

    /* renamed from: ۢۥۚ  reason: not valid java name and contains not printable characters */
    public static boolean iteratorHasNext(Object obj) {
        return ((Iterator) obj).hasNext();
    }

    /* renamed from: ۢ۫ۡ  reason: not valid java name and contains not printable characters */
    public static int parseInt(Object obj) {
        return Integer.parseInt((String) obj);
    }

    /* renamed from: ۤۨۘ  reason: not valid java name and contains not printable characters */
    public static int hashCode(Object obj) {
        return obj.hashCode();
    }

    /* renamed from: ۥۖۘ  reason: contains not printable characters */
    public static String substring(Object obj, int i, int i2) {
        return ((String) obj).substring(i, i2);
    }

    /* renamed from: ۥۚ۟  reason: contains not printable characters */
    public static List unmodifiableList(Object obj) {
        return Collections.unmodifiableList((List) obj);
    }

    /* renamed from: ۥۢۢ  reason: contains not printable characters */
    public static Object requireNonNull(Object obj) {
        return Objects.requireNonNull(obj);
    }

    /* renamed from: ۥۨۢ  reason: contains not printable characters */
    public static boolean alwaysTrue() {
        return true;
    }

    /* renamed from: ۥ۫ۛ  reason: contains not printable characters */
    public static String valueOf(Object obj) {
        return String.valueOf(obj);
    }

    /* renamed from: ۦۤۧ  reason: contains not printable characters */
    public static boolean startsWith(Object obj, Object obj2) {
        return ((String) obj).startsWith((String) obj2);
    }

    /* renamed from: ۦۨۧ  reason: contains not printable characters */
    public static boolean isWhitespace(int i) {
        return Character.isWhitespace(i);
    }

    /* renamed from: ۧ۠ۘ  reason: not valid java name and contains not printable characters */
    public static char charAt(Object obj, int i) {
        return ((String) obj).charAt(i);
    }

    /* renamed from: ۧۤۜ  reason: not valid java name and contains not printable characters */
    public static boolean listIsEmpty(Object obj) {
        return ((ArrayList) obj).isEmpty();
    }

    /* renamed from: ۧۧۦ  reason: not valid java name and contains not printable characters */
    public static Class getClass(Object obj) {
        return obj.getClass();
    }

    /* renamed from: ۧ۬ۥ  reason: not valid java name and contains not printable characters */
    public static Object listGet(Object obj, int i) {
        return ((ArrayList) obj).get(i);
    }

    /* renamed from: ۨۗ۫  reason: not valid java name and contains not printable characters */
    public static void iteratorRemove(Object obj) {
        ((Iterator) obj).remove();
    }

    /* renamed from: ۨۢۘ  reason: not valid java name and contains not printable characters */
    public static void logMessage(Object obj) {
        ModuleLogger.log((Serializable) obj);
    }

    /* renamed from: ۫ۖۙ  reason: not valid java name and contains not printable characters */
    public static Object callStaticMethod(Object obj, Object obj2, Object obj3) {
        return XposedHelpers.callStaticMethod((Class) obj, (String) obj2, (Object[]) obj3);
    }

    /* renamed from: ۫ۤۡ  reason: not valid java name and contains not printable characters */
    public static boolean objectsEqual(Object obj, Object obj2) {
        return obj.equals(obj2);
    }

    /* renamed from: ۫ۦ۬  reason: not valid java name and contains not printable characters */
    public static int charCount(int i) {
        return Character.charCount(i);
    }

    /* renamed from: ۫ۧۡ  reason: not valid java name and contains not printable characters */
    public static byte[] base64Decode(Object obj, int i) {
        return Base64.decode((String) obj, i);
    }

    /* renamed from: ۫ۨ۫  reason: not valid java name and contains not printable characters */
    public static void logThrowable(Object obj) {
        XposedBridge.log((Throwable) obj);
    }

    /* renamed from: ۫ۨ۬  reason: not valid java name and contains not printable characters */
    public static XC_MethodHook.Unhook findAndHookMethod(Object obj, Object obj2, Object obj3, Object obj4) {
        return XposedHelpers.findAndHookMethod((String) obj, (ClassLoader) obj2, (String) obj3, (Object[]) obj4);
    }

    /* renamed from: ۬ۗۡ  reason: not valid java name and contains not printable characters */
    public static boolean hasThrowable(Object obj) {
        return ((XC_MethodHook.MethodHookParam) obj).hasThrowable();
    }

    /* renamed from: ۬ۧ۠  reason: not valid java name and contains not printable characters */
    public static Integer boxInt(int i) {
        return Integer.valueOf(i);
    }
}
