#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把原版 X 3.0 壳和现有 wx30 debug hook 包合并成一个可安装 APK。

阶段一只做“原样拷贝 + 最小改写”：
  - 壳的 classes.dex / assets / res 原样保留；
  - hook 包的 classes*.dex、libwexhook.so、x30 注入 dex、项目包 zip 原样追加；
  - 仅把 AndroidManifest 的包名相关字符串改成本项目包名；
  - 追加一个很小的 Shell30Compat dex，把壳内部的 "cn.android.x"
    Context/PackageInfo 查询重定向到本项目包名。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SHELL_PACKAGE = "cn.android.x"
SHELL_ENTRY = "com.android.x.XposedInit"
HOOK_ENTRY = "github.shadowbaby.wechatxposed.hook.XposedInit"
COMPAT_ENTRY = "github.shadowbaby.wechatxposed.shell30.Shell30Compat"
COMPAT_SOURCE = "shell30/Shell30Compat.java"

REQUIRED_HOOK_ASSETS = (
    "assets/x7_3.0.zip",
    "assets/x7_3.0_ext.zip",
    "assets/featuredex/x30_sf.dex",
    "assets/featuredex/x30_mf.dex",
    "assets/featuredex/x30_af.dex",
)
REQUIRED_HOOK_LIBS = (
    "lib/arm64-v8a/libwexhook.so",
    "lib/armeabi-v7a/libwexhook.so",
)
FORBIDDEN_HOOK_ASSETS = (
    "assets/featuredex/sf.dex",
    "assets/featuredex/mf.dex",
    "assets/featuredex/af.dex",
    "assets/featuredex/core202.bin",
)

ZIP_STORED = zipfile.ZIP_STORED
ZIP_DEFLATED = zipfile.ZIP_DEFLATED


class BuildError(RuntimeError):
    pass


def log(message: str) -> None:
    print(message, flush=True)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    if os.name == "nt" and command and command[0].lower().endswith((".bat", ".cmd")):
        command = ["cmd", "/c"] + command
    log("+ " + " ".join(str(part) for part in command))
    return subprocess.run(command, check=True, **kwargs)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_properties(root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    file = root / "local.properties"
    if not file.is_file():
        return values
    for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def find_sdk(root: Path, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit)
        if (path / "build-tools").is_dir():
            return path
        raise BuildError("--android-sdk 不是有效的 SDK 目录: " + str(path))
    raw = read_properties(root).get("sdk.dir")
    if raw:
        decoded = raw.replace("\\\\", "\\").replace("\\:", ":")
        path = Path(decoded)
        if (path / "build-tools").is_dir():
            return path
    for name in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(name)
        if value and (Path(value) / "build-tools").is_dir():
            return Path(value)
    raise BuildError("找不到 Android SDK: 设 --android-sdk 或 local.properties 的 sdk.dir")


def version_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


def latest_build_tool(sdk: Path, name: str) -> Path:
    tools = sdk / "build-tools"
    if not tools.is_dir():
        raise BuildError("SDK 没有 build-tools 目录: " + str(tools))
    for directory in sorted(tools.iterdir(), key=lambda item: version_key(item.name), reverse=True):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    raise BuildError("找不到 build-tools/" + name)


def latest_android_jar(sdk: Path) -> Path:
    platforms = sdk / "platforms"
    if not platforms.is_dir():
        raise BuildError("SDK 没有 platforms 目录")
    for directory in sorted(platforms.iterdir(), key=lambda item: version_key(item.name), reverse=True):
        candidate = directory / "android.jar"
        if candidate.is_file():
            return candidate
    raise BuildError("找不到 platforms/*/android.jar")


def find_xposed_api(root: Path, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return path
        raise BuildError("--xposed-api 不存在: " + str(path))
    home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or ".")
    pattern = "modules-2/files-2.1/de.robv.android.xposed/api/82/*/api-82.jar"
    matches = [path for path in home.glob(".gradle/caches/" + pattern) if path.is_file()]
    if not matches:
        raise BuildError("找不到 Xposed API 82 jar，请用 --xposed-api 指定")
    return sorted(matches, key=lambda path: path.stat().st_size, reverse=True)[0]


def find_javac(explicit: str | None) -> str:
    if explicit:
        return explicit
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if candidate.is_file():
            return str(candidate)
    candidate = shutil.which("javac")
    if candidate:
        return candidate
    raise BuildError("找不到 javac: 设 JAVA_HOME 或 --javac")


def read_xposed_init(archive: zipfile.ZipFile) -> list[str]:
    try:
        text = archive.read("assets/xposed_init").decode("utf-8", "replace")
    except KeyError as error:
        raise BuildError("缺少 assets/xposed_init") from error
    return [line.strip() for line in text.splitlines() if line.strip()]


def validate_shell(path: Path) -> None:
    if not path.is_file():
        raise BuildError("壳 APK 不存在: " + str(path))
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if "classes.dex" not in names:
            raise BuildError("壳 APK 缺少 classes.dex")
        entries = read_xposed_init(archive)
        if SHELL_ENTRY not in entries:
            raise BuildError("壳 xposed_init 未指向 " + SHELL_ENTRY + ": " + repr(entries))
        manifest = archive.read("AndroidManifest.xml")
        if SHELL_PACKAGE.encode("utf-16le") not in manifest and SHELL_PACKAGE.encode("utf-8") not in manifest:
            raise BuildError("壳 Manifest 里找不到 " + SHELL_PACKAGE)


def validate_hook(path: Path) -> list[str]:
    if not path.is_file():
        raise BuildError("hook APK 不存在: " + str(path))
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        for required in REQUIRED_HOOK_ASSETS + REQUIRED_HOOK_LIBS:
            if required not in names:
                raise BuildError("hook APK 缺少 " + required)
        for forbidden in FORBIDDEN_HOOK_ASSETS:
            if forbidden in names:
                log("注意: hook APK 含 2.44 资产 " + forbidden + "，输出时不会带走")
        dexes = sorted(
            (name for name in names if re.fullmatch(r"classes\d*\.dex", name)),
            key=lambda name: 0 if name == "classes.dex" else int(name[7:-4]),
        )
        if not dexes:
            raise BuildError("hook APK 没有 classes*.dex")
        blob = b"".join(archive.read(name) for name in dexes)
        for marker in (b"FeatureDexInjector", b"FeaturePackUnlock"):
            if marker not in blob:
                raise BuildError(
                    "hook APK 不含 " + marker.decode() + "，不是带 x30 注入的 debug 构建"
                )
        entries = read_xposed_init(archive)
        if HOOK_ENTRY not in entries:
            raise BuildError("hook xposed_init 未指向 " + HOOK_ENTRY + ": " + repr(entries))
        log("hook dex: " + ", ".join(dexes))
        return dexes


def axml_pool(raw: bytes) -> tuple[int, int, int, int, int, list[str]]:
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", raw, 0)
    if chunk_type != 0x0003:
        raise BuildError("AndroidManifest.xml 不是 AXML")
    pos = 8
    pool_type, pool_header, pool_size = struct.unpack_from("<HHI", raw, pos)
    if pool_type != 0x0001 or pool_header != 28:
        raise BuildError("AndroidManifest.xml 字符串池格式不支持")
    count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", raw, pos + 8
    )
    offsets = struct.unpack_from("<%dI" % count, raw, pos + 28)
    base = pos + strings_start
    strings: list[str] = []
    for offset in offsets:
        cursor = base + offset
        if flags & 0x100:
            length = raw[cursor]
            cursor += 1
            if length & 0x80:
                length = ((length & 0x7F) << 8) | raw[cursor]
                cursor += 1
            byte_length = raw[cursor]
            cursor += 1
            if byte_length & 0x80:
                byte_length = ((byte_length & 0x7F) << 8) | raw[cursor]
                cursor += 1
            strings.append(raw[cursor:cursor + byte_length].decode("utf-8", "replace"))
        else:
            length = struct.unpack_from("<H", raw, cursor)[0]
            cursor += 2
            strings.append(raw[cursor:cursor + length * 2].decode("utf-16le", "replace"))
    return pos, pool_size, count, style_count, flags, strings


def encode_pool(flags: int, strings: list[str]) -> bytes:
    count = len(strings)
    data = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(len(data))
        if flags & 0x100:
            encoded = text.encode("utf-8")
            utf16_length = len(text.encode("utf-16le")) // 2
            data.append(utf16_length)
            data.append(len(encoded))
            data.extend(encoded)
            data.append(0)
        else:
            encoded = text.encode("utf-16le")
            data.extend(struct.pack("<H", len(encoded) // 2))
            data.extend(encoded)
            data.extend(b"\x00\x00")
    while len(data) % 4:
        data.append(0)
    strings_start = 28 + 4 * count
    chunk_size = strings_start + len(data)
    return (
        struct.pack("<HHI", 0x0001, 28, chunk_size)
        + struct.pack("<IIIII", count, 0, flags, strings_start, 0)
        + struct.pack("<%dI" % count, *offsets)
        + bytes(data)
    )


def patch_manifest(raw: bytes, old_package: str, new_package: str) -> bytes:
    pos, pool_size, count, style_count, flags, strings = axml_pool(raw)
    if style_count:
        raise BuildError("AndroidManifest 字符串池含 style，暂不支持")
    changed: list[str] = []
    for text in strings:
        if text == old_package or text.startswith(old_package + "."):
            changed.append(new_package + text[len(old_package):])
        else:
            changed.append(text)
    if changed == strings:
        raise BuildError("AndroidManifest 没有找到可替换的 " + old_package)
    pool = encode_pool(flags, changed)
    end = pos + pool_size
    result = bytearray(raw)
    result[pos:end] = pool
    struct.pack_into("<I", result, 4, 8 + len(pool) + (len(raw) - end))
    return bytes(result)


class RawZipInfo(zipfile.ZipInfo):
    """保留原始文件名字节的 ZipInfo（cp437/UTF-8 两种编码）。"""

    def __init__(self, name: str, raw_name: bytes, utf8_name: bool,
                 date_time: tuple[int, int, int, int, int, int]):
        super().__init__(name, date_time)
        self._raw_name = raw_name
        self._utf8_name = utf8_name

    def _encodeFilenameFlags(self):  # noqa: N802 - zipfile 内部接口
        return self._raw_name, (0x800 if self._utf8_name else 0)


def make_zip_info(
    name: str,
    compress_type: int,
    source: zipfile.ZipInfo | None = None,
    utf8_name: bool = False,
) -> zipfile.ZipInfo:
    if source is None:
        info = RawZipInfo(name, name.encode("utf-8", "replace"),
                          False, (1981, 1, 1, 1, 1, 1))
        info.external_attr = 0o644 << 16
        info.create_system = 0
    else:
        try:
            raw_name = name.encode("utf-8") if utf8_name else name.encode("cp437")
        except UnicodeEncodeError:
            raw_name = name.encode("utf-8")
            utf8_name = True
        info = RawZipInfo(name, raw_name, utf8_name, source.date_time)
        info.external_attr = source.external_attr
        info.create_system = source.create_system
        info.internal_attr = source.internal_attr
    info.compress_type = compress_type
    return info


def is_signature_entry(name: str) -> bool:
    upper = name.upper()
    if upper == "META-INF/MANIFEST.MF":
        return True
    return upper.endswith((".SF", ".RSA", ".DSA", ".EC"))


def write_entry(
    output: zipfile.ZipFile,
    name: str,
    data: bytes,
    compress_type: int,
    source: zipfile.ZipInfo | None = None,
    utf8_name: bool = False,
) -> None:
    info = make_zip_info(name, compress_type, source, utf8_name)
    output.writestr(info, data)


def extract_cert_from_apk(path: Path) -> tuple[str, str]:
    """从 APK 的 v1 签名块里取第一张 X.509 证书，返回 (base64, sha256)。"""
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    except ImportError as error:
        raise BuildError("需要 Python 包 cryptography 来提取壳证书") from error
    with zipfile.ZipFile(path) as archive:
        name = None
        for candidate in archive.namelist():
            upper = candidate.upper()
            if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC")):
                name = candidate
                break
        if name is None:
            raise BuildError("APK 没有 v1 签名块: " + str(path))
        data = archive.read(name)
    certificates = pkcs7.load_der_pkcs7_certificates(data)
    if not certificates:
        raise BuildError("签名块里没有证书: " + str(path))
    der = certificates[0].public_bytes(Encoding.DER)
    return base64.b64encode(der).decode("ascii"), hashlib.sha256(der).hexdigest()


def build_compat_dex(root: Path, work: Path, package: str, cert_b64: str,
                     module_cert_b64: str, args: argparse.Namespace) -> Path:
    source = root / "scripts" / COMPAT_SOURCE
    if not source.is_file():
        raise BuildError("缺少 " + str(source))
    sdk = find_sdk(root, args.android_sdk)
    android_jar = Path(args.android_jar) if args.android_jar else latest_android_jar(sdk)
    xposed_api = find_xposed_api(root, args.xposed_api)
    javac = find_javac(args.javac)
    d8 = Path(args.d8) if args.d8 else latest_build_tool(sdk, "d8.bat")
    if not d8.is_file():
        d8 = latest_build_tool(sdk, "d8")

    source_dir = work / "compat-src" / "github" / "shadowbaby" / "wechatxposed" / "shell30"
    classes_dir = work / "compat-classes"
    dex_dir = work / "compat-dex"
    for directory in (source_dir, classes_dir, dex_dir):
        directory.mkdir(parents=True, exist_ok=True)
    text = (source.read_text(encoding="utf-8")
            .replace("__MODULE_PACKAGE__", package)
            .replace("__ORIGINAL_CERT_B64__", cert_b64)
            .replace("__MODULE_CERT_B64__", module_cert_b64))
    (source_dir / "Shell30Compat.java").write_text(text, encoding="utf-8")

    classpath = str(android_jar) + os.pathsep + str(xposed_api)
    run(
        [
            javac,
            "-encoding", "UTF-8",
            "--release", "8",
            "-Xlint:-options",
            "-classpath", classpath,
            "-d", str(classes_dir),
            str(source_dir / "Shell30Compat.java"),
        ]
    )
    class_files = sorted(str(path) for path in classes_dir.rglob("*.class"))
    run(
        [
            str(d8),
            "--lib", str(android_jar),
            "--min-api", "26",
            "--output", str(dex_dir),
            *class_files,
        ]
    )
    dex = dex_dir / "classes.dex"
    if not dex.is_file():
        raise BuildError("d8 没有生成 compat dex")
    if COMPAT_ENTRY.replace(".", "/").encode() not in dex.read_bytes():
        raise BuildError("compat dex 不含 " + COMPAT_ENTRY)
    return dex


def dex_sort_key(name: str) -> int:
    return 0 if name == "classes.dex" else int(name[7:-4])


def build_unsigned(shell: Path, hook: Path, compat: Path, output: Path, package: str) -> None:
    with zipfile.ZipFile(shell) as base, zipfile.ZipFile(hook) as payload:
        hook_names = set(payload.namelist())
        hook_dexes = sorted(
            (name for name in hook_names if re.fullmatch(r"classes\d*\.dex", name)),
            key=dex_sort_key,
        )
        manifest = patch_manifest(base.read("AndroidManifest.xml"), SHELL_PACKAGE, package)
        xposed_init = (COMPAT_ENTRY + "\n" + HOOK_ENTRY + "\n" + SHELL_ENTRY + "\n").encode()

        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", compression=ZIP_DEFLATED, allowZip64=True) as merged:
            written: set[str] = set()
            for info in base.infolist():
                name = info.filename
                if name in written or is_signature_entry(name):
                    continue
                if name == "AndroidManifest.xml":
                    write_entry(merged, name, manifest, info.compress_type, info,
                                bool(info.flag_bits & 0x800))
                elif name == "assets/xposed_init":
                    write_entry(merged, name, xposed_init, info.compress_type, info,
                                bool(info.flag_bits & 0x800))
                else:
                    write_entry(merged, name, base.read(name), info.compress_type, info,
                                bool(info.flag_bits & 0x800))
                written.add(name)

            write_entry(merged, "classes2.dex", compat.read_bytes(), ZIP_DEFLATED)
            written.add("classes2.dex")
            for index, name in enumerate(hook_dexes):
                target = "classes%d.dex" % (index + 3)
                if target in written:
                    raise BuildError("dex 名称冲突: " + target)
                write_entry(merged, target, payload.read(name), ZIP_DEFLATED)
                written.add(target)

            for name in REQUIRED_HOOK_LIBS:
                source = payload.getinfo(name)
                write_entry(merged, name, payload.read(name), source.compress_type, source,
                            bool(source.flag_bits & 0x800))
                written.add(name)
            for name in REQUIRED_HOOK_ASSETS:
                if name in written:
                    raise BuildError("资产名称冲突: " + name)
                source = payload.getinfo(name)
                write_entry(merged, name, payload.read(name), source.compress_type, source,
                            bool(source.flag_bits & 0x800))
                written.add(name)

            # 壳/native 从 getPackageCodePath() 读自身证书；把原版 APK 作为
            # “证书捐献者”放进来，运行时由 compat 重定向到它。
            shell_apk_name = "assets/shell30/original.apk"
            if shell_apk_name in written:
                raise BuildError("资产名称冲突: " + shell_apk_name)
            write_entry(merged, shell_apk_name, shell.read_bytes(), ZIP_DEFLATED)
            written.add(shell_apk_name)

            shell_cert_name = next(
                (name for name in base.namelist()
                 if name.upper().startswith("META-INF/") and name.upper().endswith(".RSA")),
                None,
            )
            if shell_cert_name is None:
                raise BuildError("壳 APK 没有 v1 RSA 签名块")
            cert_asset = "assets/shell30/original_cert.rsa"
            if cert_asset in written:
                raise BuildError("资产名称冲突: " + cert_asset)
            write_entry(merged, cert_asset, base.read(shell_cert_name), ZIP_DEFLATED)
            written.add(cert_asset)

            if "assets/xposed_init" not in written:
                raise BuildError("没有写入 assets/xposed_init")
            if "AndroidManifest.xml" not in written:
                raise BuildError("没有写入 AndroidManifest.xml")

    with zipfile.ZipFile(output) as check:
        names = set(check.namelist())
        forbidden = [
            name for name in names
            if name.startswith("assets/wx6_2.44")
            or "core202" in name
            or name in FORBIDDEN_HOOK_ASSETS
        ]
        if forbidden:
            raise BuildError("输出仍含 2.44 资产: " + ", ".join(sorted(forbidden)))
        for required in REQUIRED_HOOK_ASSETS + ("classes.dex", "classes2.dex", "assets/xposed_init"):
            if required not in names:
                raise BuildError("输出缺少 " + required)
        log("unsigned: %d entries, %d bytes" % (len(names), output.stat().st_size))


def signing_keystore(args: argparse.Namespace, work: Path) -> tuple[Path, str, str, str]:
    if args.ks:
        keystore = Path(args.ks)
        alias = args.ks_alias or "androiddebugkey"
        store_pass = args.ks_pass or "android"
        key_pass = args.key_pass or store_pass
        return keystore, alias, store_pass, key_pass
    encoded = os.environ.get("WXH_KEYSTORE_BASE64")
    if encoded:
        keystore = work / "release.jks"
        keystore.write_bytes(base64.b64decode(re.sub(r"\s+", "", encoded)))
        alias = os.environ.get("WXH_KEY_ALIAS") or args.ks_alias or "release"
        store_pass = os.environ.get("WXH_STORE_PASSWORD") or args.ks_pass or "android"
        key_pass = os.environ.get("WXH_KEY_PASSWORD") or args.key_pass or store_pass
        return keystore, alias, store_pass, key_pass
    home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or ".")
    keystore = home / ".android" / "debug.keystore"
    if not keystore.is_file():
        raise BuildError("没有可用的签名密钥库: 设 --ks 或 WXH_KEYSTORE_BASE64")
    return keystore, "androiddebugkey", "android", "android"


def keystore_args(args: argparse.Namespace, work: Path) -> tuple[list[str], str]:
    keystore, alias, store_pass, key_pass = signing_keystore(args, work)
    return (
        ["--ks", str(keystore), "--ks-key-alias", alias,
         "--ks-pass", "pass:" + store_pass, "--key-pass", "pass:" + key_pass],
        alias,
    )


def find_keytool(explicit: str | None) -> str:
    if explicit:
        return explicit
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
        if candidate.is_file():
            return str(candidate)
    candidate = shutil.which("keytool")
    if candidate:
        return candidate
    raise BuildError("找不到 keytool: 设 JAVA_HOME 或 --keytool")


def module_cert_from_keystore(args: argparse.Namespace, work: Path) -> tuple[str, str]:
    keystore, alias, store_pass, _ = signing_keystore(args, work)
    keytool = find_keytool(args.keytool)
    result = subprocess.run(
        [keytool, "-exportcert", "-rfc", "-keystore", str(keystore),
         "-alias", alias, "-storepass", store_pass],
        check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                      result.stdout, re.S)
    if not match:
        raise BuildError("keytool 没有输出证书: " + result.stdout[-200:])
    der = ssl.PEM_cert_to_DER_cert(match.group(0))
    return base64.b64encode(der).decode("ascii"), hashlib.sha256(der).hexdigest()


def sign_apk(root: Path, unsigned: Path, output: Path, args: argparse.Namespace, work: Path) -> None:
    sdk = find_sdk(root, args.android_sdk)
    zipalign = Path(args.zipalign) if args.zipalign else latest_build_tool(sdk, "zipalign.exe" if os.name == "nt" else "zipalign")
    apksigner = Path(args.apksigner) if args.apksigner else latest_build_tool(sdk, "apksigner.bat" if os.name == "nt" else "apksigner")
    aligned = work / "aligned.apk"
    run([str(zipalign), "-f", "-p", "4", str(unsigned), str(aligned)])
    if args.no_sign:
        shutil.copyfile(aligned, output)
        log("未签名（--no-sign）: " + str(output))
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    keystore, alias = keystore_args(args, work)
    run(
        [
            str(apksigner), "sign",
            *keystore,
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--out", str(output),
            str(aligned),
        ]
    )
    log("signed: " + str(output) + " (alias=" + alias + ")")
    run([str(apksigner), "verify", "--print-certs", str(output)])


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="data/refs/X_3.0.apk")
    parser.add_argument("--hook-apk", default="data/refs/wxh-wx30-full-debug-20261022.apk")
    parser.add_argument("--package", default="github.shadowbaby.wechatxposed.hook")
    parser.add_argument("--output", default="build/generated/shell30/WeXposedHook-shell30-v117.apk")
    parser.add_argument("--work")
    parser.add_argument("--android-sdk")
    parser.add_argument("--android-jar")
    parser.add_argument("--xposed-api")
    parser.add_argument("--javac")
    parser.add_argument("--keytool")
    parser.add_argument("--d8")
    parser.add_argument("--zipalign")
    parser.add_argument("--apksigner")
    parser.add_argument("--ks")
    parser.add_argument("--ks-alias")
    parser.add_argument("--ks-pass")
    parser.add_argument("--key-pass")
    parser.add_argument("--no-sign", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    shell = (root / args.shell).resolve() if not Path(args.shell).is_absolute() else Path(args.shell)
    hook = (root / args.hook_apk).resolve() if not Path(args.hook_apk).is_absolute() else Path(args.hook_apk)
    output = (root / args.output).resolve() if not Path(args.output).is_absolute() else Path(args.output)

    log("shell: " + str(shell))
    log("hook : " + str(hook))
    log("out  : " + str(output))
    validate_shell(shell)
    validate_hook(hook)
    cert_b64, cert_sha256 = extract_cert_from_apk(shell)
    log("原版证书: sha256=" + cert_sha256)

    work_root = Path(args.work).resolve() if args.work else None
    work = work_root or Path(tempfile.mkdtemp(prefix="wxh-shell30-"))
    try:
        if args.no_sign:
            module_cert_b64, module_cert_sha256 = "", ""
        else:
            module_cert_b64, module_cert_sha256 = module_cert_from_keystore(args, work)
            log("模块证书: sha256=" + module_cert_sha256)
        compat = build_compat_dex(root, work, args.package, cert_b64, module_cert_b64, args)
        unsigned = work / "unsigned.apk"
        build_unsigned(shell, hook, compat, unsigned, args.package)
        sign_apk(root, unsigned, output, args, work)
        log("")
        log("output: " + str(output))
        log("size  : %d bytes" % output.stat().st_size)
        log("sha256: " + sha256(output))
        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            log("dex   : " + ", ".join(sorted(
                (name for name in names if re.fullmatch(r"classes\d*\.dex", name)),
                key=dex_sort_key)))
            log("init  : " + repr(archive.read("assets/xposed_init").decode()))
            log("packs : " + ", ".join(name for name in names if name.startswith("assets/x7_3.0")))
            log("2.44  : " + ("present" if any("wx6_2.44" in name for name in names) else "absent"))
        return 0
    finally:
        if not args.keep_work and not work_root:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BuildError as error:
        print("错误: " + str(error), file=sys.stderr)
        raise SystemExit(1)
