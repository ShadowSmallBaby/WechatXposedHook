#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把原版 X 3.0 壳和源码构建的 wx30 full hook 包合并成一个可安装 APK。

做“原样拷贝 + 最小改写”：
  - 壳的 classes.dex 原样；assets 默认只保留 32 位 loader，res 只替换图标；
  - hook 包的 classes*.dex、libwexhook.so、x30 注入 dex、项目包 zip 原样追加；
  - 仅把 AndroidManifest 的包名相关字符串改成本项目包名；
  - 追加一个很小的 X30Compat dex，把壳内部的 "cn.android.x"
    Context/PackageInfo 查询重定向到本项目包名。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
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
COMPAT_ENTRY = "github.shadowbaby.wechatxposed.x30.X30Compat"
COMPAT_SOURCE = "x30/X30Compat.java"

REQUIRED_HOOK_ASSETS = ("assets/x7_3.0.zip",)

OPTIONAL_HOOK_ASSETS = ("assets/x7_3.0_ext.zip",)
# 壳 APK 里真正无法从项目包 x7_3.0.zip 得到的资源：
#   74fab57f = 32 位 native loader；dc7be70f/534a 项目包内同名同字节。
MINIMAL_SHELL_ASSETS = {
    "assets/74fab57f825f1328df3d731f4de24d5",
    "assets/dc7be70f1898d3a58965a919740f97",
    "assets/534a9729a0c461cbd7a4379978fb742",
}
PROJECT_SHELL_ASSETS = {
    "assets/dc7be70f1898d3a58965a919740f97": "dc7be70f1898d3a58965a919740f97",
    "assets/534a9729a0c461cbd7a4379978fb742": "534a9729a0c461cbd7a4379978fb742",
}

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


def pack_shell_dir(directory: Path) -> Path:
    """把 app/x30 的条目打成临时壳 APK。resources.arsc 必须 STORED。"""
    if not (directory / "AndroidManifest.xml").is_file()             or not (directory / "classes.dex").is_file():
        raise BuildError("壳目录缺少 AndroidManifest.xml/classes.dex: " + str(directory))
    handle, name = tempfile.mkstemp(prefix="wxh-shell-", suffix=".apk")
    os.close(handle)
    target = Path(name)
    with zipfile.ZipFile(target, "w", allowZip64=True) as archive:
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.name == "SOURCE.txt":
                continue
            relative = path.relative_to(directory).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1981, 1, 1, 1, 1, 1))
            info.compress_type = (ZIP_STORED if relative == "resources.arsc"
                                  else ZIP_DEFLATED)
            archive.writestr(info, path.read_bytes())
    log("shell dir: " + str(directory))
    return target


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
                    "hook APK 不含 " + marker.decode() + "，不是带 x30 注入的源码构建"
                )
        modern = "META-INF/xposed/module.prop" in names
        if modern:
            if "META-INF/xposed/java_init.list" not in names:
                raise BuildError("现代 hook 缺少 META-INF/xposed/java_init.list")
            entries = archive.read("META-INF/xposed/java_init.list").decode(
                "utf-8", "replace").splitlines()
            if not any("ModernEntry" in entry for entry in entries):
                raise BuildError("java_init.list 未指向 ModernEntry")
        else:
            entries = read_xposed_init(archive)
            if HOOK_ENTRY not in entries:
                raise BuildError("hook xposed_init 未指向 " + HOOK_ENTRY + ": " + repr(entries))
        log("hook dex: " + ", ".join(dexes) + (" (modern)" if modern else ""))
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


def axml_resource_map(raw: bytes, offset: int) -> list[int]:
    """读取 AXML 的 resource-map chunk：字符串池索引 -> android attr 资源 ID。"""
    if offset + 8 > len(raw):
        return []
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", raw, offset)
    if chunk_type != 0x0180 or chunk_size > len(raw) - offset:
        return []
    start = offset + header_size
    end = offset + chunk_size
    if start >= end:
        return []
    return list(struct.unpack_from("<%dI" % ((end - start) // 4), raw, start))


def project_description(root: Path) -> str:
    """读取项目 strings.xml 的 xp_desc，作为壳的 xposeddescription。"""
    strings = root / "app" / "src" / "main" / "res" / "values" / "strings.xml"
    try:
        text = strings.read_text(encoding="utf-8")
    except OSError:
        return "WeXposedHook"
    match = re.search(r'<string name="xp_desc">(.*?)</string>', text, re.S)
    return match.group(1).strip() if match else "WeXposedHook"


def patch_manifest_identity(raw: bytes, app_name: str, version_name: str,
                           version_code: int, description: str) -> bytes:
    """改 AndroidManifest 的 app label / versionName / versionCode / 描述。"""
    pos, pool_size, count, style_count, flags, strings = axml_pool(raw)
    if style_count:
        raise BuildError("AndroidManifest 字符串池含 style，暂不支持")
    strings = list(strings)
    for index, value in enumerate(strings):
        if "Add extra features to Wechat" in value:
            strings[index] = description
            break
    else:
        raise BuildError("AndroidManifest 里找不到 xposeddescription 文本")
    if version_name in strings:
        version_index = strings.index(version_name)
    elif "3.0" in strings:
        version_index = strings.index("3.0")
        strings[version_index] = version_name
    else:
        version_index = len(strings)
        strings.append(version_name)
    if app_name in strings:
        app_name_index = strings.index(app_name)
    else:
        app_name_index = len(strings)
        strings.append(app_name)
    pool = encode_pool(flags, strings)
    end = pos + pool_size
    result = bytearray(raw)
    result[pos:end] = pool
    struct.pack_into("<I", result, 4, 8 + len(pool) + (len(raw) - end))

    resource_map = axml_resource_map(result, 8 + len(pool))
    cursor = 8 + len(pool)
    while cursor + 8 <= len(result):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", result, cursor)
        if chunk_size < 8:
            break
        if chunk_type == 0x0102 and cursor + 36 <= len(result):
            attr_start = struct.unpack_from("<H", result, cursor + 24)[0]
            attr_size = struct.unpack_from("<H", result, cursor + 26)[0]
            attr_count = struct.unpack_from("<H", result, cursor + 28)[0]
            attrs = cursor + 16 + attr_start
            for index in range(attr_count):
                offset = attrs + index * attr_size
                if offset + 20 > len(result):
                    break
                attr_name_index = struct.unpack_from("<I", result, offset + 4)[0]
                name_id = resource_map[attr_name_index] if attr_name_index < len(resource_map) else 0
                if name_id == 0x01010001:  # android:label
                    struct.pack_into("<I", result, offset + 8, app_name_index)
                    struct.pack_into("<H", result, offset + 12, 8)
                    result[offset + 15] = 0x03  # TYPE_STRING
                    struct.pack_into("<I", result, offset + 16, app_name_index)
                elif name_id == 0x0101021c:  # android:versionName
                    struct.pack_into("<I", result, offset + 8, version_index)
                    struct.pack_into("<H", result, offset + 12, 8)
                    result[offset + 15] = 0x03
                    struct.pack_into("<I", result, offset + 16, version_index)
                elif name_id == 0x0101021b:  # android:versionCode
                    struct.pack_into("<H", result, offset + 12, 8)
                    result[offset + 15] = 0x10  # TYPE_INT_DEC
                    struct.pack_into("<I", result, offset + 16, version_code)
                elif name_id == 0x0101020c:  # android:minSdkVersion
                    struct.pack_into("<H", result, offset + 12, 8)
                    result[offset + 15] = 0x10  # TYPE_INT_DEC
                    struct.pack_into("<I", result, offset + 16, 26)
                elif name_id in (0x01010002, 0x0101052c):  # android:icon / roundIcon
                    # mipmap/ic_launcher[_round] 的 adaptive-icon 已改成
                    # 白色背景 + 项目 logo 前景，避免 HyperOS 主题图标纯色块。
                    resource = 0x7F0F0000 if name_id == 0x01010002 else 0x7F0F0001
                    struct.pack_into("<I", result, offset + 8, 0xFFFFFFFF)
                    struct.pack_into("<H", result, offset + 12, 8)
                    result[offset + 15] = 0x01  # TYPE_REFERENCE
                    struct.pack_into("<I", result, offset + 16, resource)
        cursor += chunk_size
    return bytes(result)


def strip_monochrome(data: bytes) -> bytes:
    """删除 adaptive-icon 里的 <monochrome> 子元素（start + end tag）。"""
    raw = bytearray(data)
    position = 8
    starts = []
    while position + 8 <= len(raw):
        chunk_type, _, chunk_size = struct.unpack_from("<HHI", raw, position)
        if chunk_size < 8:
            break
        if chunk_type == 0x0102:
            starts.append(position)
        position += chunk_size
    if len(starts) < 4:
        return data
    start = starts[3]
    _, _, start_size = struct.unpack_from("<HHI", raw, start)
    end = start + start_size
    if end + 8 > len(raw):
        return data
    end_type, _, end_size = struct.unpack_from("<HHI", raw, end)
    if end_type != 0x0103:
        return data
    removed = end + end_size - start
    total = struct.unpack_from("<I", raw, 4)[0]
    del raw[start:end + end_size]
    struct.pack_into("<I", raw, 4, total - removed)
    return bytes(raw)


def drop_anydpi_bitmap_density(arsc: bytes) -> bytes:
    """把 drawable 的 anydpi-v21 配置降为默认密度。

    anydpi 位图在 BitmapFactory 里按 inDensity=0xFFFE 缩放，
    512px 会被压成 4x4 再放大成模糊色块。改成密度 0 后，
    系统会优先选择具体密度的 PNG，按目标密度正常解码。
    """
    data = bytearray(arsc)
    for offset in range(12, len(data) - 0x54, 4):
        if struct.unpack_from("<H", data, offset)[0] != 0x0201:
            continue
        header_size, size = struct.unpack_from("<HI", data, offset + 2)
        if header_size < 0x38 or header_size > 0x100 or size < header_size:
            continue
        if data[offset + 8] != 0x08:  # type id: drawable
            continue
        density = struct.unpack_from("<H", data, offset + 34)[0]
        sdk = struct.unpack_from("<H", data, offset + 44)[0]
        if density == 0xFFFE and sdk == 21:
            struct.pack_into("<H", data, offset + 34, 0)
    return bytes(data)


def patch_shell_resources(archive: zipfile.ZipFile, logo: bytes) -> dict[str, bytes]:
    """用项目 logo 替换壳的启动图标与自适应图标资源。"""
    png_logo = logo
    webp = None
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(logo)).convert("RGBA")
        # 壳的资源没有经过 aapt 压缩，palette PNG 的 tRNS 在部分 ROM 上会丢细节；
        # 统一重编码成标准 RGBA PNG。
        png_buffer = io.BytesIO()
        image.save(png_buffer, format="PNG")
        png_logo = png_buffer.getvalue()
        webp_buffer = io.BytesIO()
        image.save(webp_buffer, format="WEBP", lossless=True)
        webp = webp_buffer.getvalue()
    except ImportError:
        pass
    replacements: dict[str, bytes] = {}
    # 自适应图标背景：BW.xml 的前景/背景都指向 0x7f08008b，
    # 这个资源按密度落在下列 PNG；全部换成项目 logo 才能让桌面/LSPosed 显示正确。
    for name in (
            "res/CD.png", "res/lP.png", "res/ku.png", "res/pt.png",
            "res/9e.png", "res/6Y.png"):
        replacements[name] = png_logo
    if webp is not None:
        for name in (
                "res/d2.webp", "res/MO.webp", "res/qs.webp", "res/Sn.webp", "res/sK.webp",
                "res/yw.webp", "res/fq.webp", "res/u5.webp", "res/j_.webp", "res/-6.webp"):
            replacements[name] = webp
    for name in ("res/BW.xml", "res/0K.xml"):
        try:
            data = archive.read(name)
        except KeyError:
            continue
        # 子元素顺序：background / foreground / monochrome。
        # 前景指到项目 logo 的背景资源；monochrome 整个元素删掉，
        # 否则主题图标会把 logo 的 alpha 轮廓染成纯色块。
        pattern = re.compile(rb"\x08\x00\x00\x01.\x00\x08\x7f", re.S)
        matches = list(pattern.finditer(data))
        if len(matches) >= 2:
            data = bytearray(data)
            # background 必须用资源引用（@android:color/white = 0x0106000b）；
            # MIUI 的图标解析器不接受 android:drawable 上的内联颜色，
            # 会整体回退成绿色网格占位图。foreground 指向
            # drawable/ic_launcher_background 的标准密度 PNG 项。
            data[matches[0].start():matches[0].start() + 8] = \
                b"\x08\x00\x00\x01\x0b\x00\x06\x01"
            start = matches[1].start()
            data[start:start + 8] = b"\x08\x00\x00\x01\x8b\x00\x08\x7f"
            replacements[name] = strip_monochrome(bytes(data))
        else:
            replacements[name] = data.replace(
                b"\x8c\x00\x08\x7f", b"\x8b\x00\x08\x7f")
    try:
        arsc = archive.read("resources.arsc")
    except KeyError:
        arsc = None
    if arsc is not None and b"res/Yk.xml" in arsc:
        # 0x7f08008b 除了各密度 PNG，还有 anydpi-v21 的绿色网格 vector；
        # API 21+ 会优先选中它，必须把路径改到我们的前景 PNG。
        arsc = arsc.replace(b"res/Yk.xml", b"res/lP.png")
        arsc = drop_anydpi_bitmap_density(arsc)
        replacements["resources.arsc"] = arsc
    return replacements


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

    source_dir = work / "compat-src" / "github" / "shadowbaby" / "wechatxposed" / "x30"
    classes_dir = work / "compat-classes"
    dex_dir = work / "compat-dex"
    for directory in (source_dir, classes_dir, dex_dir):
        directory.mkdir(parents=True, exist_ok=True)
    text = (source.read_text(encoding="utf-8")
            .replace("__MODULE_PACKAGE__", package)
            .replace("__ORIGINAL_CERT_B64__", cert_b64)
            .replace("__MODULE_CERT_B64__", module_cert_b64))
    (source_dir / "X30Compat.java").write_text(text, encoding="utf-8")

    classpath = str(android_jar) + os.pathsep + str(xposed_api)
    run(
        [
            javac,
            "-encoding", "UTF-8",
            "--release", "8",
            "-Xlint:-options",
            "-classpath", classpath,
            "-d", str(classes_dir),
            str(source_dir / "X30Compat.java"),
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


def build_unsigned(shell: Path, hook: Path, compat: Path, output: Path, package: str,
                   drop_shell_assets: set[str] | None = None,
                   shell_assets_mode: str = "minimal", app_name: str = "WeXposedHook",
                   version_name: str = "1.3.6", version_code: int = 117,
                   icon: Path | None = None, repo_root: Path | None = None,
                   description: str = "WeXposedHook",
                   identity_apk: Path | None = None) -> None:
    with zipfile.ZipFile(shell) as base, zipfile.ZipFile(hook) as payload:
        hook_names = set(payload.namelist())
        modern = "META-INF/xposed/module.prop" in hook_names
        hook_dexes = sorted(
            (name for name in hook_names if re.fullmatch(r"classes\d*\.dex", name)),
            key=dex_sort_key,
        )
        manifest = patch_manifest_identity(
            base.read("AndroidManifest.xml"), app_name, version_name, version_code,
            description)
        manifest = patch_manifest(manifest, SHELL_PACKAGE, package)
        icon_bytes = icon.read_bytes() if icon and icon.is_file() else None
        replacements = patch_shell_resources(base, icon_bytes) if icon_bytes else {}
        xposed_init = (COMPAT_ENTRY + "\n" + SHELL_ENTRY + "\n").encode() if modern \
            else (COMPAT_ENTRY + "\n" + HOOK_ENTRY + "\n" + SHELL_ENTRY + "\n").encode()
        project_assets: dict[str, bytes] = {}
        if shell_assets_mode == "minimal" and "assets/x7_3.0.zip" in hook_names:
            with zipfile.ZipFile(io.BytesIO(payload.read("assets/x7_3.0.zip"))) as packs:
                for asset_name, pack_name in PROJECT_SHELL_ASSETS.items():
                    if pack_name in packs.namelist():
                        project_assets[asset_name] = packs.read(pack_name)
            if repo_root is not None:
                ld_path = repo_root / "xmetadata" / "wx7" / "LD"
                if ld_path.is_file():
                    raw = ld_path.read_bytes()
                    body = raw[32:]
                    if (len(body) == 331604
                            and hashlib.sha256(body).digest() == raw[:32]):
                        project_assets["assets/74fab57f825f1328df3d731f4de24d5"] = body

        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", compression=ZIP_DEFLATED, allowZip64=True) as merged:
            written: set[str] = set()
            for info in base.infolist():
                name = info.filename
                if name in written or is_signature_entry(name):
                    continue
                if drop_shell_assets and name in drop_shell_assets:
                    log("drop shell asset: " + name)
                    continue
                is_blob = re.fullmatch(r"assets/[0-9a-f]{30,32}", name) is not None
                if shell_assets_mode == "minimal" and is_blob and name not in MINIMAL_SHELL_ASSETS:
                    log("drop redundant shell asset: " + name)
                    continue
                if name == "AndroidManifest.xml":
                    write_entry(merged, name, manifest, info.compress_type, info,
                                bool(info.flag_bits & 0x800))
                elif name == "assets/xposed_init":
                    write_entry(merged, name, xposed_init, info.compress_type, info,
                                bool(info.flag_bits & 0x800))
                else:
                    data = project_assets.get(name, replacements.get(name, base.read(name)))
                    write_entry(merged, name, data, info.compress_type, info,
                                bool(info.flag_bits & 0x800))
                written.add(name)

            # 资源表把 mipmap 的 anydpi-v26 XML 指到了新的 PNG 文件名，
            # 这些 PNG 不在壳 zip 里，需要补写。
            for name, data in replacements.items():
                if name in written:
                    continue
                write_entry(merged, name, data, ZIP_DEFLATED)
                written.add(name)

            write_entry(merged, "classes2.dex", compat.read_bytes(), ZIP_DEFLATED)
            written.add("classes2.dex")
            integrity = {
                "classes.dex": hashlib.sha256(base.read("classes.dex")).hexdigest(),
                "classes2.dex": hashlib.sha256(compat.read_bytes()).hexdigest(),
            }
            for index, name in enumerate(hook_dexes):
                target = "classes%d.dex" % (index + 3)
                if target in written:
                    raise BuildError("dex 名称冲突: " + target)
                data = payload.read(name)
                write_entry(merged, target, data, ZIP_DEFLATED)
                written.add(target)
                integrity[target] = hashlib.sha256(data).hexdigest()
            integrity_name = "assets/wxh_integrity"
            if integrity_name in written:
                raise BuildError("资产名称冲突: " + integrity_name)
            integrity_text = "\n".join(
                "%s:%s" % (name, digest) for name, digest in integrity.items())
            write_entry(merged, integrity_name, integrity_text.encode("ascii"),
                        ZIP_DEFLATED)
            written.add(integrity_name)

            for name in REQUIRED_HOOK_LIBS:
                source = payload.getinfo(name)
                write_entry(merged, name, payload.read(name), source.compress_type, source,
                            bool(source.flag_bits & 0x800))
                written.add(name)
            for name in REQUIRED_HOOK_ASSETS + OPTIONAL_HOOK_ASSETS:
                if name not in hook_names:
                    continue
                data = payload.read(name)
                if name in ("assets/x7_3.0.zip", "assets/x7_3.0_ext.zip"):
                    # 运行时功能包直接平铺到 assets/ 根目录，不再放 zip。
                    # 有 _c/_s 的条目合并成一个 WXH1 容器，运行时自解。
                    with zipfile.ZipFile(io.BytesIO(data)) as pack:
                        entries = {info.filename: pack.read(info)
                                   for info in pack.infolist()}
                        handled = set()
                        for entry_name, body in entries.items():
                            if entry_name in handled:
                                continue
                            side_c = entry_name + "_c"
                            side_s = entry_name + "_s"
                            if side_c in entries or side_s in entries:
                                part_c = entries.get(side_c, b"")
                                part_s = entries.get(side_s, b"")
                                packed = (b"WXH1"
                                          + len(body).to_bytes(4, "big")
                                          + len(part_c).to_bytes(4, "big")
                                          + len(part_s).to_bytes(4, "big")
                                          + body + part_c + part_s)
                                target = "assets/" + entry_name
                                if target in written:
                                    if target in MINIMAL_SHELL_ASSETS:
                                        handled.update((entry_name, side_c, side_s))
                                        continue
                                    raise BuildError("资产名称冲突: " + target)
                                write_entry(merged, target, packed, ZIP_DEFLATED)
                                written.add(target)
                                handled.update((entry_name, side_c, side_s))
                                continue
                            target = "assets/" + entry_name
                            if target in written:
                                if target in MINIMAL_SHELL_ASSETS:
                                    handled.add(entry_name)
                                    continue
                                raise BuildError("资产名称冲突: " + target)
                            write_entry(merged, target, body, ZIP_DEFLATED)
                            written.add(target)
                            handled.add(entry_name)
                    continue
                if name in written:
                    raise BuildError("资产名称冲突: " + name)
                source = payload.getinfo(name)
                write_entry(merged, name, data, source.compress_type, source,
                            bool(source.flag_bits & 0x800))
                written.add(name)

            if modern:
                for name in sorted(hook_names):
                    if not name.startswith("META-INF/xposed/"):
                        continue
                    if name in written:
                        continue
                    source = payload.getinfo(name)
                    write_entry(merged, name, payload.read(name),
                                source.compress_type, source,
                                bool(source.flag_bits & 0x800))
                    written.add(name)

            # 壳只从 modulePath 的 manifest 里读包名/版本进入 integrated 模式；
            # 这里放一个只含 manifest + resources.arsc 的最小身份 APK。
            shell_apk_name = "assets/x30/identity.apk"
            if shell_apk_name in written:
                raise BuildError("资产名称冲突: " + shell_apk_name)
            donor = identity_apk if identity_apk is not None else shell
            write_entry(merged, shell_apk_name, donor.read_bytes(), ZIP_DEFLATED)
            written.add(shell_apk_name)

            shell_cert_name = next(
                (name for name in base.namelist()
                 if name.upper().startswith("META-INF/") and name.upper().endswith(".RSA")),
                None,
            )
            if shell_cert_name is None:
                raise BuildError("壳 APK 没有 v1 RSA 签名块")
            cert_asset = "assets/x30/original_cert.rsa"
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
        for required in ("classes.dex", "classes2.dex", "assets/xposed_init"):
            if required not in names:
                raise BuildError("输出缺少 " + required)
        if not any(re.fullmatch(r"assets/[0-9a-f]{20,40}", name) for name in names):
            raise BuildError("输出缺少平铺功能包 assets/<hash>")
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


def sign_apk(root: Path, unsigned: Path, output: Path, args: argparse.Namespace, work: Path,
             v1: bool = True) -> None:
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
            "--v1-signing-enabled", "true" if v1 else "false",
            "--v2-signing-enabled", "true",
            "--out", str(output),
            str(aligned),
        ]
    )
    log("signed: " + str(output) + " (alias=" + alias + ")")
    run([str(apksigner), "verify", "--print-certs", str(output)])


ICON_DRAWABLES = ("res/CD.png", "res/lP.png", "res/ku.png", "res/pt.png",
                  "res/9e.png", "res/6Y.png")


def patch_launcher_drawables(apk: Path, icon: Path | None) -> None:
    """把图标 drawable 的所有密度变体换成项目 logo。

    壳的 `ic_launcher_background` 按密度分了多张图，只有 mdpi 是 logo；
    不改的话高密度设备会显示壳的纯色背景。
    """
    if icon is None or not icon.is_file():
        return
    data = icon.read_bytes()
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(data)).convert("RGBA")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        data = buffer.getvalue()
    except ImportError:
        pass
    temp = apk.with_suffix(".icon.apk")
    replaced = 0
    with zipfile.ZipFile(apk) as source, zipfile.ZipFile(
            temp, "w", allowZip64=True) as target:
        for info in source.infolist():
            payload = source.read(info.filename)
            if info.filename in ICON_DRAWABLES:
                payload = data
                replaced += 1
            write_entry(target, info.filename, payload, info.compress_type, info,
                        bool(info.flag_bits & 0x800))
    if replaced == 0:
        temp.unlink()
        raise BuildError("没有找到图标 drawable，壳资源布局可能变了")
    temp.replace(apk)
    log("icon: replaced %d density drawable(s)" % replaced)


def build_identity_apk(root: Path, shell: Path, work: Path,
                       args: argparse.Namespace) -> Path:
    """生成含壳 manifest + resources.arsc 的最小身份 APK（包名 cn.android.x）。"""
    unsigned = work / "identity-unsigned.apk"
    with zipfile.ZipFile(shell) as base, zipfile.ZipFile(
            unsigned, "w", compression=ZIP_DEFLATED) as donor:
        for name in ("AndroidManifest.xml", "resources.arsc"):
            donor.writestr(name, base.read(name))
    signed = work / "identity.apk"
    sign_apk(root, unsigned, signed, args, work)
    log("identity: %d bytes" % signed.stat().st_size)
    return signed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default=None,
                        help="原版壳 APK；与 --shell-dir 二选一")
    parser.add_argument("--shell-zip", default=None,
                        help="已抽取的壳条目 zip（默认 app/x30.zip）")
    parser.add_argument("--shell-dir", default=None,
                        help="已抽取的壳条目目录；与 --shell-zip 二选一")
    parser.add_argument("--identity-apk",
                        help="自定义最小身份 APK；默认从 --shell 的 manifest/arsc 现场生成")
    parser.add_argument("--hook-apk",
                        default="app/build/outputs/apk/legacyFullEdition/release/"
                                "WeXposedHook-legacy-v2.0-beta-full.apk")
    parser.add_argument("--package", default="github.shadowbaby.wechatxposed.hook")
    parser.add_argument("--output", default="build/outputs/apk/release/WeXposedHook-legacy-v2.0-beta.apk")
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
    parser.add_argument("--app-name", default="WeXposedHook")
    parser.add_argument("--version-name", default="2.0-beta")
    parser.add_argument("--version-code", type=int, default=8)
    parser.add_argument("--icon", default="app/src/main/res/mipmap/logo.png")
    parser.add_argument("--description",
                        help="LSPosed 模块描述；默认取项目 strings.xml 的 xp_desc")
    parser.add_argument("--shell-assets", choices=("minimal", "all"), default="minimal",
                        help="minimal=只保留 32 位 loader/项目包可提供的资源；all=原样拷贝")
    parser.add_argument("--drop-shell-assets", default="",
                        help="逗号分隔的壳 assets 条目名，测试最小资产集用")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    temp_shell = None
    if args.shell_zip:
        shell = ((root / args.shell_zip).resolve()
                 if not Path(args.shell_zip).is_absolute()
                 else Path(args.shell_zip))
    elif args.shell_dir:
        shell_dir = ((root / args.shell_dir).resolve()
                     if not Path(args.shell_dir).is_absolute()
                     else Path(args.shell_dir))
        temp_shell = pack_shell_dir(shell_dir)
        shell = temp_shell
    elif args.shell:
        shell = ((root / args.shell).resolve()
                 if not Path(args.shell).is_absolute()
                 else Path(args.shell))
    else:
        raise BuildError("需要 --shell-zip / --shell-dir / --shell")
    if args.identity_apk:
        identity_apk = ((root / args.identity_apk).resolve()
                        if not Path(args.identity_apk).is_absolute()
                        else Path(args.identity_apk))
    else:
        identity_apk = None
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
    work = work_root or Path(tempfile.mkdtemp(prefix="wxh-x30-"))
    try:
        if args.no_sign:
            module_cert_b64, module_cert_sha256 = "", ""
        else:
            module_cert_b64, module_cert_sha256 = module_cert_from_keystore(args, work)
            log("模块证书: sha256=" + module_cert_sha256)
        compat = build_compat_dex(root, work, args.package, cert_b64, module_cert_b64, args)
        identity = identity_apk or build_identity_apk(root, shell, work, args)
        unsigned = work / "unsigned.apk"
        drop = {part.strip() for part in args.drop_shell_assets.split(",") if part.strip()}
        icon_path = (root / args.icon) if args.icon else None
        build_unsigned(shell, hook, compat, unsigned, args.package, drop, args.shell_assets,
                       args.app_name, args.version_name, args.version_code,
                       icon_path, root,
                       args.description or project_description(root), identity)
        patch_launcher_drawables(unsigned, icon_path)
        sign_apk(root, unsigned, output, args, work, v1=False)
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
            log("packs : assets/<hash> (%d files)" % sum(
                1 for name in names if re.fullmatch(r"assets/[0-9a-f]{20,40}", name)))
            log("2.44  : " + ("present" if any("wx6_2.44" in name for name in names) else "absent"))
        return 0
    finally:
        if temp_shell is not None:
            temp_shell.unlink(missing_ok=True)
        if not args.keep_work and not work_root:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BuildError as error:
        print("错误: " + str(error), file=sys.stderr)
        raise SystemExit(1)
