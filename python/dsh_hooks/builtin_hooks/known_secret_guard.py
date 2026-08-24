"""内置钩子：已知秘密守卫（建议挂 ReplyReady —— 回复出口的最后一道闸）

与 secret_redactor 的区别：
  - secret_redactor 用【通用正则】拦"长得像密钥"的内容（写文件/命令场景够用）
  - known_secret_guard 用【精确字面量】拦"本机已知的真实秘密值"——
    正则拦不住的场景（如密码出现在表格、URL、自由文本里）由它兜底

已知秘密的两个来源：
  1. 字面量文件：DSH_KNOWN_SECRETS（默认 ~/.dsh/.proxy-token），整行视为秘密
  2. 凭据字段提取（自动）：扫描 DSH_HOME 下常见配置文件（profiles/*/cordis.patch.yml、
     settings.yaml、hooks.json），提取 password/secret/token/api_key 字段的值——
     这类"写在配置里的登录密码/密钥"是最容易被 Agent 复述出去的
"""
import glob
import json
import os
import re
import sys
from pathlib import Path

DEFAULT_SECRET_FILES = "~/.dsh/.proxy-token"
CRED_FIELD_PATTERN = re.compile(
    r"""(?i)\b(password|passwd|secret|token|api[-_]?key)\b["']?\s*[:=]\s*["']([^'"\n]{6,})["']""")
SCAN_GLOBS = [
    "~/.dsh/profiles/*/cordis.patch.yml",
    "~/.dsh/profiles/*/cordis.yml",
    "~/.dsh/hooks.json",
]
# 占位符本身不要当成秘密（否则会自我命中）
PLACEHOLDER_MARKS = ("<REDACTED", "<YOUR-SECRET", "${", "{{")


def _is_plausible(value: str) -> bool:
    if len(value) < 6 or len(value) > 200:
        return False
    return not any(m in value for m in PLACEHOLDER_MARKS)


def load_known_secrets() -> list:
    """收集 (来源标签, 秘密值) 列表。"""
    secrets = []

    # 来源 1：字面量文件
    spec = os.environ.get("DSH_KNOWN_SECRETS", DEFAULT_SECRET_FILES)
    for raw in spec.split(":"):
        p = Path(os.path.expanduser(raw.strip()))
        if not p.exists():
            continue
        try:
            value = p.read_text(encoding="utf-8").strip()
            if _is_plausible(value):
                secrets.append((str(p), value))
        except OSError:
            continue

    # 来源 2：结构化配置中的凭据字段
    home = os.path.expanduser(os.environ.get("DSH_HOME", "~/.dsh"))
    seen_files = set()
    for pattern in SCAN_GLOBS:
        for f in glob.glob(os.path.expanduser(pattern)):
            if f in seen_files or not os.path.isfile(f):
                continue
            seen_files.add(f)
            try:
                text = Path(f).read_text(encoding="utf-8")
            except OSError:
                continue
            for m in CRED_FIELD_PATTERN.finditer(text):
                value = m.group(2).strip()
                if _is_plausible(value):
                    secrets.append((f"{f}#{m.group(1).lower()}", value))

    # 去重（同一值多个来源保留一个）
    uniq, seen = [], set()
    for tag, value in secrets:
        if value not in seen:
            seen.add(value)
            uniq.append((tag, value))
    return uniq


def scrub(obj, secrets):
    """递归替换所有字符串中的已知秘密。返回 (新对象, 命中数, 命中来源)。"""
    hits, tags = 0, set()
    if isinstance(obj, str):
        out = obj
        for tag, value in secrets:
            if value in out:
                hits += out.count(value)
                tags.add(tag)
                out = out.replace(value, "<YOUR-SECRET-请自行查看配置文件>")
        return out, hits, tags
    if isinstance(obj, list):
        items = []
        for item in obj:
            new, n, t = scrub(item, secrets)
            items.append(new)
            hits += n
            tags |= t
        return items, hits, tags
    if isinstance(obj, dict):
        out, h, t = {}, 0, set()
        for k, v in obj.items():
            new, n, tt = scrub(v, secrets)
            out[k] = new
            h += n
            t |= tt
        return out, h, t
    return obj, hits, tags


def scan_file_for_secrets(path: str, secrets: list, max_bytes: int = 50 * 1024 * 1024):
    """扫描单个文件是否包含已知秘密。支持纯文本/zip/tar.gz/tgz/gz。

    返回 (命中次数, 命中来源集合)。容器会解包后逐成员扫描。
    """
    import gzip
    import tarfile
    import zipfile
    from pathlib import Path as _P

    p = _P(path)
    if not p.exists():
        raise FileNotFoundError(path)
    if p.stat().st_size > max_bytes:
        raise ValueError(f"文件超过 {max_bytes // (1024*1024)}MB 扫描上限")

    texts = []
    suffix = p.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(p) as z:
            for name in z.namelist():
                try:
                    texts.append(z.read(name)[:5_000_000])
                except Exception:
                    pass
    elif suffix in (".tar", ".tgz") or (suffix == ".gz" and not p.name.endswith(".txt")):
        mode = "r:gz" if suffix in (".tgz", ".gz") else "r:"
        with tarfile.open(p, mode) as t:
            for member in t.getmembers():
                if member.isfile():
                    f = t.extractfile(member)
                    if f:
                        texts.append(f.read(5_000_000))
    else:
        texts.append(p.read_bytes())

    hits, tags = 0, set()
    joined = b"\n".join(texts)
    try:
        joined_text = joined.decode("utf-8", "replace")
    except Exception:
        return 0, set()
    for tag, value in secrets:
        if value in joined_text:
            hits += joined_text.count(value)
            tags.add(tag)
    return hits, tags


def main():
    # --scan-file 模式：供 lark-cli 出口哨兵等外部工具复用
    # exit 0=干净, 3=命中秘密(stderr 给出报告)
    if len(sys.argv) >= 3 and sys.argv[1] == "--scan-file":
        target = sys.argv[2]
        secrets = load_known_secrets()
        try:
            hits, tags = scan_file_for_secrets(target, secrets)
        except Exception as e:
            print(f"无法扫描: {e}", file=sys.stderr)
            sys.exit(1)
        if hits:
            src = "；".join(sorted(tags))
            print(f"发现 {hits} 处本机凭据（来源：{src}）", file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    payload = json.load(sys.stdin)
    secrets = load_known_secrets()
    if not secrets:
        json.dump({}, sys.stdout)
        return
    cleaned, hits, tags = scrub(payload.get("data") or {}, secrets)
    if not hits:
        json.dump({}, sys.stdout)
        return
    src = "；".join(sorted(tags)) if tags else ""
    json.dump({"decision": "rewrite", "data": cleaned,
               "message": f"⚠️ 已从回复中抹去 {hits} 处本机凭据（来源：{src}）。"
                          "如需查看请直接打开对应的配置文件。"},
              sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main())
