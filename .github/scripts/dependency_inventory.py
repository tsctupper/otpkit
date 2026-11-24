#!/usr/bin/env python3
"""Pinned-source dependency inventory and additions ratchet; Python stdlib only.
No network, package execution, install, product test, settings or source mutation.
Unknown/unread/provenance coverage is retained; absence of a manifest is not zero.
"""

import argparse
import ast
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib

CATEGORIES = [
    "runtime_direct",
    "runtime_resolved_placements",
    "build_test_dev_direct",
    "build_test_dev_resolved_placements",
    "native",
    "vendored_cdn",
    "ci_actions_tools",
    "hosted_services",
    "source_import_references",
    "first_party_reuse",
    "operating_tools",
]
FLOOR = {
    "machine_os": (
        "Existing macOS/Linux/Windows or browser host as applica"
        "ble; exact product deployment constraints retained sepa"
        "rately"
    ),
    "runtimes_compilers_stdlib": [
        "Installed Python interpreter and standard library",
        "Installed Node.js runtime and built-in modules",
        "Installed Swift/Clang toolchain and language standard libraries",
        (
            "Actual OS shell primitives where justified; separately "
            "installed helper executables are operating dependencies"
        ),
    ],
    "first_party_platform_primitives": [
        "Apple SDKs/Xcode and shipped OS frameworks",
        "Browser Web APIs",
    ],
    "not_exempt": [
        "Git and other external source/CI/helper executables, even when OS-distributed",
        "npm/pip/Swift/other packages, even compilers distributed through package manifests",
        "External CI actions/tools and runner-installed non-floor tools",
        "Vendored/copied upstream code, remote scripts/CDN assets",
        (
            "Hosted GitHub/Vercel/Supabase/Codemagic/npm/Apple deliv"
            "ery services (separate operating dependencies)"
        ),
    ],
    "limits": (
        "Visible execution floor, not permission for blanket exe"
        "mptions. Product/platform owners must resolve genuine i"
        "ncompatible constraints; no count is reduced by relabel"
        "ing or copying."
    ),
}
NODE_CORE = set(
    [
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "test",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
        "sqlite",
    ]
)
APPLE = set(
    [
        "AppKit",
        "Foundation",
        "SwiftUI",
        "WebKit",
        "UIKit",
        "Security",
        "Cocoa",
        "SafariServices",
        "OSLog",
        "UniformTypeIdentifiers",
        "CoreGraphics",
        "CoreFoundation",
        "Darwin",
        "Dispatch",
        "Combine",
        "XCTest",
        "AuthenticationServices",
        "UserNotifications",
        "AVFoundation",
        "Photos",
        "PhotosUI",
        "CoreLocation",
        "MapKit",
        "Network",
        "StoreKit",
        "IOKit",
        "ServiceManagement",
        "Swift",
        "Vision",
        "ImageIO",
        "Testing",
    ]
)
# Explicit first-party SDK metadata, reviewed2026-11-24, not a Swift-name wildcard.
# Public installed macOS27.2 and iPhoneSimulator27.2 framework module maps agree.
APPLE_MODULE_PROVENANCE = {
    "Vision": {
        "sdk_versions": ["macOS27.2", "iPhoneSimulator27.2"],
        "module_map_sha256": "227de61cd9b9fcd38be5a24459a36b336f78d0df228bc27710c4273021deb8c0",
    },
    "ImageIO": {
        "sdk_versions": ["macOS27.2", "iPhoneSimulator27.2"],
        "module_map_sha256": "f0010ce07755bb771d78797861745ea89c6ee245dadf2c81635a6d633bc0a6df",
    },
}
SERVICES = {
    "github": "github.com|api.github.com|githubusercontent.com",
    "vercel": "vercel.com|vercel.app",
    "supabase": "supabase.com|supabase.co",
    "codemagic": "codemagic.io",
    "npm": "registry.npmjs.org",
    "apple_delivery": "appstoreconnect.apple.com|testflight.apple.com|developer.apple.com",
    "sentry": "sentry.io",
    "openai": "api.openai.com",
    "google_fonts": "fonts.googleapis.com|fonts.gstatic.com",
    "resend": "api.resend.com|resend.com",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)


def tracked(repo, ref):
    listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", ref)
    files = {}
    links = []
    for row in listing.split(b"\0"):
        if not row:
            continue
        info, name = row.split(b"\t", 1)
        mode, kind, oid = info.decode().split()
        name = name.decode("utf-8", "surrogateescape")
        if mode == "160000":
            links.append((name, oid))
        elif kind == "blob":
            files[name] = oid
    return files, links


def source_candidate(path):
    name = pathlib.PurePosixPath(path).name
    lower = path.lower()
    suffix = pathlib.PurePosixPath(path).suffix.lower()
    return (
        name
        in {
            "skills-lock.json",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pyproject.toml",
            "Package.swift",
            "Package.resolved",
            "Podfile.lock",
            ".gitmodules",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "Gemfile",
            "Gemfile.lock",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "uv.lock",
            "Pipfile",
            "Pipfile.lock",
            "CMakeLists.txt",
            "Dockerfile",
            "README.md",
        }
        or (name.startswith("requirements") and name.endswith(".txt"))
        or suffix
        in {
            ".py",
            ".js",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".jsx",
            ".swift",
            ".html",
            ".css",
            ".yml",
            ".yaml",
            ".toml",
            ".sh",
            ".wasm",
            ".pbxproj",
            ".xcproj",
            ".gradle",
            ".kts",
        }
        or "license" in name.lower()
        or "notice" in name.lower()
        or any(
            part in lower.split("/")
            for part in ["vendor", "vendored", "third_party", "third-party"]
        )
    )


def js_module_references(source, *, include_operating=False, include_metadata=False):
    """Read module expressions, not text inside strings/comments/regex data.

    Small first-party lexical reader, not a complete JS/TS semantic parser. Dynamic
    module arguments and malformed lexical spans remain explicit coverage gaps.
    """
    tokens = []
    token_newlines = []
    comment_spans = []
    pending_newline = False
    issues = []
    length = len(source)

    def emit(kind, value):
        nonlocal pending_newline
        token_newlines.append(pending_newline)
        tokens.append((kind, value))
        pending_newline = False

    def quoted(index, quote):
        parts = []
        index += 1
        while index < length:
            char = source[index]
            if char == quote:
                return "".join(parts), index + 1
            if char == "\\" and index + 1 < length:
                escaped = source[index + 1]
                if escaped in "\r\n":
                    index += 2
                    continue
                width = 4 if escaped == "u" else 2 if escaped == "x" else 0
                if width:
                    try:
                        parts.append(chr(int(source[index + 2 : index + 2 + width], 16)))
                        index += 2 + width
                        continue
                    except ValueError:
                        issues.append("Unparsed JavaScript string escape")
                parts.append(
                    {
                        "n": "\n",
                        "r": "\r",
                        "t": "\t",
                        "b": "\b",
                        "f": "\f",
                        "v": "\v",
                        "0": "\0",
                    }.get(escaped, escaped)
                )
                index += 2
                continue
            parts.append(char)
            index += 1
        issues.append("Unterminated JavaScript string")
        return "".join(parts), index

    def code(index, interpolation=False, depth=0):
        nonlocal pending_newline
        if depth > 64:
            issues.append("JavaScript lexical nesting exceeds bound")
            return length
        braces = 0
        parens = []
        jsx_tag_bases = []
        while index < length:
            char = source[index]
            if char.isspace():
                pending_newline = pending_newline or char in "\r\n"
                index += 1
                continue
            if source.startswith("//", index):
                end = source.find("\n", index + 2)
                line_start = source.rfind("\n", 0, index) + 1
                standalone = not source[line_start:index].strip()
                comment_spans.append(
                    (
                        line_start if standalone else index,
                        (end + 1 if standalone else end) if end >= 0 else length,
                        "",
                    )
                )
                pending_newline = pending_newline or end >= 0
                index = length if end < 0 else end + 1
                continue
            if source.startswith("/*", index):
                end = source.find("*/", index + 2)
                if end < 0:
                    issues.append("Unterminated JavaScript comment")
                    return length
                comment_spans.append(
                    (
                        index,
                        end + 2,
                        "\n" * source[index : end + 2].count("\n")
                        if "\n" in source[index : end + 2]
                        else " ",
                    )
                )
                pending_newline = (
                    pending_newline
                    or "\n" in source[index : end + 2]
                    or "\r" in source[index : end + 2]
                )
                index = end + 2
                continue
            if char in "\"'":
                value, index = quoted(index, char)
                emit("string", value)
                continue
            if char == "`":
                slot = len(tokens)
                emit("string", "")
                parts = []
                dynamic = False
                index += 1
                while index < length:
                    if source[index] == "\\" and index + 1 < length:
                        # Reuse quoted-string decoding for one escaped character.
                        start = index
                        escaped = source[index + 1]
                        width = 4 if escaped == "u" else 2 if escaped == "x" else 0
                        if width:
                            try:
                                parts.append(chr(int(source[index + 2 : index + 2 + width], 16)))
                                index += 2 + width
                                continue
                            except ValueError:
                                issues.append("Unparsed JavaScript template escape")
                        if escaped not in "\r\n":
                            parts.append(
                                {
                                    "n": "\n",
                                    "r": "\r",
                                    "t": "\t",
                                    "b": "\b",
                                    "f": "\f",
                                    "v": "\v",
                                    "0": "\0",
                                }.get(escaped, escaped)
                            )
                        index = start + 2
                        continue
                    if source[index] == "`":
                        index += 1
                        break
                    if source.startswith("${", index):
                        dynamic = True
                        emit("punct", "{")
                        index = code(index + 2, True, depth + 1)
                        emit("punct", "}")
                        continue
                    parts.append(source[index])
                    index += 1
                else:
                    issues.append("Unterminated JavaScript template")
                tokens[slot] = ("dynamic_template" if dynamic else "string", "".join(parts))
                continue
            previous = tokens[-1] if tokens else None
            regex_allowed = (
                previous is None
                or previous[1]
                in {
                    "(",
                    "[",
                    "{",
                    "=",
                    ":",
                    ",",
                    ";",
                    "!",
                    "?",
                    ")control",
                    "=>",
                    "+",
                    "-",
                    "*",
                    "/",
                    "%",
                    "**",
                    "&&",
                    "||",
                    "??",
                    "&",
                    "|",
                    "^",
                    "~",
                    "+=",
                    "-=",
                    "*=",
                    "/=",
                    "%=",
                    "&&=",
                    "||=",
                    "??=",
                    "==",
                    "!=",
                    "===",
                    "!==",
                    "<",
                    ">",
                    "<=",
                    ">=",
                }
                or (
                    previous[0] == "identifier"
                    and previous[1]
                    in {
                        "return",
                        "throw",
                        "case",
                        "yield",
                        "await",
                        "void",
                        "typeof",
                        "delete",
                        "of",
                        "in",
                        "instanceof",
                        "new",
                    }
                )
            )
            if (
                char == "<"
                and index + 1 < length
                and (source[index + 1].isalpha() or source[index + 1] == "_")
                and (
                    previous is None
                    or previous[1]
                    in {
                        "=",
                        "(",
                        "{",
                        ":",
                        ",",
                        "?",
                        "&",
                        "&&",
                        "||",
                        "??",
                        "=>",
                        ">",
                        "}",
                        "return",
                    }
                )
            ):
                jsx_tag_bases.append(braces)
            jsx_self_close = (
                char == "/"
                and source.startswith("/>", index)
                and bool(jsx_tag_bases)
                and braces == jsx_tag_bases[-1]
            )
            if char == "/" and previous and previous[1] == "}" and not jsx_self_close:
                issues.append(
                    "Ambiguous JavaScript slash after closing brace requires owner syntax review"
                )
            if char == "/" and regex_allowed and not jsx_self_close:
                regex_start = index
                index += 1
                in_class = False
                closed = False
                while index < length:
                    if source[index] == "\\":
                        index += 2
                        continue
                    if source[index] == "[":
                        in_class = True
                    if source[index] == "]":
                        in_class = False
                    if source[index] == "/" and not in_class:
                        index += 1
                        while index < length and source[index].isalpha():
                            index += 1
                        closed = True
                        break
                    if source[index] in "\r\n":
                        break
                    index += 1
                if not closed:
                    issues.append("Unparsed JavaScript regex span")
                emit("regex", source[regex_start:index])
                continue
            if char.isalpha() or char in "_$":
                end = index + 1
                while end < length and (source[end].isalnum() or source[end] in "_$"):
                    end += 1
                emit("identifier", source[index:end])
                index = end
                continue
            if char == ">" and bool(jsx_tag_bases) and braces == jsx_tag_bases[-1]:
                jsx_tag_bases.pop()
            operator = next(
                (
                    op
                    for op in (
                        ">>>=",
                        "**=",
                        "===",
                        "!==",
                        "<<=",
                        ">>=",
                        "&&=",
                        "||=",
                        "??=",
                        ">>>",
                        "=>",
                        "++",
                        "--",
                        "&&",
                        "||",
                        "??",
                        "==",
                        "!=",
                        "<=",
                        ">=",
                        "+=",
                        "-=",
                        "*=",
                        "/=",
                        "%=",
                        "&=",
                        "|=",
                        "^=",
                        "<<",
                        ">>",
                        "**",
                        "?.",
                        "...",
                    )
                    if source.startswith(op, index)
                ),
                None,
            )
            if operator:
                emit("punct", operator)
                index += len(operator)
                continue
            if char == "(":
                parens.append(
                    bool(
                        previous
                        and previous[1] in {"if", "while", "for", "switch", "catch", "with"}
                    )
                )
                emit("punct", char)
            elif char == ")":
                emit("punct", ")control" if parens and parens.pop() else ")")
            elif char == "{":
                braces += 1
                emit("punct", char)
            elif char == "}":
                if interpolation and braces == 0:
                    return index + 1
                braces -= 1
                emit("punct", char)
            else:
                emit("punct", char)
            index += 1
        if interpolation:
            issues.append("Unterminated JavaScript template expression")
        return index

    code(0)
    refs = []
    tools = []
    for index, (kind, value) in enumerate(tokens):
        if (
            kind == "identifier"
            and value in {"execFileSync", "execFile", "spawnSync", "spawn"}
            and index + 2 < len(tokens)
            and tokens[index + 1][1] == "("
            and tokens[index + 2][0] == "string"
        ):
            tools.append(tokens[index + 2][1])
        if kind != "identifier" or value not in {"import", "export", "require"}:
            continue
        if index and tokens[index - 1][1] in {".", "?."}:
            continue
        following = tokens[index + 1 :]
        if not following:
            continue
        if (
            value == "require"
            and len(following) > 1
            and following[0][1] == "?."
            and following[1][1] == "("
        ):
            following = following[1:]
        if value == "require" and following[0][1] == "(":
            nesting = 0
            method = False
            for position, token in enumerate(following):
                if token[1] == "(":
                    nesting += 1
                elif token[1] == ")":
                    nesting -= 1
                    if nesting == 0:
                        method = position + 1 < len(following) and following[position + 1][1] == "{"
                        break
            if method:
                continue
        if value in {"import", "require"} and following[0][1] == "(":
            if len(following) > 2 and following[1][0] == "string" and following[2][1] == ")":
                refs.append(following[1][1])
            else:
                issues.append("Dynamic JavaScript module argument requires owner closure review")
        elif value == "import" and following[0][0] == "string":
            refs.append(following[0][1])
        elif (value == "import" and following[0][1] != ".") or (
            value == "export" and following[0][1] in {"{", "*", "type"}
        ):
            for offset, token in enumerate(following):
                if token[1] == ";" or (
                    token[0] == "identifier" and token[1] in {"import", "export"}
                ):
                    break
                if (
                    token == ("identifier", "from")
                    and offset + 1 < len(following)
                    and following[offset + 1][0] == "string"
                ):
                    refs.append(following[offset + 1][1])
                    break
    comment_elided = source
    for start, end, replacement in sorted(comment_spans, reverse=True):
        comment_elided = comment_elided[:start] + replacement + comment_elided[end:]
    metadata = {
        "comment_elided_raw_sha256": digest(comment_elided.strip("\r\n").encode()),
        "complete_lexical_code_sha256": digest(
            json.dumps(
                list(zip(tokens, token_newlines, strict=True)), separators=(",", ":")
            ).encode()
        ),
        "scope": (
            "Full-file tokens of the bounded reader, raw regex and "
            "token-boundary newlines. Only whitespace/comments normalized; "
            "no inferred loader or environment closure."
        ),
    }
    if include_metadata:
        return refs, sorted(set(issues)), tools, metadata
    return (refs, sorted(set(issues)), tools) if include_operating else (refs, sorted(set(issues)))


def parse_hashed_requirements(value):
    """Bounded hash-locked format: account for every byte; no pip execution."""
    headers = list(
        re.finditer(
            r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.+!-]*) \\\n", value, re.M
        )
    )
    if not headers:
        return None
    prefix = value[: headers[0].start()]
    if any(line.strip() and not line.startswith("#") for line in prefix.splitlines()):
        return None
    groups = []
    names = set()
    for i, h in enumerate(headers):
        name = re.sub(r"[-_.]+", "-", h[1]).lower()
        block = value[h.start() : headers[i + 1].start() if i + 1 < len(headers) else len(value)]
        if name in names:
            return None
        names.add(name)
        hashes = []
        ended = False
        for line in block.splitlines()[1:]:
            if not line.strip() or line.startswith("    #"):
                continue
            match = re.fullmatch(r"    --hash=sha256:([0-9a-f]{64})( \\)?", line)
            if not match or ended:
                return None
            hashes.append(match[1])
            ended = not bool(match[2])
        if not hashes or not ended:
            return None
        groups.append(
            {
                "name": name,
                "version": h[2],
                "hashes": hashes,
                "block_sha256": digest(block.encode()),
            }
        )
    return {
        "prefix_sha256": digest(prefix.encode()),
        "groups": groups,
        "fully_parsed_hash_groups": True,
        "environment_closure": (
            "unknown; hashes enumerate distributions, not installed transitive environment"
        ),
    }


def yaml_run_scripts(value):
    """Read literal GitHub-style run scalars/blocks; no YAML execution."""
    lines = value.splitlines()
    scripts = []
    issues = []
    for line in lines:
        selection = re.match(r"^\s*(?:-\s*)?shell:\s*(.+?)\s*$", line)
        if selection and selection[1].strip("\"'").split(" ")[0] not in {"bash", "sh"}:
            issues.append(
                "Workflow interpreter other than literal bash/sh requires owner closure review"
            )
    i = 0
    while i < len(lines):
        match = re.match(r"^( *)(?:-\s*)?run:\s*(.*?)\s*$", lines[i])
        if not match:
            i += 1
            continue
        indent = len(match[1])
        scalar = match[2]
        i += 1
        if scalar in {"|", "|-", "|+", ">", ">-", ">+"}:
            block = []
            while i < len(lines) and (
                not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip(" ")) > indent
            ):
                block.append(lines[i])
                i += 1
            nonempty = [len(line) - len(line.lstrip(" ")) for line in block if line.strip()]
            width = min(nonempty) if nonempty else indent + 1
            scripts.append("\n".join(line[width:] for line in block))
        elif scalar.startswith(("*", "&")) or not scalar:
            issues.append("Nonliteral workflow run script requires owner review")
        else:
            if scalar.startswith(('"', "'")):
                try:
                    scalar = ast.literal_eval(scalar)
                except (ValueError, SyntaxError):
                    issues.append("Quoted workflow run scalar requires owner review")
                    continue
                if not isinstance(scalar, str):
                    issues.append("Nontext workflow run scalar")
                    continue
            scripts.append(scalar)
    return scripts, issues


def embedded_python_operating_calls(content, local_python):
    tools = []
    issues = []
    try:
        tree = ast.parse(content)
    except (ValueError, SyntaxError):
        return [], ["Embedded Python source unreadable to parser"]
    modules = {}
    runners = {}
    runner_names = {"run", "Popen", "check_output", "check_call", "call"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".")[0]
                if root not in sys.stdlib_module_names and root not in local_python:
                    issues.append(
                        "Embedded Python external import closure requires review: " + root
                    )
                if item.name == "subprocess":
                    modules[item.asname or "subprocess"] = "subprocess"
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            root = node.module.split(".")[0]
            if root not in sys.stdlib_module_names and root not in local_python:
                issues.append("Embedded Python external import closure requires review: " + root)
            if node.module == "subprocess":
                for item in node.names:
                    if item.name in runner_names:
                        runners[item.asname or item.name] = item.name
                    elif item.name == "*":
                        issues.append("Embedded Python wildcard subprocess import requires review")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        runner = (isinstance(node.func, ast.Name) and node.func.id in runners) or (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in modules
            and node.func.attr in runner_names
        )
        if not runner:
            continue
        argument = (
            node.args[0]
            if node.args
            else next((kw.value for kw in node.keywords if kw.arg == "args"), None)
        )
        if (
            isinstance(argument, (ast.List, ast.Tuple))
            and argument.elts
            and isinstance(argument.elts[0], ast.Constant)
            and isinstance(argument.elts[0].value, str)
        ):
            tools.append(argument.elts[0].value)
        else:
            issues.append("Embedded Python subprocess string/dynamic command requires owner review")
    return tools, issues


def shell_operating_calls(value, *, local_python=(), depth=0):
    """Bounded literal commands; inspect executable heredocs, exclude inert data."""
    if depth > 4:
        return [], ["Embedded shell depth exceeds review bound"]
    lines = value.splitlines()
    shell = []
    i = 0
    issues = []
    embedded_tools = []
    while i < len(lines):
        line = lines[i]
        shell.append(line)
        i += 1
        heredocs = list(re.finditer(r"<<(-)?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2", line))
        if "<<" in line and not heredocs:
            issues.append("Unparsed heredoc delimiter requires owner closure review")
        for here in heredocs:
            found = False
            body = []
            while i < len(lines):
                candidate = lines[i].lstrip("\t") if here[1] else lines[i]
                i += 1
                if candidate == here[3]:
                    found = True
                    break
                body.append(candidate)
            if not found:
                issues.append("Unterminated shell heredoc requires owner review")
                continue
            content = "\n".join(body)
            if not here[2] and any(char in content for char in "$`"):
                issues.append("Unquoted heredoc shell expansion requires owner closure review")
            if re.match(r"^\s*python(?:3(?:\.[0-9]+)?)?\s", line):
                tools, nested = embedded_python_operating_calls(content, local_python)
                embedded_tools.extend(tools)
                issues.extend(nested)
            elif re.match(r"^\s*(?:bash|sh)\s", line):
                tools, nested = shell_operating_calls(
                    content, local_python=local_python, depth=depth + 1
                )
                embedded_tools.extend(tools)
                issues.extend(nested)
            else:
                issues.append(
                    "Unclassified or generated heredoc content requires owner provenance review"
                )
    source = "\n".join(shell)
    tools = re.findall(
        r"(?:^|[\n;&|])\s*(git|gh|vercel|restic|psql|pg_dump|pg_restore|docker|npm|npx|pip|pip3)\s",
        source,
    )
    return tools + embedded_tools, issues


def inspect_files(
    files,
    *,
    source_id,
    ref,
    owner,
    reviewed_provenance=False,
    listing_complete=True,
    first_party_packages=None,
):
    entries = {}
    unknown = []
    sources = []
    requirements_sets = {}
    critical_gaps = []
    sdk_modules = []
    javascript_code_fingerprints = {}

    def add(category, ecosystem, name, version, path, kind):
        # Installation/declaration/use-site counts are separate from unique package count.
        ident = json.dumps([category, ecosystem, name, path, kind], separators=(",", ":"))
        entries[ident] = {
            "id": ident,
            "category": category,
            "ecosystem": ecosystem,
            "name": name,
            "version_or_ref": str(version or "unknown"),
            "path": path,
            "kind": kind,
            "owner": owner,
        }
        return entries[ident]

    def operating(tool, path):
        tool = pathlib.PurePosixPath(tool).name
        if tool in {
            "python",
            "python3",
            "node",
            "swift",
            "swiftc",
            "clang",
            "xcrun",
            "xcodebuild",
            "sh",
            "bash",
            "zsh",
            "echo",
            "printf",
            "test",
            "true",
            "false",
        }:
            return
        scope = (
            "source_ci_build_test"
            if path.startswith((".github/", "scripts/", "tools/", "tests/", "test/", "e2e/"))
            or pathlib.PurePosixPath(path).name.startswith(
                ("test_", "test-", "check_", "check-", "dependency_")
            )
            else "application_or_helper_runtime"
        )
        ident = json.dumps(["operating_tools", "executable", tool, scope], separators=(",", ":"))
        if ident in entries:
            if path not in entries[ident]["use_sites"]:
                entries[ident]["use_sites"].append(path)
        else:
            entries[ident] = {
                "id": ident,
                "category": "operating_tools",
                "ecosystem": "executable",
                "name": tool,
                "version_or_ref": "operational prerequisite",
                "path": path,
                "kind": scope,
                "owner": owner,
                "use_sites": [path],
                "exit_or_constraint": (
                    "Owner qualifies a standard-library/first-party alternat"
                    "ive preserving behavior, or documents actual unavoidabl"
                    "e platform constraint. OS distribution alone is not exe"
                    "mption."
                ),
            }

    def gap(path, reason, coverage_kind="unparsed"):
        unknown.append(
            {"path": path, "reason": reason, "owner": owner, "coverage_kind": coverage_kind}
        )

    def text(path, raw, required=False):
        if raw is None:
            if required:
                critical_gaps.append({"path": path, "reason": "Required dependency input unread"})
            gap(path, "tracked source unread, oversized or unsupported blob")
            return None
        sources.append({"path": path, "sha256": digest(raw), "bytes": len(raw)})
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            if required:
                critical_gaps.append(
                    {"path": path, "reason": "Required dependency input is not UTF-8 text"}
                )
            gap(path, "binary dependency/provenance requires owner review")
            return None

    local_py = {pathlib.PurePosixPath(p).stem for p in files if p.endswith(".py")} | {
        p.split("/")[0] for p in files if "/" in p and p.endswith(".py")
    }
    npm_scopes = {}
    for manifest, raw in files.items():
        if pathlib.PurePosixPath(manifest).name != "package.json" or raw is None:
            continue
        try:
            data = json.loads(raw)
            npm_scopes[str(pathlib.PurePosixPath(manifest).parent)] = {
                name
                for group in [
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                ]
                for name in data.get(group, {})
            }
        except (ValueError, TypeError, AttributeError):
            pass
    manifests_found = False
    for path, raw in sorted(files.items()):
        name = pathlib.PurePosixPath(path).name
        lower = path.lower()
        suffix = pathlib.PurePosixPath(path).suffix.lower()
        is_manifest = name in {
            "skills-lock.json",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
            "Package.swift",
            "Package.resolved",
            "Podfile.lock",
            ".gitmodules",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "Gemfile",
            "Gemfile.lock",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "uv.lock",
            "Pipfile",
            "Pipfile.lock",
            "CMakeLists.txt",
            "codemagic.yaml",
            "codemagic.yml",
        } or bool(re.search(r"(^|/)(requirements[^/]*\.txt|[^/]*\.gradle(\.kts)?)$", path))
        interesting = source_candidate(path)
        if not interesting:
            continue
        value = text(path, raw, required=is_manifest)
        if value is None:
            continue
        if is_manifest:
            manifests_found = True
        try:
            if name == "skills-lock.json":
                data = json.loads(value)
                for skill, metadata in data.get("skills", {}).items():
                    add(
                        "vendored_cdn",
                        "agent_skill",
                        skill,
                        metadata.get("computedHash") or metadata.get("source") or "unresolved",
                        path,
                        "third_party_skill",
                    )
            elif name == "package.json":
                data = json.loads(value)
                for key in [
                    "dependencies",
                    "optionalDependencies",
                    "peerDependencies",
                    "devDependencies",
                ]:
                    for package, version in data.get(key, {}).items():
                        cat = (
                            "build_test_dev_direct"
                            if key == "devDependencies"
                            else "runtime_direct"
                        )
                        add(cat, "npm", package, version, path, key)
                        if str(version).startswith(("file:", "link:", "workspace:")):
                            gap(
                                path,
                                (
                                    "local package reference needs first-party provenance/ow"
                                    "ned dependency-closure review: "
                                )
                                + package,
                            )
            elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
                data = json.loads(value)
                if data.get("lockfileVersion") not in [2, 3] or not isinstance(
                    data.get("packages"), dict
                ):
                    gap(path, "npm lock format unsupported/incomplete; transitive count unknown")
                for location, package in data.get("packages", {}).items():
                    if not location:
                        continue
                    package_name = package.get("name") or location.rsplit("node_modules/", 1)[-1]
                    add(
                        "build_test_dev_resolved_placements"
                        if package.get("dev") is True
                        else "runtime_resolved_placements",
                        "npm",
                        package_name,
                        package.get("version"),
                        path + ":" + location,
                        "locked_installation",
                    )
            elif name == "pyproject.toml":
                data = tomllib.loads(value)
                for dep in data.get("project", {}).get("dependencies", []):
                    add(
                        "runtime_direct",
                        "python",
                        re.split(r"[ <>=!~\[;]", dep)[0],
                        dep,
                        path,
                        "project_dependency",
                    )
                for group, deps in data.get("project", {}).get("optional-dependencies", {}).items():
                    for dep in deps:
                        add(
                            "build_test_dev_direct",
                            "python",
                            re.split(r"[ <>=!~\[;]", dep)[0],
                            dep,
                            path,
                            "optional_group:" + group,
                        )
                for dep in data.get("build-system", {}).get("requires", []):
                    add(
                        "build_test_dev_direct",
                        "python",
                        re.split(r"[ <>=!~\[;]", dep)[0],
                        dep,
                        path,
                        "build_system",
                    )
                if data.get("tool", {}).get("poetry"):
                    gap(path, "Poetry-specific dependency tables require parsing/owner inventory")
            elif name.startswith("requirements") and name.endswith(".txt"):
                parsed = parse_hashed_requirements(value)
                if parsed:
                    requirements_sets[path] = parsed
                    for group in parsed["groups"]:
                        add(
                            "runtime_direct",
                            "python",
                            group["name"],
                            group["version"],
                            path,
                            "requirement",
                        )
                    gap(
                        path,
                        "requirements alone do not resolve full transitive environment",
                        "python_environment_unmeasured",
                    )
                else:
                    for line in value.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("-"):
                            gap(path, "requirements include/options need closure review")
                            continue
                        add(
                            "runtime_direct",
                            "python",
                            re.split(r"[ <>=!~\[;]", line)[0],
                            line,
                            path,
                            "requirement",
                        )
                    gap(path, "requirements alone do not resolve full transitive environment")
            elif name == "Package.resolved":
                data = json.loads(value)
                pins = data.get("pins", data.get("object", {}).get("pins", []))
                for pin in pins:
                    add(
                        "native",
                        "swift",
                        pin.get("identity") or pin.get("package") or pin.get("repositoryURL"),
                        pin.get("state", {}).get("version") or pin.get("state", {}).get("revision"),
                        path,
                        "locked_pin",
                    )
            elif name == "Package.swift":
                for url in re.findall(r'\.package\s*\(\s*url:\s*"([^"]+)"', value):
                    add("native", "swift", url, "declared", path, "remote_package")
                if ".package(" in value and not re.search(r"\.package\s*\(\s*url:", value):
                    gap(path, "non-literal/local Swift package closure/provenance requires review")
            elif name == "Podfile.lock":
                for package, version in re.findall(r"^\s{2}- ([^ (:]+) \(([^)]+)\)", value, re.M):
                    add("native", "cocoapods", package, version, path, "locked_pod")
                gap(
                    path,
                    (
                        "Pod lock parsing bounded; external/local-source metadat"
                        "a and installed native closure require owner review"
                    ),
                )
            elif name == ".gitmodules":
                for url in re.findall(r"^\s*url\s*=\s*(.+)", value, re.M):
                    add("vendored_cdn", "git", url, "submodule", path, "external_source")
            elif (
                name
                in {
                    "Cargo.toml",
                    "Cargo.lock",
                    "go.mod",
                    "go.sum",
                    "Gemfile",
                    "Gemfile.lock",
                    "yarn.lock",
                    "pnpm-lock.yaml",
                    "poetry.lock",
                    "uv.lock",
                    "Pipfile",
                    "Pipfile.lock",
                    "CMakeLists.txt",
                }
                or ".gradle" in name
            ):
                gap(
                    path,
                    (
                        "recognized dependency manifest/lock not parsed by initi"
                        "al inventory; owner follow-through required"
                    ),
                )
        except (ValueError, TypeError, AttributeError):
            if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
                critical_gaps.append(
                    {"path": path, "reason": "Required npm input malformed or unsupported shape"}
                )
            gap(path, "manifest malformed or unsupported fields; not zero")
        if suffix == ".py":
            try:
                tree = ast.parse(value)
                for node in ast.walk(tree):
                    names = (
                        [n.name.split(".")[0] for n in node.names]
                        if isinstance(node, ast.Import)
                        else [node.module.split(".")[0]]
                        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0
                        else []
                    )
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in {"run", "Popen", "check_output", "check_call", "call"}
                        and node.args
                        and isinstance(node.args[0], (ast.List, ast.Tuple))
                        and node.args[0].elts
                        and isinstance(node.args[0].elts[0], ast.Constant)
                        and isinstance(node.args[0].elts[0].value, str)
                    ):
                        operating(node.args[0].elts[0].value, path)
                    for module in names:
                        if module not in sys.stdlib_module_names and module not in local_py:
                            add(
                                "source_import_references",
                                "python_import",
                                module,
                                "unresolved",
                                path,
                                "source_import",
                            )
            except (SyntaxError, ValueError):
                gap(path, "Python source import analysis unavailable")
        if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
            module_refs, lexical_issues, operating_calls, metadata = js_module_references(
                value, include_operating=True, include_metadata=True
            )
            javascript_code_fingerprints[path] = metadata
            for tool in operating_calls:
                operating(tool, path)
            for issue in lexical_issues:
                gap(
                    path,
                    issue,
                    "dynamic_js_module"
                    if issue.startswith("Dynamic JavaScript module argument")
                    else "unparsed",
                )
            for specifier in module_refs:
                if specifier.startswith((".", "/", "@/", "~/", "#", "node:")):
                    continue
                if specifier.split("/")[0] in NODE_CORE:
                    continue
                if specifier.startswith(("http:", "https:")):
                    add("vendored_cdn", "url", specifier, "remote", path, "remote_import")
                else:
                    package = (
                        "/".join(specifier.split("/")[:2])
                        if specifier.startswith("@")
                        else specifier.split("/")[0]
                    )
                    entry = add(
                        "source_import_references",
                        "js_import",
                        package,
                        "unresolved",
                        path,
                        "source_import",
                    )
                    entry["usage_scope"] = (
                        "build_test_dev"
                        if path.startswith(
                            ("scripts/", "tools/", "tests/", "test/", "e2e/", ".github/")
                        )
                        or re.search(r"(^|/)[^/]+\.(test|spec)\.[^/]+$", path)
                        else "runtime_or_unknown"
                    )
                    directory = pathlib.PurePosixPath(path).parent
                    ancestors = [directory, *directory.parents]
                    scope = next(
                        (
                            str(parent)
                            for parent in ancestors
                            if package in npm_scopes.get(str(parent), set())
                        ),
                        None,
                    )
                    if scope is None:
                        gap(
                            path,
                            (
                                "External JS import lacks declaration in available ances"
                                "tor package scopes: "
                            )
                            + package,
                        )
                    else:
                        entry["declaration_manifest"] = str(
                            pathlib.PurePosixPath(scope) / "package.json"
                        )
        if suffix in {".sh", ".yml", ".yaml"}:
            scripts, run_issues = (
                yaml_run_scripts(value) if suffix in {".yml", ".yaml"} else ([value], [])
            )
            for issue in run_issues:
                gap(path, issue)
            for script in scripts:
                tools, shell_issues = shell_operating_calls(script, local_python=local_py)
                for tool in tools:
                    operating(tool, path)
                for issue in shell_issues:
                    gap(path, issue)
        if suffix == ".swift":
            for module in re.findall(r"^\s*(?:@testable\s+)?import\s+(\w+)", value, re.M):
                if module in APPLE_MODULE_PROVENANCE:
                    sdk_modules.append(
                        {
                            "module": module,
                            "path": path,
                            "evidence": APPLE_MODULE_PROVENANCE[module],
                            "scope": (
                                "Explicit first-party platform SDK primitive; "
                                "source import classification, "
                                "not physical third-party removal or availability "
                                "proof on another host"
                            ),
                        }
                    )
                if module not in APPLE:
                    add("native", "swift_import", module, "unresolved", path, "source_import")
        if suffix in {".pbxproj", ".xcproj"}:
            for url in re.findall(r'repositoryURL\s*=\s*"?([^;"\s]+)', value):
                add("native", "xcode", url, "declared", path, "remote_package")
        if path.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
            add("hosted_services", "service", "github_actions", "operating", path, "hosted_ci")
            for action in re.findall(r"^\s*(?:-\s*)?uses:\s*[\'\"]?([^\s\'\"#]+)", value, re.M):
                if not action.startswith("./"):
                    add(
                        "ci_actions_tools",
                        "github_action",
                        action.split("@")[0],
                        action.partition("@")[2] or "unpinned",
                        path,
                        "external_action",
                    )
                    if action.startswith("actions/checkout@"):
                        operating("git", path)
            for manager, tool in re.findall(
                r"\b(brew|pip3?|uv)\s+(?:install|tool install)\s+([\w@./-]+)", value
            ):
                add("ci_actions_tools", manager, tool, "declared", path, "install_command")
        for image in re.findall(r"^(?:FROM|\s*image:)\s*[\'\"]?([^\s\'\"]+)", value, re.M):
            add("ci_actions_tools", "container_image", image, "declared", path, "container_image")
        if name.startswith("codemagic."):
            add("hosted_services", "service", "codemagic", "operating", path, "hosted_ci")
        if suffix in {".html", ".css"}:
            for url in re.findall(
                r"(?:src=|@import\s*|url\()[\'\"]?(https?://[^\s\'\"<>)]*)", value
            ):
                add("vendored_cdn", "url", url, "remote", path, "remote_asset")
        if any(
            part in lower.split("/")
            for part in ["vendor", "vendored", "third_party", "third-party"]
        ) or lower.endswith((".min.js", ".wasm")):
            add(
                "vendored_cdn",
                "source",
                path,
                "provenance_review",
                path,
                "vendored_or_compiled_candidate",
            )
        if re.search(
            (
                "^\\s*(?:(?://|#|/\\*+!?|\\*|<!--)\\s*)?Copyright(?:\\s|\\(c\\)"
                "|©)[^\\n]*(Microsoft|Mozilla|Facebook|Ionic|Expo|Google|"
                "OpenJS)"
            ),
            value,
            re.I | re.M,
        ):
            add("vendored_cdn", "source", path, "attribution", path, "upstream_attribution")
        # Operational code/config and remote profile images; ordinary doc links
        # are not service reliance.
        operational = suffix != ".md" or (name == "README.md" and "![" in value)
        if operational:
            for service, hosts in SERVICES.items():
                if re.search(r"https?://[^\s\'\"<>]*(?:" + hosts.replace(".", r"\.") + r")", value):
                    add("hosted_services", "service", service, "operating", path, "source_endpoint")
    if not listing_complete:
        gap("*", "source listing incomplete")
    if not reviewed_provenance:
        gap(
            "*",
            (
                "Copied/hidden/vendored code, generated/install-time con"
                "tent and services require named owner provenance/closur"
                "e review; scanner absence is not zero proof"
            ),
        )
    if not manifests_found and not reviewed_provenance:
        gap(
            "*",
            (
                "No recognized package manifest; source/native/tool/oper"
                "ating dependencies still require review"
            ),
        )
    # Exact, explicit provenance only; no namespace exemption.
    first_party_packages = first_party_packages or {}
    root_package = {}
    try:
        root_package = json.loads(files.get("package.json") or b"{}")
    except (ValueError, TypeError):
        root_package = {}
    locks = {}
    manifests = {}
    for path, raw in files.items():
        if raw is None:
            continue
        try:
            if pathlib.PurePosixPath(path).name in {
                "package.json",
                "package-lock.json",
                "npm-shrinkwrap.json",
            }:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    critical_gaps.append(
                        {"path": path, "reason": "Required npm JSON root must be an object"}
                    )
                    gap(path, "JSON dependency manifest/lock root must be an object")
                    continue
                if pathlib.PurePosixPath(path).name == "package.json":
                    manifests[str(pathlib.PurePosixPath(path).parent)] = (path, data)
                else:
                    if not isinstance(data.get("packages", {}), dict) or any(
                        not isinstance(v, dict) for v in data.get("packages", {}).values()
                    ):
                        critical_gaps.append(
                            {"path": path, "reason": "Required npm lock packages records malformed"}
                        )
                        gap(path, "npm lock packages must be an object of package records")
                        continue
                    locks[str(pathlib.PurePosixPath(path).parent)] = (path, data)
        except (ValueError, TypeError):
            pass
    verified_first_party = {}
    for package, proof in first_party_packages.items():
        matching = [
            entry
            for _, lock in locks.values()
            for loc, entry in lock.get("packages", {}).items()
            if loc.endswith("node_modules/" + package)
        ]
        if (
            root_package.get("name") == package
            and proof.get("repository") == source_id
            and proof.get("version")
            and proof.get("gitHead")
            and proof.get("integrity")
            and matching
            and all(
                e.get("version") == proof["version"] and e.get("integrity") == proof["integrity"]
                for e in matching
            )
        ):
            verified_first_party[package] = proof
    for entry in entries.values():
        if entry["name"] in verified_first_party and entry["ecosystem"] in {"npm", "js_import"}:
            entry["external_category_before_provenance"] = entry["category"]
            entry["category"] = "first_party_reuse"
            entry["provenance"] = verified_first_party[entry["name"]]
    units = []
    unresolved = []
    for directory, (manifest_path, data) in sorted(manifests.items()):
        declarations = [
            e
            for e in entries.values()
            if e["ecosystem"] == "npm"
            and e["path"] == manifest_path
            and e["kind"] != "locked_installation"
        ]
        lock_info = locks.get(directory)
        if data.get("workspaces"):
            gap(manifest_path, "npm workspaces closure requires owner review")
        item = {
            "manifest": manifest_path,
            "declarations": len(declarations),
            "external_runtime_declarations": sum(
                e["category"] == "runtime_direct" for e in declarations
            ),
            "external_build_test_dev_declarations": sum(
                e["category"] == "build_test_dev_direct" for e in declarations
            ),
            "first_party_declarations": sum(
                e["category"] == "first_party_reuse" for e in declarations
            ),
            "resolved_placements_total": None,
            "direct_resolved_placements": None,
            "additional_transitive_placements": None,
        }
        if not lock_info:
            item["additional_unknown_reason"] = "no corresponding parsed lock"
            unresolved.append(manifest_path)
        else:
            lock_path, lock = lock_info
            packages = lock.get("packages")
            root = packages.get("") if isinstance(packages, dict) else None
            root_valid = isinstance(root, dict) and all(
                root.get(group, {}) == data.get(group, {})
                for group in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ]
            )
            if not root_valid:
                critical_gaps.append(
                    {
                        "path": lock_path,
                        "reason": (
                            "npm lock root metadata missing or declaration groups "
                            "differ from manifest"
                        ),
                    }
                )
            if (
                not root_valid
                or lock.get("lockfileVersion") not in [2, 3]
                or not isinstance(packages, dict)
                or data.get("workspaces")
                or any(
                    (p and not p.startswith("node_modules/")) or v.get("link")
                    for p, v in (packages or {}).items()
                )
            ):
                gap(lock_path, "npm workspace/link/split lock closure requires owner review")
                item["additional_unknown_reason"] = "workspace/link/split or unsupported lock graph"
                unresolved.append(manifest_path)
            else:
                placements = {loc for loc in packages if loc}
                direct = {"node_modules/" + e["name"] for e in declarations}
                item["resolved_placements_total"] = len(placements)
                if direct <= placements:
                    item["direct_resolved_placements"] = len(direct)
                    item["additional_transitive_placements"] = len(placements - direct)
                else:
                    item["additional_unknown_reason"] = (
                        "declared roots lack deterministic lock placement"
                    )
                    unresolved.append(manifest_path)
        units.append(item)
    for directory, (lock_path, _lock) in locks.items():
        if directory not in manifests:
            unresolved.append(lock_path)
    for unresolved_scope in sorted(set(unresolved)):
        semantic_only = any(
            p["manifest"] == unresolved_scope
            and p.get("additional_unknown_reason") == "no corresponding parsed lock"
            for p in units
        )
        gap(
            unresolved_scope,
            "npm resolution/lock scope remains unknown",
            "npm_resolution_unmeasured" if semantic_only else "unparsed",
        )
    npm_entries = [e for e in entries.values() if e["ecosystem"] == "npm"]
    placements = [e for e in npm_entries if e["kind"] == "locked_installation"]
    declared = [e for e in npm_entries if e["kind"] != "locked_installation"]
    npm_units = {
        "declarations_total": len(declared),
        "external_runtime_declarations": sum(e["category"] == "runtime_direct" for e in declared),
        "external_build_test_dev_declarations": sum(
            e["category"] == "build_test_dev_direct" for e in declared
        ),
        "first_party_declarations": sum(e["category"] == "first_party_reuse" for e in declared),
        "resolved_placements_total": len(placements),
        "external_resolved_placements": sum(
            e["category"] != "first_party_reuse" for e in placements
        ),
        "first_party_resolved_placements": sum(
            e["category"] == "first_party_reuse" for e in placements
        ),
        "direct_resolved_placements": None
        if unresolved
        else sum(x["direct_resolved_placements"] or 0 for x in units),
        "additional_transitive_placements": None
        if unresolved
        else sum(x["additional_transitive_placements"] or 0 for x in units),
        "projects": units,
        "additional_unknown_scopes": sorted(set(unresolved)),
        "units": (
            "Declarations, total resolved placements, and additional"
            " transitive placements are distinct. Multiple disjoint "
            "lock projects add installation sites; workspace/unresol"
            "ved/split relationships stay unknown."
        ),
    }
    counts = {c: sum(e["category"] == c for e in entries.values()) for c in CATEGORIES}
    known = sum(counts[c] for c in CATEGORIES if c not in {"hosted_services", "first_party_reuse"})
    state = "nonzero" if known else "unknown" if unknown else "zero"
    floor = dict(FLOOR)
    languages = []
    if any(p.endswith(".py") for p in files):
        languages.append(
            "Python interpreter and standard library; inventory/checker needs Python >=3.11"
        )
    if any(
        p.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")) or p.endswith("package.json")
        for p in files
    ):
        languages.append(
            "Node.js interpreter and built-in modules; exact engines"
            "/version remains per manifest/owner"
        )
    if any(p.endswith((".swift", ".m", ".mm", ".c", ".cpp")) for p in files):
        languages.append(
            "Language compiler/standard library; first-party SDK/too"
            "lchain only as actually required by owning source"
        )
    floor["runtimes_compilers_stdlib"] = [
        *languages,
        (
            "Actual OS shell primitives where justified; Git/helper "
            "executables remain counted operating dependencies"
        ),
    ]
    floor["scope"] = (
        "Source-indicated floor; owner must confirm exact deploy"
        "ed machine/runtime/SDK. No implicit Git, package or ser"
        "vice exemption."
    )
    return {
        "schema_version": 1,
        "id": source_id,
        "source_sha": ref,
        "owner": owner,
        "execution_floor": floor,
        "dependency_state": state,
        "category_counts": counts,
        "npm_units": npm_units,
        "requirements_sets": requirements_sets,
        "critical_input_gaps": critical_gaps,
        "explicit_first_party_sdk_modules": sdk_modules,
        "javascript_code_fingerprints": javascript_code_fingerprints,
        "first_party_provenance": verified_first_party,
        "known_dependency_reference_sites": known,
        "known_code_dependency_sites": known - counts["operating_tools"],
        "external_operating_tool_references": counts["operating_tools"],
        "unique_declared_or_locked_packages": len(
            {
                (e["ecosystem"], e["name"])
                for e in entries.values()
                if e["ecosystem"] in ["npm", "python", "swift", "cocoapods"]
            }
        ),
        "dependencies": sorted(entries.values(), key=lambda e: e["id"]),
        "unknowns": sorted(unknown, key=lambda e: (e["path"], e["reason"])),
        "source_listing_complete": listing_complete,
        "provenance_reviewed": reviewed_provenance,
        "source_fingerprints": sorted(sources, key=lambda e: e["path"]),
        "count_units": (
            "Declarations, locked installations and source/use sites"
            " are separately categorized; counts are not summed as d"
            "istinct packages. Hosted services excluded from code-de"
            "pendency total. Unknown coverage is retained."
        ),
    }


def scan_repo(repo, ref, source_id, owner, reviewed_provenance=False, first_party_packages=None):
    try:
        resolved = git(repo, "rev-parse", ref + "^{commit}").decode().strip()
        paths, links = tracked(repo, resolved)
        selected = {p: None for p in paths}
        wanted = [(p, oid) for p, oid in paths.items() if source_candidate(p)]
        # One bounded batch reads tracked Git objects, never the worktree or installed node_modules.
        batch = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            input="".join(oid + "\n" for _, oid in wanted).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout
        offset = 0
        for path, _oid in wanted:
            end = batch.index(b"\n", offset)
            header = batch[offset:end].decode().split()
            size = int(header[2])
            offset = end + 1
            selected[path] = batch[offset : offset + size] if size <= 2_000_000 else None
            offset += size + 1
        result = inspect_files(
            selected,
            source_id=source_id,
            ref=resolved,
            owner=owner,
            reviewed_provenance=reviewed_provenance,
            first_party_packages=first_party_packages,
        )
        for path, oid in links:
            e = {
                "id": json.dumps(["vendored_cdn", "gitlink", path]),
                "category": "vendored_cdn",
                "ecosystem": "gitlink",
                "name": path,
                "version_or_ref": oid,
                "path": path,
                "kind": "submodule",
                "owner": owner,
            }
            result["dependencies"].append(e)
            result["category_counts"]["vendored_cdn"] += 1
            result["known_code_dependency_sites"] += 1
            result["dependency_state"] = "nonzero"
        result["git_directory"] = str(pathlib.Path(repo).resolve())
        result["tracked_file_count"] = len(paths)
        result["source_tree"] = git(repo, "rev-parse", resolved + "^{tree}").decode().strip()
        return result
    except (OSError, ValueError, TypeError, AttributeError, IndexError, subprocess.SubprocessError):
        return {
            "schema_version": 1,
            "id": source_id,
            "source_sha": ref,
            "owner": owner,
            "execution_floor": FLOOR,
            "dependency_state": "unknown",
            "category_counts": {c: None for c in CATEGORIES},
            "dependencies": [],
            "unknowns": [
                {
                    "path": "*",
                    "reason": "Pinned source/listing/blob read unavailable",
                    "owner": owner,
                }
            ],
            "source_listing_complete": False,
            "source_fingerprints": [],
        }


def compare(baseline, current):
    old = {e["id"]: e for e in baseline.get("dependencies", [])}
    new = {e["id"]: e for e in current.get("dependencies", [])}
    additions = [new[k] for k in sorted(new.keys() - old.keys())]
    removed = [old[k] for k in sorted(old.keys() - new.keys())]
    relocated = []
    # A declaration may move to an ancestor if the surviving import resolves there.
    # Pair only same ecosystem/category/name/pin/kind, and require net site count unchanged.
    for added in list(additions):
        if added["ecosystem"] != "npm" or added["category"] not in {
            "runtime_direct",
            "build_test_dev_direct",
        }:
            continue
        previous = next(
            (
                r
                for r in removed
                if all(
                    r.get(k) == added.get(k)
                    for k in ["category", "ecosystem", "name", "version_or_ref", "kind"]
                )
            ),
            None,
        )
        if previous is not None:
            removed.remove(previous)
            additions.remove(added)
            relocated.append(
                {
                    "before": previous,
                    "after": added,
                    "credit": "same dependency retained, no removal",
                }
            )
    changed = [
        {"before": old[k], "after": new[k]}
        for k in sorted(new.keys() & old.keys())
        if old[k].get("version_or_ref") != new[k].get("version_or_ref")
    ]
    old_hash = {f["path"]: f["sha256"] for f in baseline.get("source_fingerprints", [])}
    new_hash = {f["path"]: f["sha256"] for f in current.get("source_fingerprints", [])}
    reuse = []
    for entry in list(additions):
        if entry.get("ecosystem") != "js_import" or entry.get("usage_scope") != "build_test_dev":
            continue
        manifest = entry.get("declaration_manifest")
        lock = (
            str(pathlib.PurePosixPath(manifest).with_name("package-lock.json"))
            if manifest
            else None
        )
        anchors = [
            e
            for e in old.values()
            if e.get("path") == manifest
            and e.get("ecosystem") == "npm"
            and e.get("name") == entry["name"]
            and e.get("category") in {"runtime_direct", "build_test_dev_direct"}
        ]
        if (
            anchors
            and all(
                e["id"] in new and new[e["id"]].get("version_or_ref") == e.get("version_or_ref")
                for e in anchors
            )
            and all(old_hash.get(p) and old_hash[p] == new_hash.get(p) for p in [manifest, lock])
        ):
            additions.remove(entry)
            reuse.append(
                {
                    "use": entry,
                    "declaration": anchors[0],
                    "manifest_sha256": old_hash[manifest],
                    "lock_sha256": old_hash[lock],
                    "credit": "existing package reuse in tooling; dependency retained",
                }
            )
    old_sets = baseline.get("requirements_sets", {})
    new_sets = current.get("requirements_sets", {})
    requirements_regressions = []
    requirements_removal_only = []
    for path, before in old_sets.items():
        after = new_sets.get(path)
        if old_hash.get(path) == new_hash.get(path):
            continue
        retained = {g["name"]: g for g in before["groups"]}
        if (
            after
            and before["prefix_sha256"] == after["prefix_sha256"]
            and all(g == retained.get(g["name"]) for g in after["groups"])
            and [
                g["name"]
                for g in before["groups"]
                if g["name"] in {a["name"] for a in after["groups"]}
            ]
            == [g["name"] for g in after["groups"]]
        ):
            requirements_removal_only.append(path)
        else:
            requirements_regressions.append(path)
    old_projects = {p["manifest"]: p for p in baseline.get("npm_units", {}).get("projects", [])}
    new_projects = {p["manifest"]: p for p in current.get("npm_units", {}).get("projects", [])}
    npm_coverage_regressions = [
        {
            "manifest": path,
            "before": "measured root graph",
            "after": new_projects.get(path, {}).get(
                "additional_unknown_reason", "scope no longer measured"
            ),
        }
        for path, p in old_projects.items()
        if p.get("additional_transitive_placements") is not None
        and (
            path not in new_projects
            or new_projects[path].get("additional_transitive_placements") is None
        )
    ]
    old_gaps = {(g["path"], g["reason"]) for g in baseline.get("unknowns", [])}
    new_gaps = [g for g in current.get("unknowns", []) if (g["path"], g["reason"]) not in old_gaps]
    # Unsupported manifests cannot change silently behind an unchanged parser gap.
    old_hash = {f["path"]: f["sha256"] for f in baseline.get("source_fingerprints", [])}
    new_hash = {f["path"]: f["sha256"] for f in current.get("source_fingerprints", [])}
    changed_unknown = [
        g["path"]
        for g in current.get("unknowns", [])
        if g["path"] != "*"
        and old_hash.get(g["path"]) != new_hash.get(g["path"])
        and g.get("coverage_kind") != "npm_resolution_unmeasured"
        and not (
            g.get("coverage_kind") == "dynamic_js_module"
            and baseline.get("javascript_code_fingerprints", {})
            .get(g["path"], {})
            .get("complete_lexical_code_sha256")
            and baseline["javascript_code_fingerprints"][g["path"]].get("comment_elided_raw_sha256")
            and baseline["javascript_code_fingerprints"][g["path"]]["comment_elided_raw_sha256"]
            == current.get("javascript_code_fingerprints", {})
            .get(g["path"], {})
            .get("comment_elided_raw_sha256")
            and baseline["javascript_code_fingerprints"][g["path"]]["complete_lexical_code_sha256"]
            == current.get("javascript_code_fingerprints", {})
            .get(g["path"], {})
            .get("complete_lexical_code_sha256")
        )
        and not (
            g.get("coverage_kind") == "python_environment_unmeasured"
            and g["path"] in requirements_removal_only
        )
    ]
    invalid = (
        baseline.get("id") != current.get("id")
        or not current.get("source_listing_complete")
        or not baseline.get("source_listing_complete")
        or baseline.get("critical_input_gaps")
        or current.get("critical_input_gaps")
    )
    return {
        "repository": current.get("id"),
        "critical_input_gaps": {
            "baseline": baseline.get("critical_input_gaps", []),
            "candidate": current.get("critical_input_gaps", []),
        },
        "baseline_sha": baseline.get("source_sha"),
        "current_sha": current.get("source_sha"),
        "state": "unknown"
        if invalid
        else "blocked_additions_or_unreviewed_changes"
        if additions
        or changed
        or new_gaps
        or changed_unknown
        or npm_coverage_regressions
        or requirements_regressions
        else "no_additions_observed",
        "additions": additions,
        "relocated_declarations": relocated,
        "existing_package_reuse": reuse,
        "requirements_removal_only": requirements_removal_only,
        "requirements_coverage_regressions": requirements_regressions,
        "removed": removed,
        "verified_removal_credit": 0,
        "removal_credit_boundary": (
            "Observed entries removed only; copying/wrapping/relabel"
            "ing is not removal. Product owner must qualify provenan"
            "ce, behavior and applicable release before credit."
        ),
        "changed_pins": changed,
        "npm_coverage_regressions": npm_coverage_regressions,
        "new_unknowns": new_gaps,
        "changed_unparsed_scopes": sorted(set(changed_unknown)),
        "exit_code": 3
        if invalid
        else 2
        if additions
        or changed
        or new_gaps
        or changed_unknown
        or npm_coverage_regressions
        or requirements_regressions
        else 0,
        "scope": (
            "Known supported source categories only; retained unknow"
            "n provenance is not verified zero. Compare with trusted"
            " default baseline, not a PR-edited allowlist. No baseli"
            "ne auto-accept/update."
        ),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=pathlib.Path, required=True)
    p.add_argument("--ref", default="HEAD")
    p.add_argument("--id", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--baseline", type=pathlib.Path)
    p.add_argument("--out", type=pathlib.Path)
    a = p.parse_args()
    baseline = json.loads(a.baseline.read_text()) if a.baseline else None
    if baseline is not None:
        baseline = (
            next((r for r in baseline.get("repositories", []) if r["id"] == a.id), None)
            if "repositories" in baseline
            else baseline
        )
    current = scan_repo(
        a.repo,
        a.ref,
        a.id,
        a.owner,
        first_party_packages=(baseline or {}).get("first_party_provenance"),
    )
    if a.baseline:
        baseline = baseline or {}
        baseline = (
            next((r for r in baseline.get("repositories", []) if r["id"] == a.id), None)
            if "repositories" in baseline
            else baseline
        )
        result = compare(baseline or {}, current)
        code = result["exit_code"]
    else:
        result = current
        code = (
            3 if not current["source_listing_complete"] or current.get("critical_input_gaps") else 0
        )
    raw = json.dumps(result, indent=2) + "\n"
    if a.out:
        a.out.write_text(raw)
        a.out.chmod(0o600)
    else:
        print(raw, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
