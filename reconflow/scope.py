"""
reconflow.scope
-----------------
Parses a bug bounty program's scope and filters discovered subdomains
against it, so you don't accidentally report (or get flagged for testing)
something out of scope.

Supports two input formats:
  1. HackerOne-style JSON export: a list of objects with
     "asset_identifier", "asset_type", "eligible_for_bounty" /
     "eligible_for_submission" / "instruction" containing "out of scope"
  2. Plain text, one entry per line:
       example.com
       *.example.com              <- subdomains only, not the apex
       !excluded.example.com      <- leading "!" means explicitly out of scope
       # comments and blank lines ignored

Wildcard semantics: a leading "*." matches one or more labels, so
"*.example.com" covers a.example.com and a.b.example.com but NOT
example.com itself. Any other "*" or "?" stays within a single label,
so "dev-*.example.com" matches dev-a.example.com but not
dev-a.b.example.com. Out-of-scope wildcards are read broadly instead:
"!*.internal.example.com" also excludes internal.example.com, since
excluding too much is the safe failure mode.
"""

import ipaddress
import json
import re
from pathlib import Path


def _normalize(asset: str) -> str:
    """Normalize a scope pattern or target string."""
    asset = asset.strip().lower()
    if "://" in asset:
        asset = asset.split("://", 1)[-1]
    asset = asset.split("/", 1)[0]
    if ":" in asset and not asset.startswith("["):
        parts = asset.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            asset = parts[0]
    if asset.startswith("."):
        asset = asset[1:]
    return asset


def load_scope(path: str):
    """Returns {'in_scope': [...], 'out_of_scope': [...]} of patterns."""
    text = Path(path).read_text(encoding="utf-8")
    in_scope, out_of_scope = [], []

    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            items = data if isinstance(data, list) else data.get("scope", data.get("targets", []))
            for item in items:
                if not isinstance(item, dict):
                    continue
                asset = item.get("asset_identifier") or item.get("target") or item.get("identifier")
                if not asset:
                    continue
                asset_type = (item.get("asset_type") or "").upper()
                if asset_type and "URL" not in asset_type and "DOMAIN" not in asset_type \
                        and "WILDCARD" not in asset_type and "OTHER" not in asset_type \
                        and "IP" not in asset_type and "CIDR" not in asset_type:
                    continue  # skip mobile apps, source code repos, etc.

                instruction = (item.get("instruction") or "").lower()
                is_out_of_scope = (
                    "out of scope" in instruction
                    or item.get("eligible_for_submission") is False
                    or item.get("eligible_for_bounty") is False
                )

                eligible = item.get(
                    "eligible_for_submission",
                    item.get("eligible_for_bounty", not is_out_of_scope),
                )
                if is_out_of_scope:
                    eligible = False

                norm = _normalize(asset)
                if norm:
                    (in_scope if eligible else out_of_scope).append(norm)
            return {"in_scope": in_scope, "out_of_scope": out_of_scope}
        except json.JSONDecodeError:
            pass  # fall through to plain-text parsing

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            norm = _normalize(line[1:])
            if norm:
                out_of_scope.append(norm)
        else:
            norm = _normalize(line)
            if norm:
                in_scope.append(norm)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope}


def _wildcard_regex(pattern: str, include_apex: bool):
    """Translate a scope wildcard into a label-aware regex."""
    prefix = ""
    if pattern.startswith("*."):
        # One or more whole labels; zero or more if the apex should match too.
        prefix = r"(?:[^.]+\.)*" if include_apex else r"(?:[^.]+\.)+"
        pattern = pattern[2:]
    body = "".join(
        "[^.]*" if ch == "*" else "[^.]" if ch == "?" else re.escape(ch)
        for ch in pattern
    )
    return re.compile(prefix + body)


def _matches_pattern(host: str, pattern: str, include_apex: bool = False) -> bool:
    host = host.lower()
    pattern = pattern.lower()

    # 1. IP / CIDR matching
    try:
        host_ip = ipaddress.ip_address(host)
        pattern_net = ipaddress.ip_network(pattern, strict=False)
        return host_ip in pattern_net
    except ValueError:
        pass

    # 2. Wildcard matching (e.g. *.example.com, dev-*.example.com)
    if "*" in pattern or "?" in pattern:
        return _wildcard_regex(pattern, include_apex).fullmatch(host) is not None

    # 3. Exact hostname match
    if host == pattern:
        return True

    # 4. Subdomain match (e.g. api.example.com matches example.com)
    return host.endswith(f".{pattern}")


def _matches_any(host: str, patterns, include_apex: bool = False) -> bool:
    for pattern in patterns:
        if _matches_pattern(host, pattern, include_apex):
            return True
    return False


def filter_in_scope(subdomains, scope: dict, output_dir: Path = None):
    """Returns (in_scope_list, out_of_scope_list). Out-of-scope rules win ties."""
    in_scope_patterns = scope.get("in_scope", [])
    out_of_scope_patterns = scope.get("out_of_scope", [])

    kept, dropped = [], []
    for host in subdomains:
        clean = host.split("://", 1)[-1].split("/", 1)[0]
        if ":" in clean and not clean.startswith("["):
            parts = clean.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                clean = parts[0]
        clean = clean.lower().strip()

        if _matches_any(clean, out_of_scope_patterns, include_apex=True):
            dropped.append(host)
        elif not in_scope_patterns or _matches_any(clean, in_scope_patterns):
            kept.append(host)
        else:
            dropped.append(host)

    if output_dir:
        (output_dir / "scope_filtered_out.txt").write_text("\n".join(dropped), encoding="utf-8")

    print(f"[+] Scope filter: {len(kept)} in-scope, {len(dropped)} excluded")
    return kept, dropped
