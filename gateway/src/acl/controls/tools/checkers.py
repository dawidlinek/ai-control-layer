"""Argument checkers for SEC-TOOL-01: URL, recipient, SQL and pinned-schema validation (pure functions).

Every function returns a list of `Violation`s (empty = fine). A violation carries a stable code and a value-free
reason; the offending raw value travels separately in `value` so that the caller can hash it (rule 2: no raw
values in verdicts, audit records or logs).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from acl.controls.egress.urls import host_allowed


@dataclass(frozen=True)
class Violation:
    code: str
    reason: str
    field: str = ""
    value: str | None = None


# ---------------------------------------------------------------- URL

_METADATA_HOSTS = frozenset(
    {"169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200", "fd00:ec2::254", "instance-data"}
)


def _internal_host(host: str) -> bool:
    """Loopback / private IPs, `localhost`, `*.local` / `*.internal`, single-label (compose service) names."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "." not in host or host == "localhost" or host.endswith((".local", ".internal", ".localdomain", ".lan"))
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


def check_url(
    raw: str, *, allow_domains: Sequence[str] | None, field: str = "", block_private: bool = False
) -> list[Violation]:
    """Scheme http/https only, no credentials in the URL, no cloud-metadata hosts, optional domain allowlist.

    `block_private` (for tools executed server-side, e.g. MCP fetchers inside the compose network) also rejects
    internal addresses and hostnames (SSRF) unless the host is explicitly on the allowlist."""
    out: list[Violation] = []
    url = raw.strip()
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # raises ValueError on a bad port
    except ValueError:
        return [Violation("URL_MALFORMED", "URL could not be parsed", field, raw)]
    if parts.scheme.lower() not in ("http", "https"):
        return [Violation("URL_SCHEME", "only http/https URLs are allowed", field, raw)]
    if "@" in parts.netloc or parts.username or parts.password:
        out.append(Violation("URL_CREDENTIALS", "URL carries credentials (userinfo)", field, raw))
    if not host:
        out.append(Violation("URL_HOST", "URL has no host", field, raw))
        return out
    if host in _METADATA_HOSTS or _link_local(host):
        out.append(Violation("URL_METADATA", "cloud metadata / link-local address", field, raw))
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", host) or (
        re.fullmatch(r"(?:\d+|0x[0-9a-f]+)(?:\.(?:\d+|0x[0-9a-f]+)){1,3}", host) and not _plain_ipv4(host)
    ):
        out.append(Violation("URL_HOST_OBFUSCATED", "numeric host in a non-standard encoding", field, raw))
    listed = allow_domains is not None and host_allowed(host, list(allow_domains))
    if block_private and not listed and _internal_host(host):
        out.append(Violation("URL_INTERNAL", "internal address / host name (SSRF)", field, raw))
    if allow_domains is not None and not listed:
        out.append(Violation("URL_DOMAIN", "domain is not on the allowlist", field, raw))
    return out


def _plain_ipv4(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


def _link_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_link_local


# ---------------------------------------------------------------- recipients

_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# Strict address grammar: dot-atom local part (no quoted local parts, no comments), a domain name (no IP literal, no
# bare host), IDN domains converted to punycode before any comparison.
_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LOCAL = re.compile(rf"^{_ATOM}(?:\.{_ATOM})*$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NAMED = re.compile(r'^(?:"[^"\\]*"|[^<>"@,;:\\]*)\s*<([^<>\s]+)>$')
MAX_RECIPIENTS = 200


def extract_recipients(values: Iterable[str]) -> list[str]:
    """Loose extraction (logging / intent only). Authorisation uses `parse_recipients`."""
    out: list[str] = []
    for v in values:
        for m in _EMAIL.finditer(v):
            addr = m.group(0).lower()
            if addr not in out:
                out.append(addr)
    return out


def normalise_domain(domain: str) -> str | None:
    """IDNA (punycode), lower-case, every label a valid host label, at least two labels, non-numeric TLD."""
    d = domain.strip().rstrip(".")
    if not d or d.startswith("[") or any(c.isspace() for c in d):
        return None
    try:
        d = d.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels) or labels[-1].isdigit():
        return None  # bare host (`localhost`), IPv4 literal (`10.0.0.1`), empty label
    return d


def normalise_address(addr: str) -> str | None:
    local, at, domain = addr.strip().rpartition("@")
    if not at or not _LOCAL.match(local) or len(local) > 64:
        return None
    dom = normalise_domain(domain)
    return f"{local.lower()}@{dom}" if dom else None


def _split_list(value: str) -> list[str] | None:
    """Split a recipient list on `,` / `;` outside quotes and angle brackets (None: unbalanced quoting)."""
    parts: list[str] = []
    buf: list[str] = []
    quote = angle = False
    for ch in value:
        if ch == '"' and not angle:
            quote = not quote
        elif ch == "<" and not quote:
            if angle:
                return None
            angle = True
        elif ch == ">" and not quote:
            if not angle:
                return None
            angle = False
        elif ch in ",;" and not quote and not angle:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if quote or angle:
        return None
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def parse_recipients(value: str) -> tuple[list[str], list[str]]:
    """(valid normalised addresses, rejected parts) of one recipient field value. Each `,`/`;` separated part must be
    exactly one address (`a@x.tld` or `Name <a@x.tld>`), confirmed by `email.utils.getaddresses`."""
    from email.utils import getaddresses

    parts = _split_list(value)
    if parts is None:
        return [], [value]
    good: list[str] = []
    bad: list[str] = []
    for part in parts[:MAX_RECIPIENTS]:
        m = _NAMED.match(part)
        addr = m.group(1) if m else part
        norm = normalise_address(addr) if (m or not any(c.isspace() for c in part)) else None
        parsed = [a for _, a in getaddresses([part]) if a]
        if norm is None or len(parsed) != 1 or normalise_address(parsed[0]) != norm:
            bad.append(part)
        elif norm not in good:
            good.append(norm)
    bad.extend(parts[MAX_RECIPIENTS:])
    return good, bad


def recipient_allowed(addr: str, allow: Sequence[str]) -> bool:
    """`@corp.example` matches exactly that domain; `corp.example` also its subdomains; full addresses match exactly.
    Domains on both sides are compared in their IDNA (punycode) form."""
    norm = normalise_address(addr)
    if norm is None:
        return False
    domain = norm.rsplit("@", 1)[-1]
    for entry in allow:
        e = entry.strip().lower()
        if not e:
            continue
        if "@" in e and not e.startswith("@"):
            if norm == normalise_address(e):
                return True
            continue
        bare = e.lstrip("@.")
        dom = normalise_domain(bare)
        if dom is None:
            continue
        if e.startswith("@"):
            if domain == dom:
                return True
        elif e.startswith("."):
            if domain.endswith("." + dom):
                return True
        elif domain == dom or domain.endswith("." + dom):
            return True
    return False


def check_recipients(
    values: Sequence[str], addresses: Sequence[str], *, allow: Sequence[str], require_allowlist: bool, field: str = ""
) -> list[Violation]:
    """Every part of every recipient value must parse as one plain address AND be on the allowlist (when one is set).
    `values` are raw argument strings (lists already flattened); `addresses` are extra addresses found elsewhere."""
    out: list[Violation] = []
    valid: list[str] = []
    for v in [*values, *addresses]:
        if not v.strip():
            continue
        good, bad = parse_recipients(v)
        for b in bad:
            out.append(Violation("RECIPIENT_MALFORMED", "recipient is not a single valid e-mail address", field, b))
        if not good and not bad:
            out.append(Violation("RECIPIENT_MALFORMED", "recipient field contains no parseable address", field, v))
        valid.extend(a for a in good if a not in valid)
    if require_allowlist and not allow:
        out.append(
            Violation("RECIPIENT_NO_ALLOWLIST", "no recipient allowlist is configured for this principal", field)
        )
        return out
    if allow:
        for addr in valid:
            if not recipient_allowed(addr, allow):
                out.append(Violation("RECIPIENT", "recipient is not on the allowlist", field, addr))
    return out


# ---------------------------------------------------------------- pinned argument schema


def check_arguments(arguments: Mapping[str, Any], schema: Mapping[str, Any]) -> list[Violation]:
    """Unknown fields are ALWAYS rejected (parasitic parameters), even if the schema allows additionalProperties;
    the rest of the schema (types, required, enums, …) is enforced with jsonschema."""
    out: list[Violation] = []
    _unknown(arguments, schema, "arguments", out)
    try:
        validator = Draft202012Validator(dict(schema))
        Draft202012Validator.check_schema(dict(schema))
    except SchemaError:
        return [*out, Violation("SCHEMA_INVALID", "the pinned argument schema is invalid (failing closed)")]
    try:
        errors = sorted(validator.iter_errors(dict(arguments)), key=lambda e: list(map(str, e.absolute_path)))
    except Exception:  # e.g. unresolvable $ref: never let a validator bug pass a call through
        return [*out, Violation("SCHEMA_INVALID", "the pinned argument schema could not be evaluated (failing closed)")]
    for err in errors[:5]:
        if err.validator == "additionalProperties":
            continue  # reported as PARASITIC above
        path = ".".join(["arguments", *[str(p) for p in err.absolute_path]])
        out.append(Violation("SCHEMA", f"argument violates the pinned schema ({err.validator})", path))
    return out


def _unknown(value: Any, schema: Mapping[str, Any], path: str, out: list[Violation]) -> None:
    if isinstance(value, Mapping):
        props = schema.get("properties")
        props = props if isinstance(props, Mapping) else {}
        if schema.get("type") in (None, "object") and (props or path == "arguments"):
            for key in value:
                if key not in props:
                    out.append(Violation("PARASITIC", "argument field is not in the pinned schema", path, str(key)))
        for key, sub in value.items():
            sub_schema = props.get(key)
            if isinstance(sub_schema, Mapping):
                _unknown(sub, sub_schema, f"{path}.{key}", out)
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, Mapping):
            for i, item in enumerate(value[:200]):
                _unknown(item, items, f"{path}[{i}]", out)


# ---------------------------------------------------------------- SQL

_WRITE_NODES = (
    "Insert",
    "Update",
    "Delete",
    "Drop",
    "Create",
    "Alter",
    "AlterTable",
    "Command",
    "Merge",
    "TruncateTable",
    "Into",
    "Lock",
    "Copy",
    "Grant",
    "Revoke",
    "Set",
    "Use",
    "Transaction",
    "Commit",
    "Rollback",
    "Pragma",
    "Analyze",
    "Describe",
    "LoadData",
    "Kill",
)
_DANGEROUS_FUNCS = frozenset(
    {
        "pg_sleep",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_stat_file",
        "lo_import",
        "lo_export",
        "load_file",
        "dblink",
        "dblink_exec",
        "xp_cmdshell",
        "sleep",
        "benchmark",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "set_config",
        "nextval",
        "setval",
        "copy",
        "query_to_xml",
        "pg_reload_conf",
        "current_setting",
    }
)


@dataclass(frozen=True)
class SqlScope:
    """Allowed columns per table (`None` = any column of that table); `tables is None` = no table restriction."""

    tables: Mapping[str, frozenset[str] | None] | None = None
    deny_columns: frozenset[str] = frozenset()


def _all(cols: Iterable[str]) -> frozenset[str] | None:
    s = frozenset(c.lower() for c in cols)
    return None if "*" in s else s


def scope_from_params(params: Mapping[str, Any], groups: Sequence[str]) -> SqlScope:
    """Checker params → scope. `groups:` (union over the principal's groups; no match = nothing) beats `allow:`."""
    deny = frozenset(str(c).lower() for c in params.get("deny_columns", []) or [])
    by_group = params.get("groups")
    if isinstance(by_group, Mapping):
        merged: dict[str, frozenset[str] | None] = {}
        for g in groups:
            entry = by_group.get(g) or {}
            # canonical shape (policy/tools.yaml): {tables: {table: [cols]}, pseudonymise_columns: [...]};
            # the flat {table: [cols]} shape is accepted too
            tables = entry.get("tables") if isinstance(entry.get("tables"), Mapping) else entry
            for table, cols in tables.items():
                if table == "pseudonymise_columns" or not isinstance(cols, list | str):
                    continue
                new = _all(cols if isinstance(cols, list) else [cols])
                old = merged.get(table.lower(), frozenset())
                merged[table.lower()] = None if (new is None or old is None) else (old | new)
        return SqlScope(merged, deny)
    allow = params.get("allow")
    if isinstance(allow, Mapping):
        return SqlScope({t.lower(): _all(c if isinstance(c, list) else [c]) for t, c in allow.items()}, deny)
    return SqlScope(None, deny)


def check_sql(
    sql: str, scope: SqlScope, *, read_only: bool = True, dialect: str | None = "postgres"
) -> list[Violation]:
    """One SELECT statement, tables/columns inside the scope, `SELECT *` must not expand to forbidden columns."""
    import sqlglot
    from sqlglot import exp
    from sqlglot.errors import SqlglotError

    try:
        statements = [s for s in sqlglot.parse(sql, read=dialect) if s is not None]
    except (SqlglotError, RecursionError):
        return [Violation("SQL_PARSE", "SQL could not be parsed (failing closed)", value=sql)]
    if len(statements) != 1:
        code = "SQL_STACKED" if len(statements) > 1 else "SQL_EMPTY"
        return [Violation(code, "exactly one SQL statement is allowed (stacked statements rejected)", value=sql)]
    tree = statements[0]
    out: list[Violation] = []

    setop = getattr(exp, "SetOperation", exp.Union)
    if read_only:
        root = tree.this if isinstance(tree, exp.Subquery) else tree
        if not isinstance(root, (exp.Select, setop)):
            out.append(Violation("SQL_NOT_SELECT", "only SELECT statements are allowed", value=sql))
        bad = tuple(getattr(exp, n) for n in _WRITE_NODES if hasattr(exp, n))
        if any(True for _ in tree.find_all(*bad)) or isinstance(tree, bad):
            out.append(
                Violation("SQL_NOT_SELECT", "statement writes, locks or changes state (read-only engine)", value=sql)
            )
    for fn in tree.find_all(exp.Func):
        name = (fn.name if isinstance(fn, exp.Anonymous) else fn.sql_name()).lower()
        if name in _DANGEROUS_FUNCS or name.startswith(("pg_read", "pg_ls", "lo_")):
            out.append(Violation("SQL_FUNCTION", "function with side effects or file access is not allowed", value=sql))
            break
    if out and any(v.code == "SQL_NOT_SELECT" for v in out):
        return out

    ctes = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    derived = {s.alias.lower() for s in tree.find_all(exp.Subquery) if s.alias} | ctes

    def is_base(t: exp.Table) -> bool:
        name = t.name.lower()
        return bool(name) and not (name in ctes and not t.args.get("db"))

    # qualifier (alias or table name) → every base table it may denote: an alias that shadows a table name, or a name
    # used twice, maps to all candidates and a column must be allowed in each of them
    base: dict[str, set[str]] = {}
    for t in tree.find_all(exp.Table):
        if not is_base(t):
            continue
        name = t.name.lower()
        base.setdefault((t.alias or t.name).lower(), set()).add(name)
        base.setdefault(name, set()).add(name)
    tables = set().union(*base.values()) if base else set()

    if scope.tables is not None:
        for name in sorted(tables):
            if name not in scope.tables:
                out.append(Violation("SQL_TABLE", "table is not allowed for this principal", value=name))
        if out:
            return out

    def allowed_cols(table: str) -> frozenset[str] | None:
        return scope.tables[table] if scope.tables is not None else None

    def column_allowed(table: str, column: str) -> bool:
        cols = allowed_cols(table)
        return cols is None or column in cols

    def local_tables(select: exp.Expression) -> set[str]:
        """Base tables in the FROM / JOIN list of exactly this SELECT."""
        return {
            t.name.lower() for t in select.find_all(exp.Table) if is_base(t) and t.find_ancestor(exp.Select) is select
        }

    def candidate_tables(col: exp.Column) -> set[str]:
        """Every base table an unqualified column may resolve to: the tables of its own SELECT plus, for a correlated
        (expression / LATERAL) subquery, the tables of every enclosing SELECT it can see."""
        out_tables: set[str] = set()
        select = col.find_ancestor(exp.Select)
        while select is not None:
            out_tables |= local_tables(select)
            node, source, lateral = select.parent, False, False
            while node is not None and not isinstance(node, exp.Select):
                if isinstance(node, exp.Lateral):
                    lateral = True
                elif isinstance(node, (exp.From, exp.Join, exp.CTE, exp.With)):
                    source = True  # a derived table / CTE body cannot see the outer FROM list (unless LATERAL)
                node = node.parent
            if node is None or (source and not lateral):
                break
            select = node
        return out_tables

    # SELECT * / t.* : must not expand to forbidden columns
    for star in tree.find_all(exp.Star):
        if isinstance(star.parent, exp.Count):
            continue
        qual = star.parent.table.lower() if isinstance(star.parent, exp.Column) and star.parent.table else ""
        select = star.find_ancestor(exp.Select)
        if qual:
            targets = set(base.get(qual, set()))
        elif select is not None:
            targets = local_tables(select)
        else:
            targets = set(tables)
        for table in sorted(targets):
            cols = allowed_cols(table)
            if (scope.tables is not None and cols is not None) or scope.deny_columns:
                out.append(
                    Violation("SQL_STAR", "SELECT * would expand to columns the principal may not read", value=table)
                )

    for col in tree.find_all(exp.Column):
        if isinstance(col.this, exp.Star):
            continue
        name = col.name.lower()
        qual = col.table.lower() if col.table else ""
        if name in scope.deny_columns:
            out.append(Violation("SQL_COLUMN", "column is not allowed for this principal", value=name))
            continue
        if scope.tables is None:
            continue
        if qual:
            if qual in base:
                if not all(column_allowed(t, name) for t in base[qual]):
                    out.append(Violation("SQL_COLUMN", "column is not allowed for this principal", value=name))
            elif qual not in derived:
                out.append(Violation("SQL_TABLE", "column references an unknown table", value=qual))
            continue
        # Unqualified: the column may belong to ANY table in scope, so it must be allowed in EVERY one of them
        # (`SELECT email FROM clients JOIN loans` must not pass because `loans` is `*`). With no base table in scope
        # it can only come from a derived table / CTE, whose own columns are checked where they are defined.
        if all(column_allowed(t, name) for t in candidate_tables(col)):
            continue
        select = col.find_ancestor(exp.Select)
        in_order = col.find_ancestor(exp.Order, exp.Group, exp.Having) is not None
        own_aliases = (
            {e.alias.lower() for e in select.expressions if isinstance(e, exp.Alias) and e.alias}
            if select is not None
            else set()
        )
        if in_order and name in own_aliases:
            continue  # `ORDER BY total` names the SELECT's own output column
        out.append(Violation("SQL_COLUMN", "column is not allowed for this principal", value=name))
    return out
