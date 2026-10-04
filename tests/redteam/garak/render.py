"""Fill the `${NAME}` / `${NAME:-default}` placeholders of a garak config template from the environment.

    python tests/redteam/garak/render.py [config.yaml] [--out reports/redteam/garak/config.rendered.yaml]

Standard library only, so it runs in garak's own virtualenv as well as in the repository environment. Secrets are never
rendered: the templates contain none, and a placeholder whose name looks like a secret (KEY, TOKEN, SECRET, PASSWORD)
is refused, so an API key can not end up in a file by accident (export OPENAICOMPATIBLE_API_KEY instead).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = HERE / "config.yaml"
PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::-([^}]*))?\}")
SECRETISH = re.compile(r"KEY|TOKEN|SECRET|PASSWORD", re.IGNORECASE)


class RenderError(ValueError):
    pass


def placeholders(text: str) -> list[tuple[str, str | None]]:
    """(name, default) of every placeholder in `text`, in order of appearance (comments included)."""
    return [(m.group(1), m.group(2)) for m in PLACEHOLDER.finditer(text)]


def render(text: str, env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env

    def sub(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(2)
        if SECRETISH.search(name):
            raise RenderError(f"placeholder ${{{name}}} looks like a secret; export it for the tool instead")
        value = env.get(name)
        if value:
            return value.rstrip("/") if name.endswith("_URL") else value
        if default is not None:
            return default
        raise RenderError(f"environment variable {name} is required by the template and not set")

    return PLACEHOLDER.sub(sub, text)


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("template", nargs="?", type=Path, default=DEFAULT_TEMPLATE)
    ap.add_argument("--out", type=Path, help="write here instead of stdout")
    args = ap.parse_args(argv)
    try:
        rendered = render(args.template.read_text(encoding="utf-8"), env)
    except (RenderError, OSError) as exc:
        print(f"render: {exc}", file=sys.stderr)
        return 2
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
