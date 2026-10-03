from __future__ import annotations

from acl.contracts.decision import Finding
from acl.contracts.inspection import ChatMessage, ChatPayload, ToolCallPayload
from acl.engine.text import apply_replacements, iter_texts, parse_path


def test_iter_texts_paths() -> None:
    p = ChatPayload(
        messages=[
            ChatMessage(role="user", content=[{"type": "text", "text": "a"}]),
            ChatMessage(role="user", content="b"),
        ]
    )
    assert iter_texts(p) == [("messages[0].content[0].text", "a"), ("messages[1].content", "b")]
    t = ToolCallPayload(tool="x.y", arguments={"to": ["a@b"], "body": {"text": "hi"}, "n": 1})
    assert iter_texts(t) == [("arguments.to[0]", "a@b"), ("arguments.body.text", "hi")]
    assert parse_path("messages[2].content[0].text") == ["messages", 2, "content", 0, "text"]


def test_apply_replacements_and_overlap() -> None:
    p = ChatPayload(messages=[ChatMessage(role="user", content="PESEL 44051401359 ok")])
    f1 = Finding(entity_type="PESEL", field="messages[0].content", start=6, end=17, replacement="<PESEL_1>")
    f2 = Finding(entity_type="X", field="messages[0].content", start=8, end=12, replacement="<X>")
    out, skipped = apply_replacements(p, [f2, f1])
    assert out.messages[0].content == "PESEL <PESEL_1> ok"
    assert skipped == [f2]
    assert p.messages[0].content == "PESEL 44051401359 ok"  # original untouched


async def test_create_all_on_sqlite() -> None:
    from acl.db import create_all, make_engine

    eng = make_engine("sqlite+aiosqlite:///:memory:")
    await create_all(eng)
    await eng.dispose()
