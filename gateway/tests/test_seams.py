from __future__ import annotations

from acl.contracts.decision import Finding
from acl.contracts.inspection import ChatMessage, ChatPayload, FunctionCall, ToolCall, ToolCallPayload
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


def _chat_with_tools() -> ChatPayload:
    return ChatPayload(
        messages=[
            ChatMessage(role="user", name="jan", content="hi"),
            ChatMessage(
                role="assistant",
                tool_calls=[ToolCall(id="c1", function=FunctionCall(name="lookup", arguments="{}"))],
            ),
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "find a customer",
                    "parameters": {
                        "type": "object",
                        "properties": {"q": {"type": "string", "description": "query", "enum": ["a", "b"]}},
                        "required": ["q"],
                    },
                },
            }
        ],
        params={"stop": ["END"], "temperature": 0.2, "stream": False},
    )


def test_iter_texts_covers_tools_names_and_params() -> None:
    """CP1: every free-text field forwarded upstream is inspected (tools, message names, params)."""
    assert iter_texts(_chat_with_tools()) == [
        ("messages[0].content", "hi"),
        ("messages[0].name", "jan"),
        ("messages[1].tool_calls[0].function.name", "lookup"),
        ("messages[1].tool_calls[0].function.arguments", "{}"),
        ("tools[0].type", "function"),
        ("tools[0].function.name", "lookup"),
        ("tools[0].function.description", "find a customer"),
        ("tools[0].function.parameters.type", "object"),
        ("tools[0].function.parameters.properties.q.type", "string"),
        ("tools[0].function.parameters.properties.q.description", "query"),
        ("tools[0].function.parameters.properties.q.enum[0]", "a"),
        ("tools[0].function.parameters.properties.q.enum[1]", "b"),
        ("tools[0].function.parameters.required[0]", "q"),
        ("params.stop[0]", "END"),
    ]


def test_apply_replacements_addresses_the_new_paths() -> None:
    enum1 = "tools[0].function.parameters.properties.q.enum[1]"
    findings = [
        Finding(entity_type="X", field="tools[0].function.description", start=7, end=15, replacement="<X_1>"),
        Finding(entity_type="X", field=enum1, start=0, end=1, replacement="<X_2>"),
        Finding(entity_type="PERSON", field="messages[0].name", start=0, end=3, replacement="<PERSON_1>"),
        Finding(entity_type="X", field="params.stop[0]", start=0, end=3, replacement="<X_3>"),
    ]
    out, skipped = apply_replacements(_chat_with_tools(), findings)
    assert not skipped
    assert isinstance(out, ChatPayload) and out.tools
    assert out.tools[0]["function"]["description"] == "find a <X_1>"
    assert out.tools[0]["function"]["parameters"]["properties"]["q"]["enum"] == ["a", "<X_2>"]
    assert out.messages[0].name == "<PERSON_1>"
    assert out.params["stop"] == ["<X_3>"]


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
