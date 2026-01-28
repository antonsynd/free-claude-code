import pytest
from providers.utils.think_parser import ThinkTagParser, ContentType
from providers.utils.heuristic_tool_parser import HeuristicToolParser


def test_think_tag_parser_basic():
    parser = ThinkTagParser()
    chunks = list(parser.feed("Hello <think>reasoning</think> world"))

    assert len(chunks) == 3
    assert chunks[0].type == ContentType.TEXT
    assert chunks[0].content == "Hello "
    assert chunks[1].type == ContentType.THINKING
    assert chunks[1].content == "reasoning"
    assert chunks[2].type == ContentType.TEXT
    assert chunks[2].content == " world"


def test_think_tag_parser_streaming():
    parser = ThinkTagParser()

    # Partial tag
    chunks = list(parser.feed("Hello <thi"))
    assert len(chunks) == 1
    assert chunks[0].content == "Hello "

    # Complete tag
    chunks = list(parser.feed("nk>reasoning</think>"))
    assert len(chunks) == 1
    assert chunks[0].type == ContentType.THINKING
    assert chunks[0].content == "reasoning"


def test_heuristic_tool_parser_basic():
    parser = HeuristicToolParser()
    text = "Let's call a tool. ● <function=Grep><parameter=pattern>hello</parameter><parameter=path>.</parameter>"
    filtered, tools_initial = parser.feed(text)
    tools_final = parser.flush()
    tools = tools_initial + tools_final

    assert "Let's call a tool." in filtered
    assert len(tools) == 1
    assert tools[0]["name"] == "Grep"
    assert tools[0]["input"] == {"pattern": "hello", "path": "."}


def test_heuristic_tool_parser_streaming():
    parser = HeuristicToolParser()

    # Feed part 1
    filtered1, tools1 = parser.feed("● <function=Write>")
    assert tools1 == []

    # Feed part 2
    filtered2, tools2 = parser.feed("<parameter=path>test.txt</parameter>")
    assert tools2 == []

    # Feed part 3 (triggering flush or completion)
    filtered3, tools3 = parser.feed("\nDone.")
    assert len(tools3) == 1
    assert tools3[0]["name"] == "Write"
    assert tools3[0]["input"] == {"path": "test.txt"}
    assert "Done." in filtered3


def test_heuristic_tool_parser_flush():
    parser = HeuristicToolParser()
    parser.feed("● <function=Bash><parameter=command>ls -la")
    tools = parser.flush()

    assert len(tools) == 1
    assert tools[0]["name"] == "Bash"
    assert tools[0]["input"] == {"command": "ls -la"}


def test_interleaved_thinking_and_tools():
    parser_think = ThinkTagParser()
    parser_tool = HeuristicToolParser()

    text = "<think>I need to search for a file.</think> ● <function=Grep><parameter=pattern>test</parameter>"

    # 1. Parse thinking
    chunks = list(parser_think.feed(text))
    thinking = [c for c in chunks if c.type == ContentType.THINKING]
    text_remaining = "".join([c.content for c in chunks if c.type == ContentType.TEXT])

    assert len(thinking) == 1
    assert thinking[0].content == "I need to search for a file."

    # 2. Parse tool from remaining text
    filtered, tools = parser_tool.feed(text_remaining)
    tools += parser_tool.flush()

    assert len(tools) == 1
    assert tools[0]["name"] == "Grep"
    assert tools[0]["input"] == {"pattern": "test"}


def test_partial_interleaved_streaming():
    parser_think = ThinkTagParser()
    parser_tool = HeuristicToolParser()

    # Chunk 1: Partial thinking (it emits since it's definitely not the start of <think>)
    chunks1 = list(parser_think.feed("<think>Part 1"))
    assert len(chunks1) == 1
    assert chunks1[0].type == ContentType.THINKING
    assert chunks1[0].content == "Part 1"

    # Chunk 2: Thinking ends, tool starts
    chunks2 = list(parser_think.feed(" ends</think> ● <func"))
    assert len(chunks2) == 2
    assert chunks2[0].type == ContentType.THINKING
    assert chunks2[0].content == " ends"

    text_rem = chunks2[1].content
    filtered, tools = parser_tool.feed(text_rem)
    assert tools == []

    # Chunk 3: Tool ends
    chunks3 = list(parser_think.feed("tion=Read><parameter=path>test.py</parameter>"))
    text_rem3 = "".join([c.content for c in chunks3])
    filtered3, tools3 = parser_tool.feed(text_rem3)
    tools3 += parser_tool.flush()

    assert len(tools3) == 1
    assert tools3[0]["name"] == "Read"
    assert tools3[0]["input"] == {"path": "test.py"}
