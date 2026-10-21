"""Bounded HTML messages with balanced formatting and intact entities."""
from __future__ import annotations

from html.parser import HTMLParser


class _Tokens(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.tokens: list[tuple[str, str, str]] = []
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tokens.append(('start', self.get_starttag_text(), tag))

    def handle_endtag(self, tag):
        self.tokens.append(('end', f'</{tag}>', tag))

    def handle_data(self, data):
        self.tokens.extend(('text', char, '') for char in data)

    def handle_entityref(self, name):
        self.tokens.append(('text', f'&{name};', ''))

    def handle_charref(self, name):
        self.tokens.append(('text', f'&#{name};', ''))


def _size(text: str) -> int:
    return len(text.encode('utf-16-le')) // 2


def split_html(text: str, limit: int = 3800) -> list[str]:
    """Split valid Telegram HTML, closing/reopening tags without changing visible text.

    Count encoded markup conservatively too; a Unicode character or entity remains
    indivisible. Raise ValueError if the limit cannot hold a formatting wrapper.
    """
    if limit < 1:
        raise ValueError('HTML message limit must be positive')
    if not text:
        return []
    chunks: list[str] = []
    stack: list[tuple[str, str]] = []
    parts: list[str] = []
    size = 0
    has_text = False
    for kind, token, tag in _Tokens(text).tokens:
        next_stack = stack.copy()
        if kind == 'start':
            next_stack.append((token, tag))
        elif kind == 'end':
            if not next_stack or next_stack[-1][1] != tag:
                raise ValueError('Unbalanced HTML message')
            next_stack.pop()
        closing = ''.join(f'</{name}>' for _, name in reversed(next_stack))
        if size + _size(token) + _size(closing) > limit:
            if not has_text:
                raise ValueError('HTML formatting exceeds message limit')
            chunks.append(''.join(parts) + ''.join(f'</{name}>' for _, name in reversed(stack)))
            parts = [start for start, _ in stack]
            size = sum(_size(part) for part in parts)
            has_text = False
            if size + _size(token) + _size(closing) > limit:
                raise ValueError('HTML formatting exceeds message limit')
        parts.append(token)
        size += _size(token)
        has_text = has_text or kind == 'text'
        stack = next_stack
    if stack:
        raise ValueError('Unbalanced HTML message')
    if parts and has_text:
        chunks.append(''.join(parts))
    return chunks
