#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Check complete language pairs, fenced blocks and local product-doc links."""
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit
from wsea_documents import DOCUMENTS, NAVIGATION, PAIRS, ROOT


def headings(text):
    return re.findall(r'^#{1,6} (.+)$', re.sub(r'```.*?```', '', text, flags=re.S), re.M)


def anchors(text):
    seen = {}
    result = set()
    for title in headings(text):
        title = title.replace('`', '').replace('*', '').lower()
        slug = ''.join(c for c in title if c in '-_ ' or unicodedata.category(c)[0] in 'LN').replace(' ', '-')
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        result.add(slug + (f'-{count}' if count else ''))
    return result


def main():
    errors = []
    texts = {}
    for name in DOCUMENTS:
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            errors.append(f'{name}: required ordinary documentation file missing')
            continue
        text = texts[name] = path.read_text(encoding='utf-8')
        if len(re.findall(r'^```', text, re.M)) % 2:
            errors.append(f'{name}: unclosed fenced block')
        if name in NAVIGATION and len(text.splitlines()) > 40:
            errors.append(f'{name}: put substantive content in both locale files')
        if '/tmp/' in text:
            errors.append(f'{name}: use project .tmp for generated work')
        for link in re.findall(r'(?<!!)\[[^\]]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)', text):
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            dest = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not dest.is_relative_to(ROOT) or not dest.is_file():
                errors.append(f'{name}: broken local link {link}')
            elif url.fragment and dest.suffix == '.md' and unquote(url.fragment) not in anchors(dest.read_text()):
                errors.append(f'{name}: missing heading {link}')
    for base in PAIRS:
        names = [f'{base}.{locale}.md' for locale in ('en_US', 'zh_CN')]
        if not all(name in texts for name in names):
            continue
        en, zh = (texts[name] for name in names)
        if len(headings(en)) != len(headings(zh)):
            errors.append(f'{base}: language versions have different section counts')
        if len(re.findall(r'^```', en, re.M)) != len(re.findall(r'^```', zh, re.M)):
            errors.append(f'{base}: language versions have different example counts')
        if len(en) < 1500 or len(zh) < 1000:
            errors.append(f'{base}: a language version appears incomplete')
    if errors:
        sys.exit('\n'.join(errors))
    print(f'PASS: {len(PAIRS)} complete locale pairs; {len(DOCUMENTS)} product documents and local links')


if __name__ == '__main__':
    main()
