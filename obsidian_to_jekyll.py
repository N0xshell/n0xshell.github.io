#!/usr/bin/env python3
"""
obsidian_to_jekyll.py
Converts an Obsidian .md note to a Jekyll/Chirpy post.
Handles both ![[image]] and ![alt](image) formats.

Usage:
  python3 obsidian_to_jekyll.py <file.md> --category <cat> --tags <tag1> <tag2>

Categories: Machines | Prolabs | Exam Review
"""

import re
import sys
import shutil
import argparse
from datetime import date
from pathlib import Path

POSTS_DIR  = Path("_posts")
ASSETS_DIR = Path("assets/img/posts")
CATEGORIES = ["Machines", "Prolabs", "Exam Review"]


def slugify(s):
    s = s.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    return s.strip('-')


def strip_frontmatter(content):
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            return parts[2].strip()
    return content.strip()


def find_image(filename, search_dirs):
    for d in search_dirs:
        candidate = d / filename
        if candidate.exists():
            return candidate
    return None


def convert(content, post_slug, search_dirs, img_dir):
    # Fix bare image references: !Pasted image X.png -> ![[Pasted image X.png]]
    content = re.sub(r'!Pasted image ([^\n]+\.png)', r'![[Pasted image \1]]', content)

    # %% Obsidian comments %%
    content = re.sub(r'%%.*?%%', '', content, flags=re.DOTALL)

    # > [!NOTE] callouts
    content = re.sub(
        r'^> \[!(\w+)\]\s*(.*?)$',
        lambda m: f"> **{m.group(1).capitalize()}:** {m.group(2).strip()}",
        content, flags=re.MULTILINE
    )

    # ![[image.png]] — handle BEFORE wikilinks so brackets aren't stripped first
    def handle_wiki_image(m):
        filename = m.group(1)
        src = find_image(filename, search_dirs)
        if src:
            shutil.copy2(str(src), str(img_dir / filename))
            print(f"[+] Copied: {filename}")
        else:
            print(f"[!] Not found: {filename} — add manually to {img_dir}/")
        return f"![{Path(filename).stem}](/assets/img/posts/{post_slug}/{filename})"

    content = re.sub(r'!\[\[([^\]]+)\]\]', handle_wiki_image, content)

    # [[wikilinks]] — runs AFTER images are already handled
    content = re.sub(
        r'\[\[([^\]|]+)(?:\|([^\]]+))?\]\]',
        lambda m: m.group(2) or m.group(1),
        content
    )

    # ![alt](image.png) — standard markdown images
    def handle_md_image(m):
        alt      = m.group(1)
        filename = m.group(2)
        if filename.startswith("http://") or filename.startswith("https://"):
            return m.group(0)
        src = find_image(filename, search_dirs)
        if src:
            shutil.copy2(str(src), str(img_dir / filename))
            print(f"[+] Copied: {filename}")
        else:
            print(f"[!] Not found: {filename} — add manually to {img_dir}/")
        return f"![{alt}](/assets/img/posts/{post_slug}/{filename})"

    content = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', handle_md_image, content)

    return content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input",                             help="Obsidian .md file")
    parser.add_argument("--category", "-c", required=True,  choices=CATEGORIES)
    parser.add_argument("--tags",     "-t", nargs="+",       default=["htb"])
    parser.add_argument("--date",     "-d", default=str(date.today()))
    args = parser.parse_args()

    src = Path(args.input).expanduser().resolve()
    if not src.exists():
        sys.exit(f"[-] Not found: {src}")

    search_dirs = [src.parent, src.parent.parent, src.parent.parent.parent]

    title     = src.stem
    slug      = slugify(title)
    post_name = f"{args.date}-{slug}"

    img_dir = ASSETS_DIR / post_name
    img_dir.mkdir(parents=True, exist_ok=True)

    body = convert(
        strip_frontmatter(src.read_text(encoding="utf-8")),
        post_name,
        search_dirs,
        img_dir
    )

    tags_yaml = "\n".join(f"  - {t.lower()}" for t in args.tags)
    frontmatter = f"""---
title: "{title}"
date: {args.date} 00:00:00 +0100
categories: [HackTheBox, {args.category}]
tags:
{tags_yaml}
---
"""

    POSTS_DIR.mkdir(exist_ok=True)
    out = POSTS_DIR / f"{post_name}.md"
    out.write_text(frontmatter + "\n" + body + "\n", encoding="utf-8")

    print(f"\n[+] Post:   {out}")
    print(f"[+] Images: {img_dir}/")
    print(f"\n    git add _posts/{post_name}.md assets/img/posts/{post_name}/")
    print(f"    git commit -m 'Add {title}'")
    print(f"    git push")


if __name__ == "__main__":
    main()
