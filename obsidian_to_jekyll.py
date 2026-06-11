#!/usr/bin/env python3
"""
obsidian_to_jekyll.py - One Post Per Sub-Folder
"""

import re
import argparse
from datetime import date
from pathlib import Path

POSTS_DIR = Path("_posts")
TAGS_DIR = Path("tags")
CATEGORIES_DIR = Path("_categories")


def slugify(s):
    s = s.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    return s.strip('-')


def ensure_tag_page(tag):
    TAGS_DIR.mkdir(exist_ok=True)
    (TAGS_DIR / f"{tag}.md").write_text(
        f"---\nlayout: tag\ntitle: {tag}\ntag: {tag}\npermalink: /tags/{tag}/\n---\n", encoding="utf-8")


def ensure_category_page(category):
    CATEGORIES_DIR.mkdir(exist_ok=True)
    slug = slugify(category)
    (CATEGORIES_DIR / f"{slug}.md").write_text(
        f"---\nlayout: category\ntitle: {category}\ncategory: {category}\npermalink: /categories/{slug}/\n---\n", encoding="utf-8")


def folder_to_markdown(folder: Path):
    files = sorted([f for f in folder.iterdir() if f.is_file() and not f.name.startswith('.')])
    content = f"# {folder.name}\n\n**Folder:** `{folder.name}`\n\n"

    for f in files:
        if f.suffix.lower() not in {'.c', '.h', '.cpp', '.hpp', '.py'}:
            continue
        lang = {'.c': 'c', '.h': 'c', '.cpp': 'cpp', '.hpp': 'cpp', '.py': 'python'}.get(f.suffix.lower(), 'text')
        code = f.read_text(encoding="utf-8", errors="replace")
        content += f"## {f.name}\n\n```{lang}\n{code}\n```\n\n---\n\n"
    
    return content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Folder path (will process all subfolders)")
    parser.add_argument("-c", "--category", default="Development", choices=["Development", "Reversing"])
    parser.add_argument("-d", "--date", default=str(date.today()))
    parser.add_argument("--batch", action="store_true")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print("[-] Not a valid folder")
        return

    post_date = args.date.replace('-', '')
    processed = 0

    # Process each sub-folder
    for subfolder in sorted(root.iterdir()):
        if not subfolder.is_dir() or subfolder.name.startswith('.'):
            continue

        print(f"   → Processing subfolder: {subfolder.name}")

        if not args.batch:
            if input("   Create post? [Y/n] > ").strip().lower() not in ('', 'y', 'yes'):
                continue

        body = folder_to_markdown(subfolder)
        post_name = f"{post_date}-{slugify(subfolder.name)}"

        # Remove old version if exists
        old = POSTS_DIR / f"{post_name}.md"
        if old.exists():
            old.unlink()

        tags = ["malware", "code", args.category.lower()]
        for tag in tags:
            ensure_tag_page(tag)
        ensure_category_page("Malware")
        ensure_category_page(args.category)

        frontmatter = f"""---
title: "{subfolder.name}"
date: {post_date[:4]}-{post_date[4:6]}-{post_date[6:8]} 00:00:00 +0100
categories: [Malware, {args.category}]
tags:
  - malware
  - code
---

"""

        POSTS_DIR.mkdir(exist_ok=True)
        out = POSTS_DIR / f"{post_name}.md"
        out.write_text(frontmatter + body, encoding="utf-8")

        print(f"[+] SUCCESS: {out.name}")
        processed += 1

    print(f"\n[*] Done! Created {processed} posts.")


if __name__ == "__main__":
    main()