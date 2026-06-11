#!/usr/bin/env python3
"""
obsidian_to_jekyll.py
Converts Obsidian .md notes + source code files (.c, .h, .cpp, etc.) into Jekyll/Chirpy posts.

=== HOW TO USE ===

1. Single Markdown file:
   python3 obsidian_to_jekyll.py "/path/to/note.md" -c Development

2. Single code file (C/C++/Header):
   python3 obsidian_to_jekyll.py "/path/to/code.c" -c Reversing

3. Whole folder (recommended for malware/dev):
   python3 obsidian_to_jekyll.py "/path/to/development" -c Development

4. Scan mode (all configured folders):
   python3 obsidian_to_jekyll.py

Categories:
   - Machines     → under HackTheBox
   - Development  → under Malware
   - Reversing    → under Malware

Update WRITEUPS_ROOTS list below with your actual Windows paths.
"""

import re
import sys
import shutil
import argparse
from datetime import date
from pathlib import Path

POSTS_DIR      = Path("_posts")
ASSETS_DIR     = Path("assets/img/posts")
TAGS_DIR       = Path("tags")
CATEGORIES_DIR = Path("_categories")

CATEGORIES     = ["Machines", "Development", "Reversing"]
DIFFICULTIES   = ["easy", "medium", "hard", "insane"]
OS_OPTIONS     = ["windows", "linux", "freebsd", "other"]

# ================== UPDATE THESE PATHS ==================
WRITEUPS_ROOTS = [
    Path(r"C:\Users\N0xshell\Documents\n0xshell.github.io\development"),
    Path(r"C:\Users\N0xshell\Documents\n0xshell.github.io\reversing"),
    Path(r"C:\Users\N0xshell\Documents\n0xshell.github.io\malware"),
    # Add your HTB path if needed:
    # Path(r"/mnt/Files/Security-Related/Pentesting-Related/HackTheBox/Machines-Writeups"),
]

SUBDIR_CATEGORY_MAP = {
    "development": "Development",
    "reversing":   "Reversing",
    "malware":     "Reversing",
    "medium-machines": "Machines",
    "hard-machines":   "Machines",
    "easy-machines":   "Machines",
    "insane-machines": "Machines",
}


def slugify(s):
    s = s.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    return s.strip('-')


def parse_date(date_str):
    clean = date_str.replace('-', '')
    if not re.match(r'^\d{8}$', clean):
        sys.exit(f"[-] Invalid date '{date_str}' — use YYYY-MM-DD or YYYYMMDD")
    formatted = f"{clean[:4]}-{clean[4:6]}-{clean[6:8]}"
    try:
        date.fromisoformat(formatted)
    except ValueError:
        sys.exit(f"[-] Invalid date '{date_str}'")
    return formatted


def get_published_slugs():
    if not POSTS_DIR.exists():
        return set()
    return {re.sub(r'^\d{4}-\d{2}-\d{2}-', '', p.stem) for p in POSTS_DIR.glob("*.md")}


def ensure_tag_page(tag):
    TAGS_DIR.mkdir(exist_ok=True)
    tag_file = TAGS_DIR / f"{tag}.md"
    if not tag_file.exists():
        tag_file.write_text(
            f"---\nlayout: tag\ntitle: {tag}\ntag: {tag}\npermalink: /tags/{tag}/\n---\n",
            encoding="utf-8"
        )
        print(f"[+] Created tag page: {tag_file}")


def ensure_category_page(category):
    CATEGORIES_DIR.mkdir(exist_ok=True)
    slug = slugify(category)
    cat_file = CATEGORIES_DIR / f"{slug}.md"
    if not cat_file.exists():
        cat_file.write_text(
            f"---\nlayout: category\ntitle: {category}\ncategory: {category}\npermalink: /categories/{slug}/\n---\n",
            encoding="utf-8"
        )
        print(f"[+] Created category page: {cat_file}")


def scan_files():
    found = []
    for root in WRITEUPS_ROOTS:
        if not root.exists():
            print(f"[!] Folder not found: {root}")
            continue
        for file in sorted(root.rglob("*.*")):
            if file.name.startswith('.') or file.suffix.lower() not in {'.md', '.c', '.cpp', '.h', '.hpp', '.py', '.rs', '.go'}:
                continue
            found.append(file)
    return found


def code_to_markdown(src_path):
    """Convert source/header file into nice Markdown post"""
    ext = src_path.suffix.lower()
    lang_map = {
        '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
        '.py': 'python', '.rs': 'rust', '.go': 'go'
    }
    lang = lang_map.get(ext, 'text')

    title = src_path.stem
    content = src_path.read_text(encoding="utf-8", errors="replace")

    return f"""# {title}

**File:** `{src_path.name}`  
**Language:** {ext.upper()}

```{lang}
{content}
```
"""


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


def make_image_html(src_path, alt, post_slug, filename):
    url = f"/assets/img/posts/{post_slug}/{filename}"
    if alt and alt != Path(filename).stem:
        return (
            f'<div style="text-align:center;margin:1.5rem auto;">\n'
            f'  <img src="{url}" alt="{alt}" style="max-width:100%;border-radius:6px;">\n'
            f'  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">{alt}</p>\n'
            f'</div>'
        )
    return f"![{alt}]({url})"


def convert(content, post_slug, search_dirs, img_dir):
    # Image and markdown fixes (same as before)
    content = re.sub(r'!Pasted image ([^\n]+\.png)', r'![[Pasted image \1]]', content)
    content = re.sub(r'^(#{1,6})([^ #\n])', r'\1 \2', content, flags=re.MULTILINE)
    content = re.sub(r'([^\n])\n(```)', r'\1\n\n\2', content)
    content = re.sub(r'\n+(\n```)', r'\1', content)
    content = re.sub(r'%%.*?%%', '', content, flags=re.DOTALL)

    def handle_wiki_image(m):
        raw = m.group(1)
        filename = raw.split('|')[0].strip()
        alt = raw.split('|')[1].strip() if '|' in raw else Path(filename).stem
        src = find_image(filename, search_dirs)
        if src:
            shutil.copy2(str(src), str(img_dir / filename))
            print(f"[+] Copied: {filename}")
        return make_image_html(src, alt, post_slug, filename)

    content = re.sub(r'!\[\[([^\]]+)\]\]', handle_wiki_image, content)

    content = re.sub(r'\[\[([^\]|]+)(?:\|([^\]]+))?\]\]', lambda m: m.group(2) or m.group(1), content)

    def handle_md_image(m):
        alt, filename = m.group(1), m.group(2)
        if filename.startswith(("http://", "https://", "/assets/")):
            return m.group(0)
        src = find_image(filename, search_dirs)
        if src:
            shutil.copy2(str(src), str(img_dir / filename))
            print(f"[+] Copied: {filename}")
        return make_image_html(src, alt, post_slug, filename)

    content = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', handle_md_image, content)
    return content


def process_file(src, post_date, category=None, tags_cli=None):
    title = src.stem
    slug = slugify(title)
    post_name = f"{post_date}-{slug}"

    subdir_key = src.parent.name.lower()
    if not category:
        category = SUBDIR_CATEGORY_MAP.get(subdir_key) or "Development"

    parent = "HackTheBox" if category == "Machines" else "Malware"

    if tags_cli:
        tags = [t.strip().lower() for t in re.split(r'[,\s]+', " ".join(tags_cli)) if t.strip()]
    else:
        tags = ["malware", "code"]
        extra = []  # prompt_extra_tags() can be added back if wanted
        tags += extra

    for tag in set(tags):  # dedup
        ensure_tag_page(tag)
    ensure_category_page(parent)
    ensure_category_page(category)

    img_dir = ASSETS_DIR / post_name
    img_dir.mkdir(parents=True, exist_ok=True)

    if src.suffix.lower() == '.md':
        body = convert(strip_frontmatter(src.read_text(encoding="utf-8")), post_name, [src.parent], img_dir)
    else:
        body = code_to_markdown(src)

    tags_yaml = "\n".join(f"  - {t}" for t in tags)
    frontmatter = f"""---
title: "{title}"
date: {post_date} 00:00:00 +0100
categories: [{parent}, {category}]
tags:
{tags_yaml}
---
"""

    POSTS_DIR.mkdir(exist_ok=True)
    out = POSTS_DIR / f"{post_name}.md"
    out.write_text(frontmatter + body + "\n", encoding="utf-8")

    print(f"\n[+] SUCCESS: {out}")
    print(f"    Images folder: {img_dir}")
    print(f"\n    git add _posts/{post_name}.md assets/img/posts/{post_name}/ tags/ _categories/")
    print(f"    git commit -m 'Add {title}'")
    print(f"    git push")


def main():
    parser = argparse.ArgumentParser(description="Convert notes & code to Jekyll posts")
    parser.add_argument("input", nargs="?", help="File or folder path (optional)")
    parser.add_argument("--category", "-c", choices=CATEGORIES, help="Force category")
    parser.add_argument("--tags", "-t", nargs="+", help="Extra tags")
    parser.add_argument("--date", "-d", default=str(date.today()), help="Post date YYYYMMDD")
    parser.add_argument("--batch", action="store_true", help="No confirmation prompts (for big folders)")
    args = parser.parse_args()

    post_date = parse_date(args.date)

    if args.input:
        path = Path(args.input).expanduser().resolve()
        if path.is_file():
            process_file(path, post_date, args.category, args.tags)
        elif path.is_dir():
            print(f"[*] Processing folder: {path}")
            for f in sorted(path.rglob("*.*")):
                if f.name.startswith('.') or f.suffix.lower() not in {'.md','.c','.cpp','.h','.hpp','.py'}:
                    continue
                print(f"   → {f.name}")
                if args.batch or input("   Publish? [Y/n] > ").strip().lower() in ('', 'y', 'yes'):
                    process_file(f, post_date, args.category, args.tags)
                else:
                    print("   Skipped")
        else:
            print(f"[-] Path not found: {path}")
        return

    # Scan mode
    print("[*] Scanning all configured folders...")
    all_files = scan_files()
    published = get_published_slugs()
    new_files = [f for f in all_files if slugify(f.stem) not in published]

    if not new_files:
        print("[+] No new files found.")
        return

    print(f"[*] Found {len(new_files)} unpublished files:")
    for i, f in enumerate(new_files, 1):
        print(f"  {i}) {f.name}  ({f.parent.name})")

    for f in new_files:
        if args.batch or input(f"\nPublish '{f.name}'? [y/n] > ").strip().lower() in ('y', 'yes'):
            process_file(f, post_date, args.category, args.tags)
        else:
            print(f"  [-] Skipped")


if __name__ == "__main__":
    main()
