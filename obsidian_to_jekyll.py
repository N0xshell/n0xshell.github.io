#!/usr/bin/env python3
"""
obsidian_to_jekyll.py
Converts an Obsidian .md note to a Jekyll/Chirpy post.
Handles both ![[image]] and ![alt](image) formats.

Usage:
  python3 obsidian_to_jekyll.py                        # scan mode
  python3 obsidian_to_jekyll.py <file.md>              # single file
  python3 obsidian_to_jekyll.py <file.md> -c Machines -D medium -o windows

Categories: Machines | Prolabs | Exam Review
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
CATEGORIES     = ["Machines", "Prolabs", "Exam Review"]
DIFFICULTIES   = ["easy", "medium", "hard", "insane"]
OS_OPTIONS     = ["windows", "linux", "freebsd", "other"]

WRITEUPS_ROOT = Path("/mnt/Files/Security-Related/Pentesting-Related/HackTheBox/Machines-Writeups")

SUBDIR_CATEGORY_MAP = {
    "medium-machines": "Machines",
    "hard-machines":   "Machines",
    "easy-machines":   "Machines",
    "insane-machines": "Machines",
    "exam review":     "Exam Review",
    "prolabs":         "Prolabs",
}

SUBDIR_DIFFICULTY_MAP = {
    "medium-machines": "medium",
    "hard-machines":   "hard",
    "easy-machines":   "easy",
    "insane-machines": "insane",
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
        sys.exit(f"[-] Invalid date '{date_str}' — not a real calendar date")
    return formatted


def get_published_slugs():
    if not POSTS_DIR.exists():
        return set()
    return {
        re.sub(r'^\d{4}-\d{2}-\d{2}-', '', p.stem)
        for p in POSTS_DIR.glob("*.md")
    }


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


def scan_writeups():
    if not WRITEUPS_ROOT.exists():
        sys.exit(f"[-] Writeups root not found: {WRITEUPS_ROOT}")
    found = []
    for subdir in sorted(WRITEUPS_ROOT.iterdir()):
        if not subdir.is_dir() or subdir.name.startswith('.'):
            continue
        for md in sorted(subdir.rglob("*.md")):
            if md.name.startswith('.'):
                continue
            found.append(md)
    return found


def prompt_choice(question, options):
    print(f"\n{question}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        try:
            choice = input("  > ").strip()
            if choice.lower() in [o.lower() for o in options]:
                return choice.lower()
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx].lower()
        except (ValueError, KeyboardInterrupt):
            print()
            sys.exit(0)
        print(f"  [-] Pick 1-{len(options)} or type the option name")


def prompt_yn(question):
    while True:
        try:
            ans = input(f"{question} [y/n] > ").strip().lower()
            if ans in ('y', 'yes'):
                return True
            if ans in ('n', 'no'):
                return False
        except KeyboardInterrupt:
            print()
            sys.exit(0)


def prompt_extra_tags():
    print("\nExtra tags? (comma-separated, or leave blank)")
    try:
        raw = input("  > ").strip()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
    if not raw:
        return []
    return [t.strip().lower() for t in raw.split(',') if t.strip()]


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
    """Return figure HTML if caption present, plain markdown otherwise."""
    url = f"/assets/img/posts/{post_slug}/{filename}"
    if alt and alt != Path(filename).stem:
        return (
            f'<figure>\n'
            f'  <a href="{url}" data-lightbox="{filename}">\n'
            f'    <img src="{url}" alt="{alt}">\n'
            f'  </a>\n'
            f'  <figcaption>{alt}</figcaption>\n'
            f'</figure>'
        )
    return f"![{alt}]({url})"


def convert(content, post_slug, search_dirs, img_dir):
    # Fix bare image references
    content = re.sub(r'!Pasted image ([^\n]+\.png)', r'![[Pasted image \1]]', content)

    # Fix headings missing space after #
    content = re.sub(r'^(#{1,6})([^ #\n])', r'\1 \2', content, flags=re.MULTILINE)

    # Obsidian comments
    content = re.sub(r'%%.*?%%', '', content, flags=re.DOTALL)

    # Callouts
    content = re.sub(
        r'^> \[!(\w+)\]\s*(.*?)$',
        lambda m: f"> **{m.group(1).capitalize()}:** {m.group(2).strip()}",
        content, flags=re.MULTILINE
    )

    # ![[image.png]] and ![[image.png|caption]]
    def handle_wiki_image(m):
        raw      = m.group(1)
        filename = raw.split('|')[0].strip()
        alt      = raw.split('|')[1].strip() if '|' in raw else Path(filename).stem
        src = find_image(filename, search_dirs)
        if src:
            shutil.copy2(str(src), str(img_dir / filename))
            print(f"[+] Copied: {filename}")
        else:
            print(f"[!] Not found: {filename} — add manually to {img_dir}/")
        return make_image_html(src, alt, post_slug, filename)

    content = re.sub(r'!\[\[([^\]]+)\]\]', handle_wiki_image, content)

    # [[wikilinks]]
    content = re.sub(
        r'\[\[([^\]|]+)(?:\|([^\]]+))?\]\]',
        lambda m: m.group(2) or m.group(1),
        content
    )

    # ![alt](image.png) standard markdown images
    def handle_md_image(m):
        alt      = m.group(1)
        filename = m.group(2)
        if filename.startswith("http://") or \
           filename.startswith("https://") or \
           filename.startswith("/assets/"):
            return m.group(0)
        src = find_image(filename, search_dirs)
        if src:
            shutil.copy2(str(src), str(img_dir / filename))
            print(f"[+] Copied: {filename}")
        else:
            print(f"[!] Not found: {filename} — add manually to {img_dir}/")
        return make_image_html(src, alt, post_slug, filename)

    content = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', handle_md_image, content)
    return content


def process_file(src, post_date, category=None, difficulty=None, os_tag=None, tags_cli=None):
    search_dirs = [src.parent, src.parent.parent, src.parent.parent.parent]

    title     = src.stem
    slug      = slugify(title)
    post_name = f"{post_date}-{slug}"

    subdir_key = src.parent.name.lower()
    if not category:
        category = SUBDIR_CATEGORY_MAP.get(subdir_key) or \
                   prompt_choice("Category?", CATEGORIES).capitalize()
    if not difficulty:
        difficulty = SUBDIR_DIFFICULTY_MAP.get(subdir_key) or \
                     prompt_choice("Difficulty?", DIFFICULTIES)
    if not os_tag:
        os_tag = prompt_choice("OS?", OS_OPTIONS)

    if tags_cli:
        raw  = " ".join(tags_cli)
        tags = [t.strip().lower() for t in re.split(r'[,\s]+', raw) if t.strip()]
    else:
        tags  = [difficulty, os_tag]
        extra = prompt_extra_tags()
        tags += [t for t in extra if t not in tags]

    for tag in tags:
        ensure_tag_page(tag)
    ensure_category_page("HackTheBox")
    ensure_category_page(category)

    img_dir = ASSETS_DIR / post_name
    img_dir.mkdir(parents=True, exist_ok=True)

    body = convert(
        strip_frontmatter(src.read_text(encoding="utf-8")),
        post_name,
        search_dirs,
        img_dir
    )

    tags_yaml   = "\n".join(f"  - {t}" for t in tags)
    cat_display = category if category in CATEGORIES else category.capitalize()
    frontmatter = f"""---
title: "{title}"
date: {post_date} 00:00:00 +0100
categories: [HackTheBox, {cat_display}]
tags:
{tags_yaml}
---
"""

    POSTS_DIR.mkdir(exist_ok=True)
    out = POSTS_DIR / f"{post_name}.md"
    out.write_text(frontmatter + "\n" + body + "\n", encoding="utf-8")

    print(f"\n[+] Post:   {out}")
    print(f"[+] Images: {img_dir}/")
    print(f"\n    git add _posts/{post_name}.md assets/img/posts/{post_name}/ tags/ _categories/")
    print(f"    git commit -m 'Add {title}'")
    print(f"    git push")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input",        nargs="?",           help="Obsidian .md file (omit to scan)")
    parser.add_argument("--category",   "-c", choices=CATEGORIES)
    parser.add_argument("--difficulty", "-D", choices=DIFFICULTIES)
    parser.add_argument("--os",         "-o", choices=OS_OPTIONS)
    parser.add_argument("--tags",       "-t", nargs="+")
    parser.add_argument("--date",       "-d", default=str(date.today()))
    args = parser.parse_args()

    post_date = parse_date(args.date)

    if args.input:
        src = Path(args.input).expanduser().resolve()
        if not src.exists():
            sys.exit(f"[-] Not found: {src}")
        process_file(src, post_date, args.category, args.difficulty, args.os, args.tags)
        return

    published = get_published_slugs()
    all_files = scan_writeups()
    new_files = [f for f in all_files if slugify(f.stem) not in published]

    if not new_files:
        print("[+] No new writeups found.")
        return

    print(f"[*] Found {len(new_files)} unpublished writeup(s):\n")
    for i, f in enumerate(new_files, 1):
        print(f"  {i}) {f.stem}  ({f.parent.name})")

    print()
    for f in new_files:
        if prompt_yn(f"\nPublish '{f.stem}'?"):
            process_file(f, post_date, args.category, args.difficulty, args.os, args.tags)
        else:
            print(f"  [-] Skipped {f.stem}")


if __name__ == "__main__":
    main()