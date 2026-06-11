#!/usr/bin/env python3
"""
obsidian_to_jekyll.py
Converts an Obsidian .md note to a Jekyll/Chirpy post.
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

WRITEUPS_ROOT = Path("/mnt/Files/Security-Related/Pentesting-Related/HackTheBox/Machines-Writeups")

SUBDIR_CATEGORY_MAP = {
    "medium-machines": "Machines",
    "hard-machines":   "Machines",
    "easy-machines":   "Machines",
    "insane-machines": "Machines",
    "development":     "Development",
    "reversing":       "Reversing",
    "malware":         "Reversing",   # or Development
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
        print(f"[!] Writeups root not found: {WRITEUPS_ROOT} (scan mode limited)")
        return []
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
            sys.exit(0)
        print(f"  [-] Pick 1-{len(options)} or type the option name")


def prompt_yn(question):
    while True:
        ans = input(f"{question} [y/n] > ").strip().lower()
        if ans in ('y', 'yes'): return True
        if ans in ('n', 'no'): return False


def prompt_extra_tags():
    print("\nExtra tags? (comma-separated, or leave blank)")
    raw = input("  > ").strip()
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
    url = f"/assets/img/posts/{post_slug}/{filename}"
    if alt and alt != Path(filename).stem:
        return f'<div style="text-align:center;margin:1.5rem auto;">\n  <img src="{url}" alt="{alt}" style="max-width:100%;border-radius:6px;">\n  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">{alt}</p>\n</div>'
    return f"![{alt}]({url})"


def convert(content, post_slug, search_dirs, img_dir):
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


def process_file(src, post_date, category=None, difficulty=None, os_tag=None, tags_cli=None):
    search_dirs = [src.parent, src.parent.parent, src.parent.parent.parent]

    title = src.stem
    slug = slugify(title)
    post_name = f"{post_date}-{slug}"

    subdir_key = src.parent.name.lower()
    if not category:
        category = SUBDIR_CATEGORY_MAP.get(subdir_key) or prompt_choice("Category?", CATEGORIES).capitalize()

    # Determine parent category
    if category == "Machines":
        parent = "HackTheBox"
    else:
        parent = "Malware"

    if tags_cli:
        tags = [t.strip().lower() for t in re.split(r'[,\s]+', " ".join(tags_cli)) if t.strip()]
    else:
        tags = []
        if category == "Machines":
            if not difficulty:
                difficulty = SUBDIR_DIFFICULTY_MAP.get(subdir_key) or prompt_choice("Difficulty?", DIFFICULTIES)
            if not os_tag:
                os_tag = prompt_choice("OS?", OS_OPTIONS)
            tags.extend([difficulty, os_tag])
        extra = prompt_extra_tags()
        tags += [t for t in extra if t not in tags]
        if not tags:
            tags = ["malware"]

    for tag in tags:
        ensure_tag_page(tag)
    ensure_category_page(parent)
    ensure_category_page(category)

    img_dir = ASSETS_DIR / post_name
    img_dir.mkdir(parents=True, exist_ok=True)

    body = convert(strip_frontmatter(src.read_text(encoding="utf-8")), post_name, search_dirs, img_dir)

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
    out.write_text(frontmatter + "\n" + body + "\n", encoding="utf-8")

    print(f"\n[+] Post created: {out}")
    print(f"[+] Images: {img_dir}/")
    print(f"\n    git add _posts/{post_name}.md assets/img/posts/{post_name}/ tags/ _categories/")
    print(f"    git commit -m 'Add {title}'")
    print(f"    git push")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", help="Obsidian .md file")
    parser.add_argument("--category", "-c", choices=CATEGORIES)
    parser.add_argument("--difficulty", "-D", choices=DIFFICULTIES)
    parser.add_argument("--os", "-o", choices=OS_OPTIONS)
    parser.add_argument("--tags", "-t", nargs="+")
    parser.add_argument("--date", "-d", default=str(date.today()))
    args = parser.parse_args()

    post_date = parse_date(args.date)

    if args.input:
        src = Path(args.input).expanduser().resolve()
        if not src.exists():
            sys.exit(f"[-] File not found: {src}")
        process_file(src, post_date, args.category, args.difficulty, args.os, args.tags)
        return

    # Scan mode
    published = get_published_slugs()
    all_files = scan_writeups()
    new_files = [f for f in all_files if slugify(f.stem) not in published]

    if not new_files:
        print("[+] No new files found.")
        return

    print(f"[*] Found {len(new_files)} new file(s):")
    for i, f in enumerate(new_files, 1):
        print(f"  {i}) {f.stem} ({f.parent.name})")

    for f in new_files:
        if prompt_yn(f"\nPublish '{f.stem}'?"):
            process_file(f, post_date, args.category, args.difficulty, args.os, args.tags)
        else:
            print(f"  [-] Skipped {f.stem}")


if __name__ == "__main__":
    main()