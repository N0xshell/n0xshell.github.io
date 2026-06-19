#!/usr/bin/env python3
"""
obsidian_to_jekyll.py + c_to_jekyll.py combined
Converts Obsidian .md notes OR C source code folders to Jekyll/Chirpy posts.

Usage (Markdown):
  python3 obsidian_to_jekyll.py                              # scan mode (all sources)
  python3 obsidian_to_jekyll.py <file.md>                    # single file (auto-detect source)
  python3 obsidian_to_jekyll.py <file.md> -s htb -c Machines -D medium -o windows
  python3 obsidian_to_jekyll.py <file.md> -s maldev -c Development

Usage (C Code):
  python3 obsidian_to_jekyll.py --scan-code maldev          # scan maldev folders for .c files
  python3 obsidian_to_jekyll.py --scan-code reversing       # scan reversing folders for .c files
  python3 obsidian_to_jekyll.py --code-folder "folder-path" # single folder with C files

Sources:    htb | maldev | reversing
Categories (HTB):      Machines
Categories (MalDev):   Development | Reversing
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

HTB_CATEGORIES    = ["Machines"]
MALDEV_CATEGORIES = ["Development", "Reversing"]
ALL_CATEGORIES    = HTB_CATEGORIES + MALDEV_CATEGORIES

DIFFICULTIES = ["easy", "medium", "hard", "insane"]
OS_OPTIONS   = ["windows", "linux", "freebsd", "other"]
SOURCES      = ["htb", "maldev", "reversing"]

# ── Root paths ────────────────────────────────────────────
CONTENT_ROOTS = {
    "htb":       Path("//10.0.0.15/Files/Security-Related/Pentesting-Related/HackTheBox/Machines-Writeups"),
    "maldev":    Path("//10.0.0.15/Files/Security-Related/Malware-Related/MaldevAcademy-Related/Malware Development Modules"),
    "reversing": Path("//10.0.0.15/Files/Security-Related/Malware-Related/Reversing-Notes"),
}

# ── HTB subdir → category / difficulty auto-mapping
SUBDIR_CATEGORY_MAP = {
    "medium-machines": "Machines",
    "hard-machines":   "Machines",
    "easy-machines":   "Machines",
    "insane-machines": "Machines",
}

SUBDIR_DIFFICULTY_MAP = {
    "medium-machines": "medium",
    "hard-machines":   "hard",
    "easy-machines":   "easy",
    "insane-machines": "insane",
}

# ── MalDev subdir → category auto-mapping
MALDEV_SUBDIR_CATEGORY_MAP = {
    "maldev":    "Development",
    "mal-dev":   "Development",
    "dev":       "Development",
    "reversing": "Reversing",
    "re":        "Reversing",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def detect_source(path: Path) -> str:
    """Best-effort source detection from the file's absolute path."""
    parts = [p.lower() for p in path.parts]
    if "hackthebox" in parts or "htb" in parts or "machines-writeups" in parts:
        return "htb"
    if "malware-related" in parts or "maldevacademy-related" in parts or "maldev" in parts or "mal-dev" in parts:
        return "maldev"
    if "reversing" in parts or "reverse-engineering" in parts or "reversing-notes" in parts:
        return "reversing"
    return "htb"


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


def scan_all():
    """Scan all configured content roots for unpublished .md files."""
    found = []
    for source, root in CONTENT_ROOTS.items():
        if not root.exists():
            print(f"[~] Skipping '{source}' root (not found): {root}")
            continue
        for subdir in sorted(root.iterdir()):
            if not subdir.is_dir() or subdir.name.startswith('.'):
                continue
            for md in sorted(subdir.rglob("*.md")):
                if not md.name.startswith('.'):
                    found.append((source, md))
    return found


def scan_code_folders(source):
    """Scan maldev/reversing root for folders with .c files."""
    root = CONTENT_ROOTS.get(source)
    if not root or not root.exists():
        print(f"[-] Source root not found: {source}")
        return []
    
    found = []
    for folder in sorted(root.iterdir()):
        if not folder.is_dir() or folder.name.startswith('.'):
            continue
        c_files = list(folder.glob("*.c"))
        if c_files:
            found.append((folder, c_files))
    
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
    content = re.sub(r'!Pasted image ([^\n]+\.png)', r'![[Pasted image \1]]', content)
    content = re.sub(r'^(#{1,6})([^ #\n])', r'\1 \2', content, flags=re.MULTILINE)
    content = re.sub(r'([^\n])\n(```)', r'\1\n\n\2', content)
    content = re.sub(r'\n+(\n```)', r'\1', content)
    content = re.sub(r'%%.*?%%', '', content, flags=re.DOTALL)
    content = re.sub(
        r'^> \[!(\w+)\]\s*(.*?)$',
        lambda m: f"> **{m.group(1).capitalize()}:** {m.group(2).strip()}",
        content, flags=re.MULTILINE
    )

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
    content = re.sub(
        r'\[\[([^\]|]+)(?:\|([^\]]+))?\]\]',
        lambda m: m.group(2) or m.group(1),
        content
    )

    def handle_md_image(m):
        alt      = m.group(1)
        filename = m.group(2)
        if filename.startswith(("http://", "https://", "/assets/")):
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


# ── Code file processing ──────────────────────────────────────────────────────

def process_code_folder(folder: Path, source: str, post_date: str):
    """Create a Jekyll post from a folder containing .c files."""
    title = folder.name
    slug = slugify(title)
    post_name = f"{post_date}-{slug}"
    
    # Determine category from source
    if source == "maldev":
        category = "Development"
    elif source == "reversing":
        category = "Reversing"
    else:
        category = "Development"  # fallback
    
    # Read all .c files in the folder
    c_files = sorted(folder.glob("*.c"))
    if not c_files:
        print(f"[-] No .c files found in {folder}")
        return
    
    # Build body with code blocks for each file
    body_parts = [f"# {title}\n"]
    
    for c_file in c_files:
        try:
            code = c_file.read_text(encoding="utf-8")
            body_parts.append(f"\n## {c_file.name}\n\n```c\n{code}\n```\n")
            print(f"[+] Included: {c_file.name}")
        except Exception as e:
            print(f"[!] Failed to read {c_file.name}: {e}")
    
    body = "\n".join(body_parts)
    
    # Create category pages
    ensure_category_page("Malware")
    ensure_category_page(category)
    
    # Tags
    tags = ["malware", category.lower()]
    for tag in tags:
        ensure_tag_page(tag)
    
    tags_yaml = "\n".join(f"  - {t}" for t in tags)
    categories_yaml = f"[Malware, {category}]"
    
    frontmatter = f"""---
title: "{title}"
date: {post_date} 00:00:00 +0100
categories: {categories_yaml}
tags:
{tags_yaml}
---
"""
    
    POSTS_DIR.mkdir(exist_ok=True)
    out = POSTS_DIR / f"{post_name}.md"
    out.write_text(frontmatter + "\n" + body + "\n", encoding="utf-8")
    
    print(f"\n[+] Post created: {out}")
    print(f"    git add _posts/{post_name}.md tags/ _categories/")
    print(f"    git commit -m 'Add {title}'")
    print(f"    git push")


# ── Markdown file processing ──────────────────────────────────────────────────

def process_file(src, post_date, source=None, category=None, difficulty=None, os_tag=None, tags_cli=None):
    search_dirs = [src.parent, src.parent.parent, src.parent.parent.parent]

    title     = src.stem
    slug      = slugify(title)
    post_name = f"{post_date}-{slug}"

    if not source:
        source = detect_source(src)

    subdir_key = src.parent.name.lower()
    is_htb     = (source == "htb")

    if not category:
        if is_htb:
            category = SUBDIR_CATEGORY_MAP.get(subdir_key) or \
                       prompt_choice("Category?", HTB_CATEGORIES).capitalize()
        else:
            category = MALDEV_SUBDIR_CATEGORY_MAP.get(subdir_key) or \
                       prompt_choice("Category?", MALDEV_CATEGORIES)

    if is_htb:
        if not difficulty:
            difficulty = SUBDIR_DIFFICULTY_MAP.get(subdir_key) or \
                         prompt_choice("Difficulty?", DIFFICULTIES)
        if not os_tag:
            os_tag = prompt_choice("OS?", OS_OPTIONS)

    if tags_cli:
        raw  = " ".join(tags_cli)
        tags = [t.strip().lower() for t in re.split(r'[,\s]+', raw) if t.strip()]
    else:
        if is_htb:
            tags = [difficulty, os_tag]
        else:
            tags = ["malware", category.lower()]
        extra = []
        tags += [t for t in extra if t not in tags]

    for tag in tags:
        ensure_tag_page(tag)

    if is_htb:
        ensure_category_page("HackTheBox")
        ensure_category_page("Machines")
    else:
        ensure_category_page("Malware")
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

    if is_htb:
        categories_yaml = f"[HackTheBox, Machines]"
    else:
        categories_yaml = f"[Malware, {category}]"

    frontmatter = f"""---
title: "{title}"
date: {post_date} 00:00:00 +0100
categories: {categories_yaml}
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


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input",          nargs="?",                   help="Obsidian .md file")
    parser.add_argument("--source",       "-s", choices=SOURCES,       help="Content source type")
    parser.add_argument("--category",     "-c", choices=ALL_CATEGORIES)
    parser.add_argument("--difficulty",   "-D", choices=DIFFICULTIES)
    parser.add_argument("--os",           "-o", choices=OS_OPTIONS)
    parser.add_argument("--tags",         "-t", nargs="+")
    parser.add_argument("--date",         "-d", default=str(date.today()))
    parser.add_argument("--scan-code",    choices=["maldev", "reversing"], help="Scan for C code folders")
    parser.add_argument("--code-folder",  type=str, help="Single C code folder to process")
    
    args = parser.parse_args()

    post_date = parse_date(args.date)

    # Handle code folder scanning
    if args.scan_code:
        folders = scan_code_folders(args.scan_code)
        if not folders:
            print(f"[+] No folders with .c files found in {args.scan_code}")
            return
        
        published = get_published_slugs()
        new_folders = [(f, c) for f, c in folders if slugify(f.name) not in published]
        
        if not new_folders:
            print("[+] All code folders already published")
            return
        
        print(f"[*] Found {len(new_folders)} unpublished code folder(s):\n")
        for i, (f, c) in enumerate(new_folders, 1):
            print(f"  {i}) {f.name} ({len(c)} .c files)")
        
        print()
        for folder, c_files in new_folders:
            if prompt_yn(f"\nPublish '{folder.name}'?"):
                process_code_folder(folder, args.scan_code, post_date)
            else:
                print(f"  [-] Skipped {folder.name}")
        return
    
    # Handle single code folder
    if args.code_folder:
        folder = Path(args.code_folder).resolve()
        if not folder.is_dir():
            sys.exit(f"[-] Not a directory: {folder}")
        c_files = list(folder.glob("*.c"))
        if not c_files:
            sys.exit(f"[-] No .c files in {folder}")
        source = detect_source(folder)
        process_code_folder(folder, source, post_date)
        return
    
    # Handle markdown files
    if args.input:
        src = Path(args.input).expanduser().resolve()
        if not src.exists():
            sys.exit(f"[-] Not found: {src}")
        process_file(src, post_date, args.source, args.category, args.difficulty, args.os, args.tags)
        return

    published = get_published_slugs()
    all_files = scan_all()
    new_files = [(s, f) for s, f in all_files if slugify(f.stem) not in published]

    if not new_files:
        print("[+] No new notes found.")
        return

    print(f"[*] Found {len(new_files)} unpublished note(s):\n")
    for i, (s, f) in enumerate(new_files, 1):
        print(f"  {i}) [{s:10s}] {f.stem}  ({f.parent.name})")

    print()
    for s, f in new_files:
        if prompt_yn(f"\nPublish '{f.stem}' [{s}]?"):
            process_file(f, post_date, s, args.category, args.difficulty, args.os, args.tags)
        else:
            print(f"  [-] Skipped {f.stem}")


if __name__ == "__main__":
    main()