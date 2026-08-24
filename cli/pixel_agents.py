"""
Pixel Agents — ASCII sprite animations for Argus scan tasks.

Each scan module gets a named character who "performs" the task with
frame-based sprite animations rendered via Rich Live display.

Characters and their animation sets:
  Scout  — dir_enum       (walks left-right, crouches, peeks)
  Recon  — vhost          (binoculars pose, looks left/right)
  Hacker — param          (typing at keyboard, flips hair)
  API    — api            (points at screen, rotates charts)
  Spider — subdomain      (climbs, drops on web)
  Rule   — rules          (reads scroll, stamps MATCH)
"""

from typing import List, Tuple

# ─── Sprite definitions ───────────────────────────────────────────────────────
# Each sprite is a list of frames.  Each frame is a list of strings (rows).
# Width is kept at 12 chars, height at 7 rows so they align cleanly.

# Walking cycle — used by Scout (dir_enum)
SPRITE_SCOUT: List[List[str]] = [
    [
        r"    o    ",
        r"   /|\   ",
        r"   / \   ",
        r"  _/ \_  ",
        r"",
        r"  searching",
        r"  paths... ",
    ],
    [
        r"    o    ",
        r"   \|/   ",
        r"   / \   ",
        r"  _/ \_  ",
        r"",
        r"  scanning ",
        r"  dirs...  ",
    ],
    [
        r"    o    ",
        r"   /|\   ",
        r"   /  \  ",
        r" _/    \ ",
        r"",
        r"  enumerating",
        r"  files...   ",
    ],
    [
        r"    o    ",
        r"   \|/   ",
        r"   /  \  ",
        r" _/    \ ",
        r"",
        r"  probing  ",
        r"  endpoints",
    ],
]

# Binoculars — Recon (vhost)
SPRITE_RECON: List[List[str]] = [
    [
        r"    o    ",
        r"   /|==> ",
        r"   / \   ",
        r"  /   \  ",
        r"",
        r"  scanning ",
        r"  hosts... ",
    ],
    [
        r"    o    ",
        r" <==|\   ",
        r"   / \   ",
        r"  /   \  ",
        r"",
        r"  fuzzing  ",
        r"  headers..",
    ],
    [
        r"    o    ",
        r"   /|==> ",
        r"    \    ",
        r"   / \   ",
        r"",
        r"  host     ",
        r"  detected!",
    ],
    [
        r"  \o/    ",
        r"   |     ",
        r"  / \    ",
        r" /   \   ",
        r"",
        r"  vhost    ",
        r"  confirmed",
    ],
]

# Typing hacker — param fuzzer
SPRITE_HACKER: List[List[str]] = [
    [
        r"   \o/   ",
        r"    |    ",
        r"   _|_   ",
        r" [=====] ",
        r"",
        r"  fuzzing  ",
        r"  params.. ",
    ],
    [
        r"    o/   ",
        r"    |    ",
        r"   _|_   ",
        r" [=====] ",
        r"",
        r"  injecting",
        r"  payloads.",
    ],
    [
        r"   \o    ",
        r"    |    ",
        r"   _|_   ",
        r" [=====] ",
        r"",
        r"  testing  ",
        r"  SQLi...  ",
    ],
    [
        r"   \o/   ",
        r"    |    ",
        r"  __|__  ",
        r" [=====] ",
        r"",
        r"  XSS      ",
        r"  payload..",
    ],
]

# API scanner — points at chart
SPRITE_API: List[List[str]] = [
    [
        r"    o    ",
        r"   /|->  ",
        r"   /|    ",
        r"  / |    ",
        r" [/api/] ",
        r"  mapping  ",
        r"  routes.. ",
    ],
    [
        r"    o    ",
        r"   /|->> ",
        r"   /|    ",
        r"  / |    ",
        r" [/api/] ",
        r"  reading  ",
        r"  schema.. ",
    ],
    [
        r"    o    ",
        r"  /|->>> ",
        r"   /|    ",
        r"  / |    ",
        r" [/api/] ",
        r"  fuzzing  ",
        r"  endpoint ",
    ],
    [
        r"   \o/   ",
        r"    |    ",
        r"    |    ",
        r"  __|__  ",
        r" [/api/] ",
        r"  API      ",
        r"  found!   ",
    ],
]

# Spider / climber — subdomain
SPRITE_SPIDER: List[List[str]] = [
    [
        r"    |    ",
        r"   \o/   ",
        r"  --+--  ",
        r"   / \   ",
        r"  *   *  ",
        r"  crawling ",
        r"  DNS...   ",
    ],
    [
        r"   \|/   ",
        r"   (o)   ",
        r"  --+--  ",
        r"   / \   ",
        r" *     * ",
        r"  querying ",
        r"  crt.sh.. ",
    ],
    [
        r"    |    ",
        r"   /o\   ",
        r"  --+--  ",
        r"   / \   ",
        r"  *   *  ",
        r"  AXFR     ",
        r"  probe... ",
    ],
    [
        r"  \   /  ",
        r"   \o/   ",
        r"   -+-   ",
        r"   / \   ",
        r" **   ** ",
        r"  subdomain",
        r"  found!   ",
    ],
]

# Rule reader — reads scroll, stamps
SPRITE_RULES: List[List[str]] = [
    [
        r"    o    ",
        r"   /|>   ",
        r"   / \   ",
        r"  [===]  ",
        r"",
        r"  loading  ",
        r"  templates",
    ],
    [
        r"    o    ",
        r"   /|>   ",
        r"   / \   ",
        r"  [===]  ",
        r"",
        r"  reading  ",
        r"  rules... ",
    ],
    [
        r"  \o/    ",
        r"   |>    ",
        r"   |\    ",
        r"  [===]  ",
        r"",
        r"  matching ",
        r"  pattern..",
    ],
    [
        r"  \o/    ",
        r"   |     ",
        r"  _|_    ",
        r" [MATCH] ",
        r"",
        r"  rule     ",
        r"  matched! ",
    ],
]

# Generic idle / done sprite
SPRITE_DONE: List[List[str]] = [
    [
        r"  \o/    ",
        r"   |     ",
        r"  / \    ",
        r" /   \   ",
        r"",
        r"  done!    ",
        r"           ",
    ],
]

# ─── Module → sprite mapping ──────────────────────────────────────────────────
MODULE_SPRITES = {
    "dir":       SPRITE_SCOUT,
    "vhost":     SPRITE_RECON,
    "param":     SPRITE_HACKER,
    "api":       SPRITE_API,
    "subdomain": SPRITE_SPIDER,
    "rules":     SPRITE_RULES,
}

MODULE_NAMES = {
    "dir":       "Scout",
    "vhost":     "Recon",
    "param":     "Hacker",
    "api":       "API",
    "subdomain": "Spider",
    "rules":     "Rule",
}

# ─── Mini pixel-art title cards for each agent ───────────────────────────────
AGENT_TITLES = {
    "dir": [
        "  +-----------+",
        "  |  SCOUT    |",
        "  | dir_enum  |",
        "  +-----------+",
    ],
    "vhost": [
        "  +-----------+",
        "  |  RECON    |",
        "  |   vhost   |",
        "  +-----------+",
    ],
    "param": [
        "  +-----------+",
        "  |  HACKER   |",
        "  |   param   |",
        "  +-----------+",
    ],
    "api": [
        "  +-----------+",
        "  |  API BOT  |",
        "  |    api    |",
        "  +-----------+",
    ],
    "subdomain": [
        "  +-----------+",
        "  |  SPIDER   |",
        "  | subdomain |",
        "  +-----------+",
    ],
    "rules": [
        "  +-----------+",
        "  |  RULER    |",
        "  |   rules   |",
        "  +-----------+",
    ],
}


def get_frame(module: str, tick: int) -> Tuple[List[str], str]:
    """
    Return (sprite_frame_lines, agent_name) for a given module and tick counter.
    Ticks cycle through all frames of the sprite.
    """
    frames = MODULE_SPRITES.get(module, SPRITE_SCOUT)
    frame  = frames[tick % len(frames)]
    name   = MODULE_NAMES.get(module, "Agent")
    return frame, name


def render_agent_panel(module: str, tick: int, status_line: str = "") -> str:
    """
    Build a Rich markup string showing the pixel agent for this module.
    Designed to be printed inside a Rich Panel or alongside progress bars.
    """
    frame, name = get_frame(module, tick)
    title_lines = AGENT_TITLES.get(module, [])

    lines = []
    # Title card
    for tl in title_lines:
        lines.append(f"[bright_black]{tl}[/bright_black]")
    lines.append("")

    # Sprite body
    for row in frame:
        if not row:
            lines.append("")
        elif any(kw in row for kw in ("found", "MATCH", "confirmed", "detected")):
            lines.append(f"[bold cyan]{row}[/bold cyan]")
        elif row.startswith("  "):
            # action/status text line (indented 2+ spaces)
            lines.append(f"[bright_black]{row}[/bright_black]")
        else:
            # sprite body character art
            lines.append(f"[bold blue]{row}[/bold blue]")

    if status_line:
        lines.append("")
        lines.append(f"[bright_black]{status_line}[/bright_black]")

    return "\n".join(lines)
