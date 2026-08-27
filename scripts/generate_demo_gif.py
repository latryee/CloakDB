"""Automated local terminal demo GIF generator for CloakDB.

Renders high-resolution terminal frames simulating CLI commands and outputs,
and compiles them into an animated assets/demo.gif using Pillow.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont
from typer.testing import CliRunner

from cloakdb.cli import app

# Palette: Catppuccin Mocha
BG_COLOR = (30, 30, 46)  # #1e1e2e
TOPBAR_COLOR = (24, 24, 37)  # #181825
TEXT_WHITE = (205, 214, 244)  # #cdd6f4
TEXT_GREEN = (166, 227, 161)  # #a6e3a1
TEXT_CYAN = (137, 220, 235)  # #89dceb
TEXT_YELLOW = (249, 226, 175)  # #f9e2af
TEXT_BLUE = (137, 180, 250)  # #89b4fa
TEXT_DIM = (108, 112, 134)  # #6c7086
BORDER_COLOR = (49, 50, 68)  # #313244

WIDTH = 1200
HEIGHT = 760
PADDING = 30
TOPBAR_HEIGHT = 42


def _get_font(size: int = 15) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for font_name in ["consola.ttf", "DejaVuSansMono.ttf", "Courier New.ttf", "arial.ttf"]:
        try:
            return ImageFont.truetype(font_name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _draw_terminal_base() -> tuple[Image.Image, ImageDraw.ImageDraw, Any]:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Top bar
    draw.rectangle([(0, 0), (WIDTH, TOPBAR_HEIGHT)], fill=TOPBAR_COLOR)
    draw.line([(0, TOPBAR_HEIGHT), (WIDTH, TOPBAR_HEIGHT)], fill=BORDER_COLOR, width=1)

    # Window buttons
    draw.ellipse([(20, 14), (32, 26)], fill=(243, 139, 168))  # Red
    draw.ellipse([(40, 14), (52, 26)], fill=(249, 226, 175))  # Yellow
    draw.ellipse([(60, 14), (72, 26)], fill=(166, 227, 161))  # Green

    # Window title
    font_title = _get_font(13)
    draw.text((WIDTH // 2 - 80, 12), "cloakdb — bash — 1200x760", fill=TEXT_DIM, font=font_title)

    font_body = _get_font(14)
    return img, draw, font_body


def _render_command_scene(
    command_str: str,
    output_lines: list[str],
) -> list[tuple[Image.Image, int]]:
    """Generates frames for typing a command and viewing its output."""
    frames: list[tuple[Image.Image, int]] = []
    line_height = 20
    start_y = TOPBAR_HEIGHT + 20

    # 1. Typing animation frames
    prompt_prefix = "user@cloakdb:~$ "
    for i in range(1, len(command_str) + 1, max(1, len(command_str) // 8)):
        img, draw, font = _draw_terminal_base()
        typed_part = command_str[:i]

        draw.text((PADDING, start_y), prompt_prefix, fill=TEXT_GREEN, font=font)
        p_len = int(draw.textlength(prompt_prefix, font=font))
        draw.text((PADDING + p_len, start_y), typed_part, fill=TEXT_CYAN, font=font)

        # Draw cursor
        c_len = int(draw.textlength(typed_part, font=font))
        draw.rectangle(
            [
                (PADDING + p_len + c_len + 2, start_y + 2),
                (PADDING + p_len + c_len + 10, start_y + 16),
            ],
            fill=TEXT_WHITE,
        )
        frames.append((img, 80))

    # 2. Output frames
    img, draw, font = _draw_terminal_base()
    draw.text((PADDING, start_y), prompt_prefix, fill=TEXT_GREEN, font=font)
    p_len = int(draw.textlength(prompt_prefix, font=font))
    draw.text((PADDING + p_len, start_y), command_str, fill=TEXT_CYAN, font=font)

    current_y = start_y + line_height + 8
    max_visible_lines = (HEIGHT - current_y - PADDING) // line_height

    for line in output_lines[:max_visible_lines]:
        clean_line = line.rstrip()
        color = TEXT_WHITE
        if (
            clean_line.startswith("┌")
            or clean_line.startswith("├")
            or clean_line.startswith("└")
            or clean_line.startswith("│")
        ):
            color = TEXT_BLUE
        elif "[OK]" in clean_line or "[+]" in clean_line or "Successfully" in clean_line:
            color = TEXT_GREEN
        elif "Table:" in clean_line or "Benchmark" in clean_line or "Execution" in clean_line:
            color = TEXT_YELLOW
        elif "Tip:" in clean_line or "Scanning" in clean_line or "Previewing" in clean_line:
            color = TEXT_DIM

        draw.text((PADDING, current_y), clean_line, fill=color, font=font)
        current_y += line_height

    # Hold the completed output frame
    frames.append((img, 2800))
    return frames


def build_demo_gif(output_path: Path) -> None:
    runner = CliRunner()
    all_frames: list[Image.Image] = []
    durations: list[int] = []

    commands = [
        ("cloakdb scan examples/sample_postgres.sql", ["scan", "examples/sample_postgres.sql"]),
        (
            "cloakdb preview -c examples/cloakdb.example.yaml -i examples/sample_postgres.sql",
            [
                "preview",
                "-c",
                "examples/cloakdb.example.yaml",
                "-i",
                "examples/sample_postgres.sql",
            ],
        ),
        (
            "cloakdb apply -c examples/cloakdb.example.yaml -i examples/sample_postgres.sql -o masked.sql --workers 4",
            [
                "apply",
                "-c",
                "examples/cloakdb.example.yaml",
                "-i",
                "examples/sample_postgres.sql",
                "-o",
                "masked.sql",
                "--workers",
                "4",
            ],
        ),
        ("cloakdb bench --rows 10000", ["bench", "--rows", "10000"]),
    ]

    for display_cmd, args in commands:
        res = runner.invoke(app, args)
        lines = res.stdout.splitlines()
        scene_frames = _render_command_scene(display_cmd, lines)
        for frame, dur in scene_frames:
            all_frames.append(frame)
            durations.append(dur)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if all_frames:
        all_frames[0].save(
            output_path,
            save_all=True,
            append_images=all_frames[1:],
            duration=durations,
            loop=0,
            optimize=True,
        )
        print(
            f"[OK] Successfully rendered animated demo GIF to {output_path} ({len(all_frames)} frames)"
        )


if __name__ == "__main__":
    out_file = Path(__file__).parent.parent / "assets" / "demo.gif"
    build_demo_gif(out_file)
