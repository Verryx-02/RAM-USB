#!/usr/bin/env python3
"""Post-processing step for 09-security-trust-zones.svg only.

Two hand-drawn adjustments PlantUML/smetana can't do cleanly for this
file (see .claude/agent-memory/diagram-agent.md for the full history of
why - adding any node/edge that touches Headscale's rank re-solves the
whole canvas under smetana, even a fully disconnected node):

1. An orthogonal (3-segment, 2-corner, right-angle) line from UnauthUser
   to Headscale, representing CL-F-04 (the mesh join, using the pre-auth
   key from registration - the registered-but-not-logged-in user, per the
   SRS). Down from UnauthUser, right at 1cm below the legend's bottom
   edge, up into Headscale's horizontal center.
2. Re-centering the legend box under Mesh VPN Zone specifically (not the
   whole canvas, which is PlantUML's own default `legend` centering).

Both computed from the actual node/cluster coordinates PlantUML already
produced, avoiding the layout engine entirely for both adjustments.

Run this AFTER `make diagrams` regenerates the .svg from the .puml, every
time either changes:

    make diagrams
    python3 docs/design/diagrams/inject-cl-f-04-arc.py

Idempotent: safe to re-run, re-reads fresh coordinates each time and
replaces its own prior injection rather than stacking duplicates.
"""

import re
import sys
from pathlib import Path

SVG_PATH = Path(__file__).parent / "rendered" / "09-security-trust-zones.svg"
MARKER = "<!-- CL-F-04-ARC-INJECTED -->"

ARC_STROKE = "#333333"  # matches this diagram's other edges exactly


def node_bbox(svg: str, qualified_name: str) -> tuple[float, float, float, float]:
    """Return (min_x, min_y, max_x, max_y) for a node's polygon by its
    PlantUML qualified name (e.g. "Authenticated User Zone.AuthUser")."""
    idx = svg.find(f'data-qualified-name="{qualified_name}"')
    if idx == -1:
        raise ValueError(f"node not found in SVG: {qualified_name}")
    segment = svg[idx : idx + 600]
    match = re.search(r'points="([-\d.,\s]+)"', segment)
    if not match:
        raise ValueError(f"no polygon points found for: {qualified_name}")
    coords = [float(n) for n in match.group(1).replace(",", " ").split()]
    xs, ys = coords[0::2], coords[1::2]
    return min(xs), min(ys), max(xs), max(ys)


def cluster_left(svg: str, qualified_name: str) -> float:
    """Return the min (left) x of a package/cluster's border path."""
    idx = svg.find(f"cluster {qualified_name}--")
    if idx == -1:
        raise ValueError(f"cluster not found in SVG: {qualified_name}")
    segment = svg[idx : idx + 500]
    match = re.search(r'path d="M([\d.]+),', segment)
    return float(match.group(1))


def cluster_left_right(svg: str, qualified_name: str) -> tuple[float, float]:
    """Return (left, right) x of a package/cluster's border path."""
    idx = svg.find(f"cluster {qualified_name}--")
    if idx == -1:
        raise ValueError(f"cluster not found in SVG: {qualified_name}")
    segment = svg[idx : idx + 500]
    match = re.search(r'path d="([^"]+)"', segment)
    left = float(re.search(r"M([\d.]+),", match.group(1)).group(1))
    line_xs = re.findall(r"L([\d.]+),", match.group(1))
    right = max(float(x) for x in line_xs)
    return left, right


CM_TO_PX = 96 / 2.54  # standard CSS px-per-cm, consistent with earlier
# measurements this session (e.g. the ~2.6cm zone-to-mesh gap figures).


def main() -> None:
    svg = SVG_PATH.read_text()

    # Strip any previous injection so re-running this script is idempotent.
    svg = re.sub(
        rf"{re.escape(MARKER)}.*?<!-- /CL-F-04-ARC -->\n?",
        "",
        svg,
        flags=re.DOTALL,
    )

    ua_min_x, ua_min_y, ua_max_x, ua_max_y = node_bbox(
        svg, "Unauthenticated User Zone.UnauthUser"
    )
    hs_min_x, hs_min_y, hs_max_x, hs_max_y = node_bbox(svg, "Public Zone.Headscale")
    auth_left = cluster_left(svg, "Authenticated User Zone")
    mesh_left, mesh_right = cluster_left_right(svg, "Mesh VPN Zone")

    # --- 1. Re-center the legend box under Mesh VPN Zone -----------------
    # PlantUML's own `legend` centers on the whole canvas; the user wants
    # it centered specifically under Mesh VPN Zone instead. Shift the
    # existing rect + both text lines by the same dx, rather than
    # rebuilding the legend from scratch.
    legend_idx = svg.find('class="legend"')
    if legend_idx == -1:
        raise ValueError("legend not found in SVG")
    legend_end = svg.find("</g>", legend_idx) + len("</g>")
    legend_block = svg[legend_idx:legend_end]

    rect_match = re.search(
        r'<rect fill="#DDDDDD" height="([\d.]+)"[^>]*width="([\d.]+)" x="([\d.]+)" y="([\d.]+)"',
        legend_block,
    )
    legend_h, legend_w, legend_x, legend_y = (float(g) for g in rect_match.groups())
    mesh_center_x = (mesh_left + mesh_right) / 2
    legend_center_x = legend_x + legend_w / 2
    dx = mesh_center_x - legend_center_x

    def shift_x(m: re.Match) -> str:
        return f'x="{float(m.group(1)) + dx:.4f}"'

    # Negative lookbehind for a letter is required: a bare `x="..."`
    # pattern also matches inside `rx="..."` (the rect's corner radius),
    # which is NOT a coordinate and must never be shifted - confirmed live
    # (rx went 8 -> 47, i.e. +dx applied to a radius, producing the
    # pill-shaped/inconsistent corners the user flagged).
    new_legend_block = re.sub(r'(?<![a-zA-Z])x="([\d.]+)"', shift_x, legend_block)
    svg = svg[:legend_idx] + new_legend_block + svg[legend_end:]

    legend_bottom_y = legend_y + legend_h  # unaffected by the x-shift

    # --- 2. Orthogonal (right-angle) line, UnauthUser -> Headscale -------
    # Start left of Authenticated User Zone's own left border, so the
    # vertical drop doesn't cut through that box on the way down.
    start_x = min(ua_min_x + (ua_max_x - ua_min_x) * 0.25, auth_left - 20.0)
    start_y = ua_max_y  # UnauthUser's bottom edge

    turn_y = legend_bottom_y + 1.0 * CM_TO_PX  # 1cm below the legend's
    # (re-centered) bottom edge - x-shift above doesn't move legend_y/h.

    end_x = (hs_min_x + hs_max_x) / 2  # Headscale's horizontal center
    end_y = hs_max_y  # Headscale's bottom edge, arriving from below

    arrowhead_len = 9.0
    arrowhead_half_width = 4.5
    notch_len = 4.0
    path_end_y = end_y + notch_len  # path stops at the arrowhead's back
    # notch, matching PlantUML's own arrow convention (verified against an
    # existing edge in this same file's rendered SVG).

    # Three straight segments, two 90-degree corners: down from UnauthUser,
    # right to Headscale's center x, up into Headscale.
    path_d = (
        f"M {start_x:.4f},{start_y:.4f} "
        f"L {start_x:.4f},{turn_y:.4f} "
        f"L {end_x:.4f},{turn_y:.4f} "
        f"L {end_x:.4f},{path_end_y:.4f}"
    )
    arrowhead_points = (
        f"{end_x:.4f},{end_y:.4f},"
        f"{end_x - arrowhead_half_width:.4f},{end_y + arrowhead_len:.4f},"
        f"{end_x:.4f},{end_y + notch_len:.4f},"
        f"{end_x + arrowhead_half_width:.4f},{end_y + arrowhead_len:.4f},"
        f"{end_x:.4f},{end_y:.4f}"
    )

    injected = (
        f'{MARKER}\n'
        f'<path d="{path_d}" fill="none" '
        f'style="stroke:{ARC_STROKE};stroke-width:1;"/>\n'
        f'<polygon fill="{ARC_STROKE}" points="{arrowhead_points}" '
        f'style="stroke:{ARC_STROKE};stroke-width:1;'
        f'stroke-linejoin:miter;stroke-miterlimit:10;"/>\n'
        f'<!-- /CL-F-04-ARC -->\n'
    )

    # Insert right before </svg>.
    svg = svg.replace("</svg>", injected + "</svg>")

    # Grow the canvas to fit the turn (plus a small margin), since the
    # line's horizontal segment now falls well past the diagram's
    # original bottom edge.
    needed_height = turn_y + 20
    width_match = re.search(r'width="(\d+)px"', svg)
    height_match = re.search(r'height="(\d+)px"', svg)
    orig_width = int(width_match.group(1))
    orig_height = int(height_match.group(1))
    new_height = max(orig_height, round(needed_height))

    if new_height != orig_height:
        svg = svg.replace(f'height="{orig_height}px"', f'height="{new_height}px"', 1)
        svg = svg.replace(
            f"height:{orig_height}px", f"height:{new_height}px", 1
        )
        svg = svg.replace(
            f'viewBox="0 0 {orig_width} {orig_height}"',
            f'viewBox="0 0 {orig_width} {new_height}"',
            1,
        )

    SVG_PATH.write_text(svg)
    print(
        f"Injected CL-F-04 line: UnauthUser({start_x:.0f},{start_y:.0f}) -> "
        f"turn({turn_y:.0f}) -> Headscale({end_x:.0f},{end_y:.0f}); "
        f"legend shifted dx={dx:+.1f} (center now {mesh_center_x:.0f}, "
        f"matching Mesh VPN Zone); canvas height {orig_height}px -> {new_height}px"
    )


if __name__ == "__main__":
    sys.exit(main())
