import re


SVG_BADGE = """<svg xmlns="http://www.w3.org/2000/svg" width="99" height="20">
    <linearGradient id="a" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <rect rx="3" width="99" height="20" fill="#555"/>
    <rect rx="3" x="63" width="36" height="20" fill="{color}"/>
    <path fill="{color}" d="M63 0h4v20h-4z"/>
    <rect rx="3" width="99" height="20" fill="url(#a)"/>
    <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
        <text x="32.5" y="15" fill="#010101" fill-opacity=".3">coverage</text>
        <text x="32.5" y="14">coverage</text>
        <text x="80" y="15" fill="#010101" fill-opacity=".3">{coverage}%</text>
        <text x="80" y="14">{coverage}%</text>
    </g>
</svg>"""


def render_badge(coverage: int, coverage_ok: bool) -> bytes:
    """
    Helper to render SVG coverage badge
    :param coverage: coverage percentage
    :param coverage_ok: good / bad coverage (green / red background, or orange if coverage is undefined (equals 0))
    :return: bytes
    """
    if coverage == 0:
        color = '#BA5106'
    elif coverage_ok:
        color = '#15BA06'
    else:
        color = '#F02E2E'
    return re.sub(r'\n[\s]*', '', SVG_BADGE.format(coverage=coverage, color=color)).encode(encoding='utf-8')
