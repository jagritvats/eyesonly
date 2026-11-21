"""Render assets/demo.gif from real `npm run demo` output (CI run 44937445678)."""
import sys
from PIL import Image, ImageDraw, ImageFont

OUT = sys.argv[1]
W, H = 900, 440
SCALE = 1
BG, BG2, LINE = (11, 13, 16), (17, 21, 26), (31, 38, 46)
TEXT, DIM = (230, 233, 237), (139, 150, 163)
MINT, BLUE, RED, YEL = (126, 224, 181), (138, 180, 255), (255, 123, 114), (227, 196, 107)

F = "C:/Windows/Fonts/CascadiaMono.ttf"
font = ImageFont.truetype(F, 15)
fontb = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 16)
title_font = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 13)
big = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 30)
mid = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 18)
CW = font.getlength("M")
LH = 24
X0, Y0 = 28, 64
COLS = int((W - 2 * X0) // CW)

# Each scene: (caption, [items]); item = ("cmd", who, text) | ("out", color, text) | ("gap",)
SCENES = [
    ("1/5  same repo, same file", [
        ("cmd", "alice", "cat .env"),
        ("out", MINT, "STRIPE_SECRET=sk_live_51H_demo"),
        ("gap",),
        ("cmd", "junior", "cat .env | head -c 60"),
        ("out", YEL, 'EYESONLY-V1 {  "v": 1,  "path": ".env",  "signer": "alice", …'),
        ("cmd", "junior", "git status --short"),
        ("out", DIM, "(clean)"),
    ]),
    ("2/5  private branches are invisible", [
        ("cmd", "alice", "git ls-remote origin"),
        ("out", DIM, "789bccdc…  HEAD"),
        ("out", DIM, "789bccdc…  refs/heads/main"),
        ("out", BLUE, "912c451c…  refs/heads/private/launch"),
        ("gap",),
        ("cmd", "junior", "git ls-remote origin"),
        ("out", DIM, "789bccdc…  HEAD"),
        ("out", DIM, "789bccdc…  refs/heads/main"),
        ("cmd", "junior", "git -c protocol.version=2 fetch origin 912c451c…   # learned the sha"),
        ("out", RED, "error: Server does not allow request for unadvertised object 912c451c6fc27abac2956d064dde1ba4f4f15ff4"),
    ]),
    ("3/5  the server enforces it, not the client", [
        ("cmd", "junior", "echo DB_PASS=oops > .env && git add .env"),
        ("out", RED, "[eyesonly] 'junior' is not allowed to write '.env' (allowed: alice)"),
        ("gap",),
        ("note", "junior disables the client filter and tries anyway:"),
        ("cmd", "junior", "git -c filter.eyesonly.clean=cat commit -am leak && git push"),
        ("out", RED, "[eyesonly] REJECTED: 'junior' may not modify protected file '.env' (43a4c051)"),
    ]),
    ("4/5  private history can't leak into main", [
        ("cmd", "alice", "git merge private/launch && git push"),
        ("out", RED, "[eyesonly] REJECTED: pushing 'refs/heads/main' would expose commit 912c451c from a branch with a narrower audience. Use `git merge --squash`."),
        ("gap",),
        ("cmd", "alice", "git merge --squash private/launch && git commit && git push"),
        ("out", MINT, "accepted: only the squashed content goes public, not the private history"),
    ]),
]

PROMPT = {"alice": MINT, "junior": YEL}


def wrap(s, n):
    out = []
    while len(s) > n:
        cut = s.rfind(" ", 0, n)
        if cut <= n // 2:
            cut = n
        out.append(s[:cut])
        s = s[cut:].lstrip(" ")
    out.append(s)
    return out


def chrome(d, caption):
    d.rounded_rectangle([10, 10, W - 11, H - 11], radius=12, fill=BG2, outline=LINE)
    d.line([10, 44, W - 11, 44], fill=LINE)
    for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
        d.ellipse([28 + i * 20, 22, 40 + i * 20, 34], fill=c)
    t = "eyesonly demo  ·  stock git client"
    d.text((W / 2 - title_font.getlength(t) / 2, 19), t, font=title_font, fill=DIM)
    if caption:
        d.text((W - 28 - font.getlength(caption), H - 40), caption, font=font, fill=DIM)


def render(lines, caption, cursor=None):
    """lines: list of list-of-(text,color) segments."""
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    chrome(d, caption)
    y = Y0
    for segs in lines:
        x = X0
        for text, color, *b in segs:
            f = fontb if b else font
            d.text((x, y), text, font=f, fill=color)
            x += f.getlength(text)
        y += LH
    if cursor:
        cx, cy = cursor
        d.rectangle([cx, cy + 3, cx + CW - 1, cy + LH - 3], fill=TEXT)
    return im


frames, durs = [], []


def add(im, ms):
    frames.append(im)
    durs.append(ms)


for caption, items in SCENES:
    lines = []
    for it in items:
        kind = it[0]
        if kind == "gap":
            lines.append([])
            continue
        if kind == "note":
            lines.append([("# " + it[1], DIM)])
            add(render(lines, caption), 900)
            continue
        if kind == "cmd":
            who, cmd = it[1], it[2]
            p = f"{who}$ "
            # type the command, 3 chars per frame
            for i in range(0, len(cmd) + 4, 4):
                cur = [(p, PROMPT[who], 1), (cmd[:min(i, len(cmd))], TEXT)]
                x = X0 + font.getlength(p + cmd[:min(i, len(cmd))])
                add(render(lines + [cur], caption, cursor=(x, Y0 + len(lines) * LH)), 35)
            lines.append([(p, PROMPT[who], 1), (cmd, TEXT)])
            add(render(lines, caption), 350)
            continue
        if kind == "out":
            color, text = it[1], it[2]
            for w in wrap(text, COLS):
                lines.append([(w, color)])
            hold = 1900 if color in (RED, MINT) else 700
            add(render(lines, caption), hold)
    durs[-1] = 2600

# outro
im = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(im)
chrome(d, "5/5")
t1 = "That was the stock git client the whole time."
d.text((W / 2 - big.getlength(t1) / 2, 130), t1, font=big, fill=TEXT)
t2 = "Private files · private branches · built-in secrets · enforced by the server"
d.text((W / 2 - mid.getlength(t2) / 2, 185), t2, font=mid, fill=DIM)
t3 = "$ npx eyesonly demo"
d.rounded_rectangle([W / 2 - 150, 240, W / 2 + 150, 286], radius=8, fill=BG, outline=LINE)
d.text((W / 2 - font.getlength(t3) / 2, 252), t3, font=font, fill=MINT)
logo = "eyesonly"
lf = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 26)
lx = W / 2 - (lf.getlength(logo + ".")) / 2
d.text((lx, 320), logo, font=lf, fill=TEXT)
d.text((lx + lf.getlength(logo), 320), ".", font=lf, fill=MINT)
add(im, 3500)

# quantize all frames to one shared palette for small, flicker-free output
keys = [f for f, ms in zip(frames, durs) if ms >= 1900]
pal_src = Image.new("RGB", (W, H * len(keys)))
for i, f in enumerate(keys):
    pal_src.paste(f, (0, H * i))
pal = pal_src.quantize(colors=64, method=Image.Quantize.MEDIANCUT)
q = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
q[0].save(OUT, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True, disposal=1)
print(f"{len(frames)} frames, {sum(durs)/1000:.1f}s")
