"""Pola loreng hutan orisinal, tile mulus (seamless), dihasilkan prosedural. Bukan salinan motif resmi."""
import math, random
random.seed(1945)
W = H = 480
BASE = "#3d4a2c"
LAYERS = [("#56633a", 26, 40, 70), ("#5a4630", 22, 30, 58), ("#26301c", 20, 26, 50), ("#17190f", 18, 14, 30)]

def blob(cx, cy, r):
    n = random.randint(7, 11)
    rot = random.random() * math.pi
    sx = random.uniform(1.0, 2.2)
    pts = []
    for i in range(n):
        a = 2 * math.pi * i / n
        rr = r * random.uniform(0.55, 1.15)
        x, y = rr * math.cos(a) * sx, rr * math.sin(a)
        pts.append((cx + x * math.cos(rot) - y * math.sin(rot), cy + x * math.sin(rot) + y * math.cos(rot)))
    # Catmull-Rom -> Bezier tertutup (tepi halus)
    d = f"M{pts[0][0]:.1f},{pts[0][1]:.1f}"
    for i in range(n):
        p0, p1, p2, p3 = pts[i - 1], pts[i], pts[(i + 1) % n], pts[(i + 2) % n]
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6)
        d += f"C{c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}"
    return d + "Z"

out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       f'<rect width="{W}" height="{H}" fill="{BASE}"/>']
for col, n, rmin, rmax in LAYERS:
    ds = []
    for _ in range(n):
        cx, cy, r = random.uniform(0, W), random.uniform(0, H), random.uniform(rmin, rmax)
        d = blob(0, 0, r)
        for ox in (-W, 0, W):          # salin ke tepi agar tile menyambung mulus
            for oy in (-H, 0, H):
                if -2.4 * r < cx + ox < W + 2.4 * r and -2.4 * r < cy + oy < H + 2.4 * r:
                    ds.append(f'<path transform="translate({cx + ox:.1f} {cy + oy:.1f})" d="{d}"/>')
    out.append(f'<g fill="{col}">' + "".join(ds) + "</g>")
out.append("</svg>")
open("loreng.svg", "w").write("\n".join(out))
