"""Show ECB pattern leakage with the lab's toy cipher (not AES).

Install: python3 -m pip install matplotlib numpy
Run: python3 penguin_demo.py
Save without a window: MPLBACKEND=Agg python3 penguin_demo.py --output penguin.png
"""
import argparse
import os

import matplotlib.pyplot as plt
import numpy as np

from modes import BS, cbc_encrypt, ecb_encrypt


def penguin():
    """Draw a simple RGB penguin with flat colors and no external image file."""
    y, x = np.mgrid[:240, :192]
    pixels = np.full((240, 192, 3), (180, 220, 245), dtype=np.uint8)

    def ellipse(cx, cy, rx, ry, color):
        mask = ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1
        pixels[mask] = color

    black, white, orange = (20, 20, 25), (250, 250, 245), (255, 170, 20)
    ellipse(62, 220, 31, 12, orange)
    ellipse(130, 220, 31, 12, orange)
    ellipse(46, 145, 22, 64, black)
    ellipse(146, 145, 22, 64, black)
    ellipse(96, 145, 57, 77, black)
    ellipse(96, 65, 43, 47, black)
    ellipse(96, 153, 40, 62, white)
    ellipse(80, 64, 15, 21, white)
    ellipse(112, 64, 15, 21, white)
    ellipse(83, 63, 5, 8, black)
    ellipse(109, 63, 5, 8, black)
    ellipse(96, 88, 19, 9, orange)
    return pixels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='Save the figure to this path.')
    args = parser.parse_args()

    original = penguin()
    raw = original.tobytes()
    key = os.urandom(16)
    iv = os.urandom(BS)  # Fresh IV; this toy cipher uses 3-byte blocks.
    encrypted = [ecb_encrypt(raw, key), cbc_encrypt(raw, key, iv)]
    # Each RGB pixel is 3 bytes, exactly one block in the lab's toy cipher.
    views = [original] + [
        np.frombuffer(data, dtype=np.uint8).reshape(original.shape)
        for data in encrypted
    ]
    fig, axes = plt.subplots(1, 3, figsize=(10, 5))
    for ax, view, title in zip(axes, views, ['Original', 'ECB', 'CBC']):
        ax.imshow(view, interpolation='nearest')
        ax.set_title(title)
        ax.axis('off')
    fig.suptitle('Toy cipher: 3-byte blocks (not AES)')
    fig.tight_layout()
    if args.output:
        fig.savefig(args.output, dpi=160)
    else:
        plt.show()
    plt.close(fig)


if __name__ == '__main__':
    main()
