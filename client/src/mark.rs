// The application mark, drawn in code — and the only place its geometry exists.
//
// It is the site's `favicon.svg` — a rounded dark tile, a ring, four satellites and a hub joined
// by spokes, all in the Nova gradient from `--link #58a6ff` to `--accent #a371f7`. Reproduced
// here as arithmetic rather than shipped as a file so that one binary stays one file, the
// on/off pair cannot drift apart, and every size is rendered rather than resampled.
//
// Everything is computed in the SVG's own 64-unit space and scaled at the end, which is what
// lets the same code produce a 32-pixel tray icon and a 256-pixel window icon from one set of
// coordinates.
//
// THIS FILE HAS NO DEPENDENCIES ON PURPOSE, AND `build.rs` `include!`s IT. The Windows shell
// cannot ask a running process what a program looks like: Explorer, the Start menu, the Alt-Tab
// list and the "Apps & features" entry all read an icon *resource* out of the file on disk, which
// has to exist before the process does. So the same rasteriser produces the runtime icons through
// `icon.rs` and, at build time, the `.ico` that gets linked into the executable. A second copy of
// the geometry for the resource is exactly the drift the mark was drawn in code to avoid.
//
// The comments here are `//` and not `//!` for that reason: a doc comment is an inner attribute,
// and an inner attribute arriving through a macro expansion — which is what `include!` is — does
// not compile.

/// Supersampling factor. A 16-pixel ring without it reads as a smudge.
const SS: usize = 4;

/// Protection ON. Brighter than the site's own `--link`/`--accent` on purpose: those are text
/// colours on a dark PAGE, and this is a 16-pixel glyph sitting in a notification area next to
/// Windows' own icons, which are near-white. At that size the eye reads luminance long before it
/// reads hue, so the pair below is the site's gradient lifted into the range where the mark is
/// still ours and still legible against a dark taskbar.
const GRAD_FROM: [u8; 3] = [0x8c, 0xcc, 0xff];
const GRAD_TO: [u8; 3] = [0xc6, 0xa2, 0xff];
/// `--bg-color`: the tile, so the mark reads on both light and dark taskbars.
const TILE: [u8; 3] = [0x0d, 0x11, 0x17];
/// Protection off — the same mark with the colour taken out of it. Deliberately NOT brightened:
/// the whole signal is that one state is vivid and the other is not, and lifting both would keep
/// the icon dim in exactly the state the user needs to notice.
const OFF_FROM: [u8; 3] = [0x6e, 0x76, 0x81];
const OFF_TO: [u8; 3] = [0x8b, 0x94, 0x9e];

/// Stroke weights, in the 64-unit space. Everything here was ~15% thinner and the ring came out at
/// 0.75 device pixels in a 16-pixel tray icon — below the point where anti-aliasing turns a line
/// into a grey suggestion of one. Thicker is the other half of "brighter": a bright colour spread
/// over less than a pixel is still grey.
const RING_R: f32 = 20.0;
const RING_HALF: f32 = 1.8;
const HUB_R: f32 = 6.6;
const NODE_R: f32 = 4.5;
const SPOKE_HALF: f32 = 1.5;

/// The sizes that go into the embedded `.ico`.
///
/// 16 through 48 are the ones Windows actually picks for a Start-menu tile, a taskbar button and a
/// details-view row; 128 and 256 exist because Explorer's "extra large icons" upscales whatever it
/// finds, and an upscaled 48 is visibly soft. Rendering each one rather than resampling is free
/// here — this runs once, at build time.
pub const ICO_SIZES: [usize; 6] = [16, 32, 48, 64, 128, 256];

/// Squared distance in the 64-unit space.
fn dist(x: f32, y: f32, cx: f32, cy: f32) -> f32 {
    ((x - cx).powi(2) + (y - cy).powi(2)).sqrt()
}

/// Coverage of the rounded tile: `rect(0,0,64,64) rx=14`.
fn in_tile(x: f32, y: f32) -> bool {
    const R: f32 = 14.0;
    let cx = x.clamp(R, 64.0 - R);
    let cy = y.clamp(R, 64.0 - R);
    // Inside the inset rectangle the clamp is a no-op and the distance is zero; only near a
    // corner does it become the corner's own radius test.
    dist(x, y, cx, cy) <= R
}

/// Coverage of the mark itself — everything drawn in the gradient.
fn in_mark(x: f32, y: f32) -> bool {
    const C: f32 = 32.0;
    // Four satellites at N/E/S/W, r=4; hub r=6.
    let nodes = [(32.0, 12.0), (52.0, 32.0), (32.0, 52.0), (12.0, 32.0)];
    for (nx, ny) in nodes {
        if dist(x, y, nx, ny) <= NODE_R {
            return true;
        }
    }
    if dist(x, y, C, C) <= HUB_R {
        return true;
    }
    // The ring.
    let d = dist(x, y, C, C);
    if (d - RING_R).abs() <= RING_HALF {
        return true;
    }
    // Spokes: hub to each satellite. Axis-aligned, so a box test is exact and there is no reason
    // to solve for the distance to a segment.
    let on_v = (x - C).abs() <= SPOKE_HALF && (12.0..=52.0).contains(&y);
    let on_h = (y - C).abs() <= SPOKE_HALF && (12.0..=52.0).contains(&x);
    on_v || on_h
}

/// The gradient the SVG declares: linear, top-left to bottom-right.
fn gradient(x: f32, y: f32, from: [u8; 3], to: [u8; 3]) -> [u8; 3] {
    let t = ((x + y) / 128.0).clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
    [
        mix(from[0], to[0]),
        mix(from[1], to[1]),
        mix(from[2], to[2]),
    ]
}

/// `size * size` pixels, RGBA, top row first.
pub fn rgba(size: usize, active: bool) -> Vec<u8> {
    let (from, to) = if active {
        (GRAD_FROM, GRAD_TO)
    } else {
        (OFF_FROM, OFF_TO)
    };
    let scale = 64.0 / (size * SS) as f32;

    let mut out = vec![0u8; size * size * 4];
    for py in 0..size {
        for px in 0..size {
            // Accumulate in floating point over the subsamples: averaging colour and coverage
            // separately is what keeps the ring's edge from picking up a dark halo.
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = ((px * SS + sx) as f32 + 0.5) * scale;
                    let y = ((py * SS + sy) as f32 + 0.5) * scale;
                    if !in_tile(x, y) {
                        continue;
                    }
                    let c = if in_mark(x, y) {
                        gradient(x, y, from, to)
                    } else {
                        TILE
                    };
                    r += c[0] as f32;
                    g += c[1] as f32;
                    b += c[2] as f32;
                    a += 1.0;
                }
            }

            let i = (py * size + px) * 4;
            if a > 0.0 {
                out[i] = (r / a).round() as u8;
                out[i + 1] = (g / a).round() as u8;
                out[i + 2] = (b / a).round() as u8;
                out[i + 3] = (a / (SS * SS) as f32 * 255.0).round() as u8;
            }
        }
    }
    out
}

// =================================================================================================
// The `.ico` a Windows shortcut needs
// =================================================================================================

/// A multi-size `.ico`, ready to be handed to the resource compiler.
///
/// Each image is a 32-bit BGRA DIB rather than a PNG. PNG entries are legal from Vista on and
/// would be a good deal smaller, but they would mean an encoder — a build dependency, a second
/// format to get right, and a failure mode that only shows up as a blank icon on somebody else's
/// machine. Uncompressed DIBs are ~370 KB inside a 10 MB binary and are what every Windows since
/// 95 reads.
pub fn ico(sizes: &[usize]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes.iter().map(|&s| dib(s)).collect();

    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // 1 = icon
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());

    // Directory entries are fixed width, so every image offset is known before a byte of image
    // data is written.
    let mut offset = 6 + 16 * sizes.len();
    for (&size, image) in sizes.iter().zip(&images) {
        // 256 does not fit in a byte and is spelled 0 — the one wart in the format.
        let dim = if size >= 256 { 0u8 } else { size as u8 };
        out.push(dim); // width
        out.push(dim); // height
        out.push(0); // palette size; 0 for a true-colour image
        out.push(0); // reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // colour planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&(image.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += image.len();
    }
    for image in images {
        out.extend_from_slice(&image);
    }
    out
}

/// One icon image: `BITMAPINFOHEADER`, the colour bitmap, then the 1-bit AND mask.
///
/// Two details are easy to get wrong and produce an icon that is merely upside down or invisible.
/// The header's height is **doubled**, because it describes the colour bitmap and the mask
/// together; and both bitmaps are stored bottom-up, the reverse of how [`rgba`] hands them over.
/// The mask is redundant for a 32-bit image — the alpha channel already says what is transparent —
/// but it is not optional, and a renderer old enough to use it should get the right answer.
fn dib(size: usize) -> Vec<u8> {
    let pixels = rgba(size, true);
    let mask_stride = size.div_ceil(32) * 4;

    let mut out = Vec::with_capacity(40 + size * size * 4 + mask_stride * size);
    out.extend_from_slice(&40u32.to_le_bytes()); // biSize
    out.extend_from_slice(&(size as i32).to_le_bytes()); // biWidth
    out.extend_from_slice(&((size * 2) as i32).to_le_bytes()); // biHeight: colour + mask
    out.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    out.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    out.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
    out.extend_from_slice(&((size * size * 4 + mask_stride * size) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // biXPelsPerMeter
    out.extend_from_slice(&0u32.to_le_bytes()); // biYPelsPerMeter
    out.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    out.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    for row in (0..size).rev() {
        for col in 0..size {
            let i = (row * size + col) * 4;
            out.push(pixels[i + 2]); // B
            out.push(pixels[i + 1]); // G
            out.push(pixels[i]); // R
            out.push(pixels[i + 3]); // A
        }
    }

    for row in (0..size).rev() {
        let mut line = vec![0u8; mask_stride];
        for col in 0..size {
            // A set bit means "leave the screen alone here", i.e. transparent. Most significant
            // bit first, which is the opposite of how a byte is usually indexed.
            if pixels[(row * size + col) * 4 + 3] == 0 {
                line[col / 8] |= 0x80 >> (col % 8);
            }
        }
        out.extend_from_slice(&line);
    }
    out
}
