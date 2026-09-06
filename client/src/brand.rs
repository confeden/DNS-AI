//! What the window is made of that is not a screen: the machine's own fonts, the wordmark, and
//! the one control this program is mostly made of.
//!
//! All three exist because the defaults were wrong for this program specifically. egui's bundled
//! fonts are not Windows' fonts, so the client looked like a port of something; a wordmark with a
//! gradient cannot be a label, because a label has one colour; and a checkbox in a dark theme is a
//! small grey square that reads as disabled.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eframe::egui;

/// `--fg-3` from the site. Hints and disabled labels.
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x7b, 0x84, 0x94);
/// `--fg`.
const TEXT: egui::Color32 = egui::Color32::from_rgb(0xe8, 0xec, 0xf3);
/// `--accent`, for fills. The switch's track when it is on.
const PRIMARY: egui::Color32 = egui::Color32::from_rgb(0x5b, 0x8c, 0xff);
/// The track when it is off — `--line-strong` over the card, so an off switch reads as part of it.
const TRACK_OFF: egui::Color32 = egui::Color32::from_rgb(0x30, 0x36, 0x3d);
/// `--ok`. The one green on the screen, and it says «рекомендуется».
const OK: egui::Color32 = egui::Color32::from_rgb(0x7e, 0xe2, 0xb8);
/// Between the label and the badge.
const BADGE_GAP: f32 = 8.0;
/// `--surface-1`. What the front sheet of the copy icon is filled with, so the sheet behind it stops
/// where it should.
const PANEL_BEHIND: egui::Color32 = egui::Color32::from_rgb(0x16, 0x1b, 0x22);

/// The wordmark's two gradients, verbatim from the landing page's `.logo` rule:
/// `DNS-AI` is `linear-gradient(100deg,#58a6ff 0%,#7ea6ff 45%,#a371f7 100%)` and the `.RU` suffix
/// carries its own, `linear-gradient(100deg,#a371f7,#7ee2b8)` — which is what makes the mark read
/// as the site's rather than as a blue word with a grey tail.
const BRAND_STOPS: [(f32, [f32; 3]); 3] = [
    (0.00, [0x58 as f32, 0xa6 as f32, 0xff as f32]),
    (0.45, [0x7e as f32, 0xa6 as f32, 0xff as f32]),
    (1.00, [0xa3 as f32, 0x71 as f32, 0xf7 as f32]),
];
const TLD_STOPS: [(f32, [f32; 3]); 2] = [
    (0.00, [0xa3 as f32, 0x71 as f32, 0xf7 as f32]),
    (1.00, [0x7e as f32, 0xe2 as f32, 0xb8 as f32]),
];

/// The colour a multi-stop gradient has at `t` ∈ [0, 1].
fn gradient(stops: &[(f32, [f32; 3])], t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let mut span = (stops[0], stops[stops.len() - 1]);
    for pair in stops.windows(2) {
        if t >= pair[0].0 && t <= pair[1].0 {
            span = (pair[0], pair[1]);
            break;
        }
    }
    let ((from_at, from), (to_at, to)) = span;
    let local = if (to_at - from_at).abs() < f32::EPSILON {
        0.0
    } else {
        (t - from_at) / (to_at - from_at)
    };
    let c = |i: usize| egui::lerp(from[i]..=to[i], local).round() as u8;
    egui::Color32::from_rgb(c(0), c(1), c(2))
}

/// Proportional faces, best first. Segoe UI Semibold is what Windows 11 sets its own settings
/// rows in; the rest are what a machine has if it does not have that.
const PROPORTIONAL: [&str; 4] = ["seguisb.ttf", "segoeui.ttf", "tahoma.ttf", "arial.ttf"];

/// Loads the machine's own fonts and hands them to egui.
///
/// The binary embeds none: eframe is built without `default_fonts`, which is ~2 MB of Ubuntu, Hack
/// and two emoji faces in a program that is already large and unsigned by a root anybody trusts.
/// Reading Segoe UI off the disk costs a few milliseconds at start-up and is also what makes the
/// window look like the settings screen next to it.
///
/// **The first face that reads wins, and the rest are not read at all.** A fallback chain is what
/// egui expects, and it would buy nothing here: the list below is four Latin+Cyrillic faces, so a
/// glyph missing from Segoe UI is missing from all of them. What it would cost is real — three
/// more files of about 700 KB each, read and parsed at every start, for a window with six switches
/// on it.
///
/// **If nothing at all could be read it returns without touching the context**, because handing
/// egui an empty font set is a panic rather than a window with no text.
pub fn install_fonts(ctx: &egui::Context) {
    let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
    let dir = PathBuf::from(windir).join("Fonts");

    let mut defs = egui::FontDefinitions::empty();
    let proportional = first_that_reads(&mut defs, &dir, &PROPORTIONAL);
    // Consolas for the addresses, which are the only monospaced text on the screen. A machine
    // without it falls back to the proportional face: misaligned columns beat missing text.
    let monospace = first_that_reads(&mut defs, &dir, &["consola.ttf", "lucon.ttf"])
        .or_else(|| proportional.clone());

    let Some(body) = proportional.clone().or_else(|| monospace.clone()) else {
        log::error!(
            "no system font could be read from {} — keeping egui's own",
            dir.display()
        );
        return;
    };
    log::debug!("fonts: proportional={body}, monospace={monospace:?}");

    defs.families
        .insert(egui::FontFamily::Proportional, vec![body.clone()]);
    defs.families
        .insert(egui::FontFamily::Monospace, vec![monospace.unwrap_or(body)]);
    ctx.set_fonts(defs);
}

/// Reads the first of `names` that exists, and stops. Returns the key it was filed under.
fn first_that_reads(
    defs: &mut egui::FontDefinitions,
    dir: &Path,
    names: &[&str],
) -> Option<String> {
    for name in names {
        if defs.font_data.contains_key(*name) {
            return Some((*name).to_owned()); // Already read for another family.
        }
        match std::fs::read(dir.join(name)) {
            Ok(bytes) => {
                defs.font_data.insert(
                    (*name).to_owned(),
                    Arc::new(egui::FontData::from_owned(bytes)),
                );
                return Some((*name).to_owned());
            }
            Err(e) => log::debug!("{}: {e}", dir.join(name).display()),
        }
    }
    None
}

/// The wordmark: `DNS-AI` in the site's blue→violet gradient, `.RU` in its violet→green one.
///
/// Painted glyph by glyph because the gradient is the point — one `Label` carries one colour, and
/// the flat-blue version of this mark is not the one on the site. The glyphs are measured with the
/// plain font, so there is no letter-spacing; the site's is -.02em and it is not worth a second
/// layout pass to reproduce.
pub fn wordmark(ui: &mut egui::Ui, size: f32) {
    const BRAND: &str = "DNS-AI";
    const TLD: &str = ".RU";

    let font = egui::FontId::proportional(size);
    let (height, brand_widths, tld_widths) = ui.fonts_mut(|f| {
        let height = f.row_height(&font);
        let brand: Vec<f32> = BRAND.chars().map(|c| f.glyph_width(&font, c)).collect();
        let tld: Vec<f32> = TLD.chars().map(|c| f.glyph_width(&font, c)).collect();
        (height, brand, tld)
    });

    let brand_width: f32 = brand_widths.iter().sum();
    let tld_width: f32 = tld_widths.iter().sum();
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(brand_width + tld_width, height),
        egui::Sense::hover(),
    );

    let painter = ui.painter();
    let mut x = rect.min.x;
    // Each run carries its own gradient across its own width, exactly as the two CSS rules do.
    for (text, widths, run_width, stops) in [
        (BRAND, &brand_widths, brand_width, &BRAND_STOPS[..]),
        (TLD, &tld_widths, tld_width, &TLD_STOPS[..]),
    ] {
        let mut run = 0.0;
        for (c, w) in text.chars().zip(widths) {
            // Position along the run, taken at the glyph's centre so the first and last are not the
            // pure endpoint colours — the same thing a CSS gradient does across a text box.
            let t = if run_width > 0.0 {
                (run + w / 2.0) / run_width
            } else {
                0.0
            };
            painter.text(
                egui::pos2(x, rect.min.y),
                egui::Align2::LEFT_TOP,
                c,
                font.clone(),
                gradient(stops, t),
            );
            x += w;
            run += w;
        }
    }
}

/// The copy button: two overlapping rounded rectangles, painted rather than typed.
///
/// **A glyph was tried first and came out as a box.** `⧉` (U+29C9) is not in Segoe UI, and the icon
/// fonts that do have a copy symbol — Segoe MDL2 Assets, Segoe Fluent Icons — start at Windows 10,
/// which this program deliberately does not require. Sixteen pixels of geometry needs no font at
/// all and looks the same on every version.
pub fn copy_icon(ui: &mut egui::Ui) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
    let colour = if response.hovered() { TEXT } else { MUTED };
    let stroke = egui::Stroke::new(1.0, colour);
    let painter = ui.painter();
    // The sheet behind, offset up and left; then the one in front, drawn over it.
    let back = egui::Rect::from_min_size(
        rect.min + egui::vec2(2.0, 1.0),
        egui::vec2(8.0, 10.0),
    );
    let front = egui::Rect::from_min_size(
        rect.min + egui::vec2(5.5, 4.0),
        egui::vec2(8.0, 10.0),
    );
    painter.rect_stroke(back, 1.5, stroke, egui::StrokeKind::Inside);
    painter.rect_filled(front, 1.5, PANEL_BEHIND);
    painter.rect_stroke(front, 1.5, stroke, egui::StrokeKind::Inside);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// One settings row: a label, an optional line of explanation under it, and a switch at the right
/// edge. Returns `true` on the frame the user flipped it.
///
/// **The whole row is the control**, not the 40 px of switch. A switch is a small target, the text
/// beside it is what the eye is on, and every settings screen on this machine behaves that way.
///
/// The text is laid out into a galley at the width that is left over, so a hint wraps instead of
/// running under the switch — which is what painting a string straight onto the row would do.
pub fn switch(
    ui: &mut egui::Ui,
    value: &mut bool,
    label: &str,
    badge: Option<&str>,
    enabled: bool,
    hint: Option<&str>,
) -> bool {
    const SWITCH: egui::Vec2 = egui::vec2(40.0, 22.0);
    const GAP: f32 = 12.0;
    const HINT_GAP: f32 = 2.0;

    let width = ui.available_width();
    let text_width = (width - SWITCH.x - GAP).max(40.0);

    let body = egui::TextStyle::Body.resolve(ui.style());
    let hint_font = egui::FontId::new(body.size * 0.85, body.family.clone());
    let label_colour = if enabled { TEXT } else { MUTED };

    // The badge — «рекомендуется» — is measured first, and the label is then laid out into what is
    // left. A badge that would not fit is dropped rather than allowed to run under the switch: it
    // is an aside, and an aside that breaks the row is worse than no aside.
    let badge_galley = badge.map(|b| {
        ui.painter().layout_no_wrap(
            b.to_owned(),
            egui::FontId::new(body.size * 0.85, body.family.clone()),
            OK,
        )
    });
    let badge_width = badge_galley
        .as_ref()
        .map_or(0.0, |g| g.size().x + BADGE_GAP);

    let label_galley = ui.painter().layout(
        label.to_owned(),
        body,
        label_colour,
        text_width - badge_width,
    );
    let hint_galley = hint.map(|h| {
        ui.painter()
            .layout(h.to_owned(), hint_font, MUTED, text_width)
    });

    let text_height =
        label_galley.size().y + hint_galley.as_ref().map_or(0.0, |g| HINT_GAP + g.size().y);
    let row = egui::vec2(width, text_height.max(SWITCH.y));
    let (rect, response) = ui.allocate_exact_size(row, egui::Sense::click());

    let flipped = enabled && response.clicked();
    if flipped {
        *value = !*value;
    }

    let painter = ui.painter();
    let mut y = rect.center().y - text_height / 2.0;
    painter.galley(egui::pos2(rect.left(), y), label_galley.clone(), TEXT);
    if let Some(g) = badge_galley {
        // On the first line, after the label, vertically centred against it — this is a note about
        // the label, not a second label.
        let first_line = label_galley
            .rows
            .first()
            .map_or(label_galley.size().x, |r| r.rect().width());
        let x = rect.left() + first_line + BADGE_GAP;
        let dy = (label_galley.size().y - g.size().y) / 2.0;
        painter.galley(egui::pos2(x, y + dy), g, OK);
    }
    if let Some(g) = hint_galley {
        y += label_galley.size().y + HINT_GAP;
        painter.galley(egui::pos2(rect.left(), y), g, MUTED);
    }

    let track = egui::Rect::from_min_size(
        egui::pos2(rect.right() - SWITCH.x, rect.center().y - SWITCH.y / 2.0),
        SWITCH,
    );
    // Animated, so a change made from the tray menu or by the service is visible even when the eye
    // is on the other half of the window.
    let t = ui.ctx().animate_bool(response.id, *value);
    let radius = track.height() / 2.0;
    // Dimmed when it cannot be clicked, never redrawn as OFF. A row that is briefly unclickable —
    // a change is in flight, or the mode needs a Windows this is not — still has to show what the
    // setting IS, or the screen lies for as long as it is busy.
    let dim = |c: egui::Color32| {
        if enabled {
            c
        } else {
            c.gamma_multiply(0.45)
        }
    };
    painter.rect_filled(track, radius, dim(if *value { PRIMARY } else { TRACK_OFF }));
    painter.circle_filled(
        egui::pos2(
            egui::lerp((track.left() + radius)..=(track.right() - radius), t),
            track.center().y,
        ),
        radius - 3.0,
        dim(egui::Color32::WHITE),
    );

    flipped
}
