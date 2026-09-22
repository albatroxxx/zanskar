# Brand assets

| File | Use |
|---|---|
| `logo-mark.svg` | Square mark on a 128 px grid. App icon, avatars, social. |
| `logo-mark-mono.svg` | Single-colour mark using `currentColor`. Print, embroidery, monochrome UI. |
| `logo.svg` | Horizontal lockup for light backgrounds. |
| `logo-dark.svg` | Horizontal lockup for dark backgrounds. |
| `badge.svg` | 20 px flat badge for README files of projects that use Zanskar. |
| `favicon/` | `favicon.svg` plus PNG icons at 16, 32, 48, 180 (Apple touch), 192 and 512 px. |

## The mark

A shell prompt redrawn: the chevron is a summit with a snow cap, the block cursor waits for
input. It says "terminal" to the people who will use Zanskar and "mountain" to everyone else.

Keep the chevron and cursor proportions as drawn. The snow cap is dropped in the mono version
and at 16 px, where it would be a single pixel.

## Palette

Warm stone neutrals and one ultramarine accent. The neutrals carry the interface;
the accent is reserved for the mark, actions, links and active states, so colour
means something when it appears. Status colours (green, amber, red) are the only
other hues and are used for status alone.

| Name | Hex | Role |
|---|---|---|
| Ink | `#121318` | Mark gradient bottom, badge label, deepest surface |
| Charcoal | `#2A2D36` | Mark gradient top, wordmark on light |
| Ultramarine | `#3D4FE0` | Chevron gradient end, focus ring |
| Periwinkle | `#A9B4FF` | Chevron gradient start, links and cursor on dark surfaces |
| Indigo | `#2F3FBF` | Buttons and links on light, badge value |
| Bone | `#F2EEE6` | Cursor, snow cap, wordmark on dark |
| Paper | `#F4F2EC` | Interface background (light) |

The UI tokens in `web/src/styles/tokens.css` derive from this table. Dark mode keeps
the same accent family on charcoal surfaces rather than tinting the neutrals.

The wordmark and tagline in the lockups are Cantarell outlines (Bold 700 and Medium 500), so the
SVGs render identically everywhere and depend on no installed font. Cantarell is also the UI
typeface: the GNOME 0.311 variable font, subset to Latin, Greek and Cyrillic, bundled at
`web/public/fonts/Cantarell-VF.woff2` under the SIL Open Font License 1.1.

## Favicon markup

```html
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/icon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/icon-180.png">
```
