---
name: theme-factory
description: "Apply pre-set or custom color and typography themes to slides, docs, reports, and HTML pages. Use when the user asks to theme, style, brand, or change the look and feel of an artifact, or requests a specific color scheme, visual identity, or design system for their content."
license: Complete terms in LICENSE.txt
---

# Theme Factory

Apply professional color palettes and font pairings to any artifact. 10 built-in themes cover common contexts; custom themes can be generated on the fly.

## Workflow

1. Show `theme-showcase.pdf` so the user can browse themes visually (do not modify this file)
2. Ask the user to pick a theme (or describe a custom one)
3. Read the selected theme file from `themes/<theme-name>.md`
4. Apply hex colors and fonts consistently across the artifact
5. **Verify**: check that foreground/background contrast meets WCAG AA (≥ 4.5:1 for body text, ≥ 3:1 for large text) and that no element uses an off-theme color
6. Present the themed artifact for user review; iterate if needed

## Built-in Themes

| Theme | Vibe | Best for |
|-------|------|----------|
| `ocean-depths` | Calming navy/teal | Corporate, finance, consulting |
| `sunset-boulevard` | Warm orange/coral | Marketing, events, lifestyle |
| `forest-canopy` | Earthy greens | Sustainability, education, wellness |
| `modern-minimalist` | Clean grayscale | Any professional context |
| `golden-hour` | Rich amber/brown | Autumn campaigns, luxury |
| `arctic-frost` | Cool blue/white | Healthcare, clean-tech |
| `desert-rose` | Dusty pink/mauve | Fashion, hospitality, editorial |
| `tech-innovation` | Electric blue/cyan | Tech, AI/ML, product launches |
| `botanical-garden` | Fresh green/cream | Food, organic, garden |
| `midnight-galaxy` | Deep purple/cosmic | Entertainment, creative, nightlife |

Each theme file in `themes/` defines: hex color palette, header font, body font, and recommended use cases.

## Custom Themes

When no built-in theme fits, generate a custom theme:

1. Ask the user for a mood, brand colors, or reference image
2. Create a theme file following the same structure as `themes/ocean-depths.md` (color palette with 4 hex values, header/body font pairing, "Best Used For" context)
3. Show the custom theme spec for approval before applying
4. Apply using the same workflow as built-in themes
