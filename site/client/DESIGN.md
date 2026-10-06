---
version: alpha
name: PokéHabitat
description: A forest field guide behind refractive milky glass for Russian and English Pokémon fans.
colors:
  primary: "#2e604b"
  foreground: "#18392d"
  background: "#edf4ef"
  surface: "#f8fffa9e"
  border: "#ffffffad"
  muted: "#586f60"
  focus: "#397c5c"
typography:
  body:
    fontFamily: "Avenir Next, Segoe UI, Arial, sans-serif"
    fontSize: "1rem"
    lineHeight: "1.5"
  display:
    fontFamily: "Arial Rounded MT Bold, Avenir Next, Segoe UI, sans-serif"
rounded:
  DEFAULT: "1rem"
  card: "1.5625rem"
  pill: "6.25rem"
  dialog: "2rem"
spacing:
  page-max: "89.5rem"
  page-gutter: "2.75rem"
  card-gap: "1.3125rem"
components:
  glass:
    backgroundColor: "#f8fffa9e"
  primary-button:
    backgroundColor: "#2e604b"
    textColor: "#ffffff"
---

# PokéHabitat design system

## Overview

An interactive field guide for Russian and English Pokémon fans. The reference is an iPhone liquid-glass control hovering above a sunlit forest lake. Authentic Pokémon artwork appears inside botanical glass specimens. Use the same restrained forest identity for the atlas, collection, account and real multiplayer arena.

One root route with query-addressable atlas, collection, arena, club and account views; a reusable Pokémon detail dialog. Both locales carry the same content. Language is a device-local preference. Account, collection and duel state are server-owned and persistent. See PRODUCT.md for economy and duel rules and UX-CONTRACT.md for workflows. Pokémon's Japanese origin does not imply a Japanese market or locale.

Token ownership: Model B. `app/globals.css` is canonical. Frontmatter mirrors accepted values. Colors map to `--primary`, `--foreground`, `--background`, `--glass-surface`, `--glass-edge`, `--muted-foreground`, and `--ring`. Tailwind adapts the semantic variables. Glass cards, buttons and dialog consume them. Typography maps to `--font-body` and `--font-display`.

## Colors

Forest green actions and dark leaf-green text. Milky glass stabilizes contrast over the natural scene. Game type colors always accompany written labels. The light glass theme is fixed, independent of OS dark mode. Forced colors use Canvas and CanvasText and remove the scene.

## Typography

Rounded display letters and restrained sans-serif body. Cyrillic and Latin share system-capable families without late font downloads. Main descriptions are 16px; secondary metadata is at least 12px. Names never use ellipsis. Tabs can wrap. Headings and the wordmark have no trailing periods in either locale.

## Layout

Natural document scroll, four columns on desktop, three on tablet, two on phones. At 680px the featured card stacks under the compact heading. Habitat navigation scrolls horizontally with a visible scrollbar. Cards reserve artwork geometry. The detail dialog owns bounded scrolling and adapts to phone heights. No viewport-height constraints on the page.

## Elevation & Depth

Glass has 22px blur, a white edge, an inset highlight and a restrained shadow. Six bundled nature landscapes follow the selected habitat; the unclassified habitat uses the crystal cave. The modal's blur and darker overlay establish depth. No animated backdrop or hover-only content.

## Shapes

25px cards, rounded pills and 32px dialog. Lucide icons use consistent strokes. Favicon is a simple forest-green capture-ball motif.

## Components

Starter Radix Dialog owns focus trapping, Escape, scroll locking and inert background. A trigger ref restores focus to the card that opened it. Starter Tabs owns detail-panel keyboard navigation. Habitat filters expose pressed state. Changing language preserves active habitat and open details. All actions are native semantic buttons.

PokemonArt is shared and has a labeled missing-image fallback. All game data and artwork are bundled; no runtime remote API dependency. Twelve catalogue cards per page with explicit Load more; changing habitat resets the count. The collection reuses PokemonArt and TypeBadge from components/pokemon-visuals.tsx, and shares the atlas detail dialog. Evolution nodes are buttons that replace the complete selected record and portrait.

Disabled attack buttons preserve geometry. User-triggered effects last 1.75s; reduced motion uses a gentle 600ms pass without sprite motion. MoveEffect is shared between the atlas and arena; it selects a visual signature by the actual move slug (jet, flame, bubble, lightning, leaves, vine, rock, slash, psychic, impact). Effects are labeled stylized demonstrations. Agility is explicitly derived from Speed, not presented as an official seventh game stat.

Scrollbars globally inherit tokenized thumb/track/hover/active colors with standards and WebKit paths. Pointer targets have hover, focus, active and disabled states. GameField/GameForm own labels and form errors; Feedback owns persistent live-region feedback. Installed Radix AlertDialog confirms surrender. Async API failures preserve drafts and expose Retry. The arena uses real rooms, two private orders, bounded polling and server conflict checks.

PresenceCounter remains a decorative random integer in the inclusive 75–168 range, updated on mount, every 45 seconds while visible and on returning to the tab. Per the user's copy preference, it only displays the localized “Сейчас в игре” / “In game now” label and number. The counter shares forest-glass controls, reserves three numeric characters, cleans up timers and does not affect matchmaking or rewards.

## Do's and Don'ts

- Keep the catalogue visible below compact framing.
- Localize descriptions, attacks, abilities and evolution requirements.
- Credit primary data and game ownership discreetly.
- Use authentic Pokémon artwork for factual creatures.
- Keep official atlas statistics separate from explicitly documented simplified arena rules. Game coins are earned and have no payment flow.

## Trainer expansion

Type-tinted edges and short pointer-fine glints enrich cards without hiding actions. All motion honors reduced motion. The Radix reward dialog reveals the server-issued card through a Poké Ball, or fades the original portrait into its evolved form. Club panels share glass, native labeled selects and explicit empty/loading/error states. Trainer covers use bundled habitat artwork; avatars and up to three favorites must be owned. Unsaved profile changes require an app-owned AlertDialog before section navigation.
