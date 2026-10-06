# PokéHabitat interaction contract

## Canonical UI Map

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
| --- | --- | --- | --- | --- |
| Form | GameField / GameForm in components/game-ui.tsx, server validation | PRODUCT.md + server/game-service.ts | registration, login, recovery | API auth tests; form audit |
| Select/Listbox | native select through GameField | UX-CONTRACT.md | habitat expedition, atlas filters, profile cover, bot difficulty | label + keyboard semantics |
| Scrollbar | app/globals.css | DESIGN.md | bounded dialog | strict static audit |
| Toast | Feedback in components/game-ui.tsx | UX-CONTRACT.md | status, error | live regions |
| CRUD | useGame API client + server/game-service.ts | PRODUCT.md | refresh after confirmed mutation | multi-player integration tests |
| Overlay | installed Radix Dialog / AlertDialog | DESIGN.md | creature preview, reward reveal, surrender, unsaved profile | focus ownership by primitive |
| Locale | Home locale prop + lib/pokemon.ts | DESIGN.md | ru, en | equivalent paths/copy |

## Behavior

Atlas, collection, arena and account are main view query states; browser back restores the selected view. Locale changes preserve the current view, form drafts and game state. Pokémon preview is the shared atlas dialog; evolution buttons replace its complete selected Pokémon, artwork and moves while staying on the evolution tab.

GameField pairs a persistent label, hint and error via aria-describedby. GameForm disables repeated submission, preserves entered values on failure, focuses the first invalid control, and never places passwords or recovery codes in URLs. Feedback uses an assertive error live region or polite success region. Loading reserves geometry, empty collections guide registration, network errors retain the last known state with manual retry. Recovery codes are revealed only after register/reset, with an explicit saved-code acknowledgement before dismissing.

Collection team selections stay as a draft until Save; failed saves keep the draft. Card acquisition requests carry idempotency UUIDs and retain the same UUID after network failure. Server-confirmed rewards update the profile and reveal the received card. Pack cost is stated before the action.

Arena state polls every three seconds while visible. Requests are sequenced and aborted on unmount; stale responses never overwrite newer local state. Own submitted order remains visible; opponent order remains hidden. A failed request preserves the duel, shows a retry action and refreshes authoritative state. Surrender uses installed AlertDialog with outcome text. Cancellation of an empty waiting room is direct.

Reduced motion suppresses sprite movement and uses a static low-intensity move signature. No flashing background. Canvas is visual-only with equivalent text battle history. Mobile layout stacks combatants and keeps attacks/switches at least 44px high. Artwork dimensions are reserved.

## Decorative presence

PresenceCounter is independent of accounts and duel rooms. It retains the requested random inclusive 75–168 count with 45-second visible-page updates. The visible label is only “Сейчас в игре” / “In game now”; the user requested removing the extra demo text. Numeric width is reserved, periodic changes are not an assertive live region, and no gameplay rule depends on the value.

## Expanded paths

Atlas filters (name or number, type, total stats, sort) are URL-addressable and preserve habitat. Reset restores the complete catalogue. The site uses fixed light glass styling; no theme toggle is shown. Club poll requests are aborted on unmount and guarded against stale responses. Quest and season rewards are explicit claims with server-owned eligibility and idempotent receipts. Friends require mutual acceptance; invitations admit only the named friend and stay out of public matchmaking. Practice rooms use the same battle interface and effects, explicitly identify a bot, and do not affect PvP ranking. Profile save validates owned avatars/favorites; Cancel restores saved values; failures preserve drafts. Reward overlays restore opener focus and can close without reversing acquisition.
