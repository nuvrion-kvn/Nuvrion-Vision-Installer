# PokéHabitat

Russian/English fan atlas and persistent card game. User confirmed open game registration and turn-based teams of three. Public visitors can explore the atlas; username/password sessions authorize every personal or game mutation. No payments, email messaging, or AI masquerading as another player.

Registration: ASCII username 3–20 characters; password 10–128 characters. Choose Bulbasaur, Charmander or Squirtle, plus two distinct common starter cards. Return a recovery code once; store only its keyed digest. Recovery resets the password, rotates the recovery code and revokes all sessions.

Acquisition: one habitat expedition per rolling 24 hours, awarding one non-legendary card or 20 coins for an existing card. A 100-coin pack contains one card: 1% legendary/mythical, 9% other evolved forms, 90% unevolved common cards. Duplicate cards return 20 coins. The first three qualifying finished duels each UTC day earn 30 coins for a win, 10 for a loss. Later duels still update wins/losses. A surrender before round three earns no coins for either player. All random selection and rewards are server-owned, atomic and idempotent.

Team: three distinct owned cards, sum of base stats at most 1500. Changes apply to the next duel; current duels keep a snapshot. One unfinished room per player. Rooms are publicly joinable or joinable by a six-character code. No opponent action is disclosed before both orders are received.

Arena: both players choose an attack or a switch each round. Switches precede attacks; move priority, then Speed, decide attack order. Accuracy, physical/special stats, STAB, type effectiveness, PP and 85–100% damage variation apply at level 50 without EVs. Transform copies the opponent's form and gives 5 PP per copied move. Exhausted PP permits Struggle with recoil. A knockout automatically sends the next surviving card. Secondary status effects and passive abilities are descriptive atlas data, not included in this simplified duel engine. Low Kick uses the target weight tiers; Flail uses the cached API 64×HP/maxHP tiers; Dragon Rage inflicts 40 HP, respecting type immunity. Absorb heals the user by 50% of inflicted damage. Round deadline is 120 seconds; absent orders become passes, and two absent players cancel the match. A waiting room expires after 20 minutes.

Persistence is node-local SQLite in this autonomous distribution; cookies are HttpOnly/Secure/SameSite=Lax. Password hashes use bcrypt cost 12 over a secret HMAC prehash; session and recovery tokens are keyed/hashed. No authentication token or game progress in browser storage. Mutation origin checks, per-account/IP throttling, ownership and version checks are server enforced.

## Trainer club

Direct card evolution costs 150 earned coins, grants the direct next form and 30 XP, and keeps the original. Already-owned targets cannot be repurchased. Every evolution transaction is atomic and retries replay the receipt.

Trainer XP includes 10 per owned card, 40 per PvP win and 10 per PvP loss plus earned quest, evolution and practice XP. Level = 1 + floor(XP / 100), cosmetic only. Practice easy/normal/hard bots use three distinct eligible cards and server-owned orders. Practice completion awards 15 XP for a win, 5 otherwise, once per room, and never awards PvP coins or rating.

UTC daily quests: expedition 20 coins/25 XP, completed PvP duel 25/30, practice win 20/25. Permanent achievements: 10 cards 60/50, first PvP win 50/50, 10 PvP wins 150/100, first evolution 50/50, 3 practice wins 60/50. Explicit reward claims are idempotent.

Monthly UTC seasons rank completed PvP records by max(0, total wins × 25 − total losses × 10), ties by wins then account creation. Leagues: bronze 0, silver 100, gold 250, legend 500. Positive-score leaders of the previous closed season may claim 300 coins for rank 1, 200 for ranks 2–3, 100 for ranks 4–10 once. Draws and practice are excluded.

Friends use accepted mutual relationships (maximum 100 entries per requesting account). Only accepted friends can receive a private duel invitation. Only its intended receiver may join that room; private rooms are excluded from public room listings. Invitations and waiting rooms expire after 20 minutes. Trainer avatars and up to three distinct showcased favorites come from owned cards; covers offer the seven habitats.
