import data from "../app/catalog.json";
export type Locale = "ru" | "en";
export type Localized = { ru: string; en: string };
export type Move = { id: number; slug?: string; name: Localized; description: Localized; type: string; power: number | null; accuracy: number | null; pp?: number; priority?: number; damageClass?: string; meta?: {drain?: number; min_hits?: number|null; max_hits?: number|null} };
export type Pokemon = { id: number; name: Localized; genus: Localized; description: Localized; habitat: string; types: string[]; height: number; weight: number; stats: number[]; isLegendary?: boolean; isMythical?: boolean; abilities: { name: Localized; description: Localized; hidden: boolean }[]; moves: Move[]; evolution: { nodes: { id: number; name: Localized }[]; edges: { from: number; to: number; condition: Localized }[] } };
export const pokemon = data as Pokemon[];
export const byId = new Map(pokemon.map(p => [p.id, p]));
