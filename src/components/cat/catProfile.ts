export type CatCoatId = "tabbyWhite" | "whitePaws" | "orange" | "black" | "white" | "cow" | "calico" | "gray";
export type CatOutfitSlot = "head" | "face" | "collar" | "clothes" | "tail";

export type CatProfile = {
  name: string;
  affection: number;
  hunger: number;
  cans: number;
  driedFish: number;
  coat: CatCoatId;
  outfit: Partial<Record<CatOutfitSlot, string>>;
  ownedItems: string[];
  claimedArticles: string[];
  redeemedCodes: string[];
  lastPetAt?: number;
  lastFedAt?: number;
  lastMessageRewardAt?: string;
  lastUpdatedAt: number;
};

export type CatProfileReward =
  | { kind: "article"; amount: number; articleId: string }
  | { kind: "message"; amount: number; date: string }
  | { kind: "feed"; affection: number; hunger: number }
  | { kind: "pet"; affection: number };

export const CAT_PROFILE_STORAGE_KEY = "corn-kingdom-pixel-cat";
export const CAT_PROFILE_EVENT = "corn-kingdom-cat-profile";
const LEGACY_DEFAULT_CAT_NAMES = new Set(["", "小猫", "猫猫", "Pixel Cat", "pixel cat"]);
const SUPPORTED_OUTFIT_VALUES: Partial<Record<CatOutfitSlot, Set<string>>> = {
  face: new Set(["sunglasses"]),
  collar: new Set(["bell", "blueScarf"]),
  clothes: new Set(["red-ribbon-bow", "sleep-cap", "headphones", "explorer-backpack", "rain-poncho", "star-charm-collar"]),
};

export const defaultCatProfile: CatProfile = {
  name: "米线",
  affection: 12,
  hunger: 72,
  cans: 2,
  driedFish: 1,
  coat: "tabbyWhite",
  outfit: {
    collar: "bell",
  },
  ownedItems: [
    "coat:tabbyWhite",
    "coat:whitePaws",
    "coat:orange",
    "coat:black",
    "coat:white",
    "coat:cow",
    "coat:calico",
    "coat:gray",
    "collar:bell",
    "collar:blueScarf",
    "face:sunglasses",
    "clothes:red-ribbon-bow",
    "clothes:sleep-cap",
    "clothes:headphones",
    "clothes:explorer-backpack",
    "clothes:rain-poncho",
    "clothes:star-charm-collar",
  ],
  claimedArticles: [],
  redeemedCodes: [],
  lastUpdatedAt: 0,
};

function clamp(value: number, min = 0, max = 100) {
  return Math.min(max, Math.max(min, value));
}

function sanitizeOutfit(outfit: Partial<Record<CatOutfitSlot, string>> | undefined) {
  const next: Partial<Record<CatOutfitSlot, string>> = {};

  (Object.keys(SUPPORTED_OUTFIT_VALUES) as CatOutfitSlot[]).forEach((slot) => {
    const value = outfit?.[slot];
    if (value && SUPPORTED_OUTFIT_VALUES[slot]?.has(value)) {
      next[slot] = value;
    }
  });

  return next;
}

function mergeProfile(value: Partial<CatProfile> | null | undefined): CatProfile {
  const rawName = value?.name?.trim() ?? "";
  const name = LEGACY_DEFAULT_CAT_NAMES.has(rawName) ? defaultCatProfile.name : value?.name ?? defaultCatProfile.name;

  return {
    ...defaultCatProfile,
    ...value,
    name,
    outfit: {
      ...sanitizeOutfit(defaultCatProfile.outfit),
      ...sanitizeOutfit(value?.outfit),
    },
    ownedItems: Array.from(new Set([...(defaultCatProfile.ownedItems ?? []), ...(value?.ownedItems ?? [])])),
    claimedArticles: value?.claimedArticles ?? [],
    redeemedCodes: value?.redeemedCodes ?? [],
    affection: clamp(value?.affection ?? defaultCatProfile.affection),
    hunger: clamp(value?.hunger ?? defaultCatProfile.hunger),
    cans: Math.max(0, value?.cans ?? defaultCatProfile.cans),
    driedFish: Math.max(0, value?.driedFish ?? defaultCatProfile.driedFish),
    lastUpdatedAt: value?.lastUpdatedAt ?? Date.now(),
  };
}

export function loadCatProfile(): CatProfile {
  if (typeof window === "undefined") return defaultCatProfile;

  const raw = window.localStorage.getItem(CAT_PROFILE_STORAGE_KEY);
  if (!raw) return { ...defaultCatProfile, lastUpdatedAt: Date.now() };

  try {
    return mergeProfile(JSON.parse(raw) as Partial<CatProfile>);
  } catch {
    return { ...defaultCatProfile, lastUpdatedAt: Date.now() };
  }
}

export function saveCatProfile(profile: CatProfile) {
  if (typeof window === "undefined") return;

  const next = {
    ...profile,
    affection: clamp(profile.affection),
    hunger: clamp(profile.hunger),
    cans: Math.max(0, profile.cans),
    driedFish: Math.max(0, profile.driedFish),
    lastUpdatedAt: Date.now(),
  };

  window.localStorage.setItem(CAT_PROFILE_STORAGE_KEY, JSON.stringify(next));
  window.dispatchEvent(new CustomEvent(CAT_PROFILE_EVENT, { detail: next }));
}

export function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

export function claimArticleReward(articleId: string): { profile: CatProfile; claimed: boolean } {
  const profile = loadCatProfile();
  if (profile.claimedArticles.includes(articleId)) return { profile, claimed: false };

  const next = {
    ...profile,
    cans: profile.cans + 1,
    affection: clamp(profile.affection + 1),
    claimedArticles: [...profile.claimedArticles, articleId],
  };
  saveCatProfile(next);
  return { profile: next, claimed: true };
}

export function claimMessageReward(): { profile: CatProfile; claimed: boolean } {
  const profile = loadCatProfile();
  const today = todayKey();
  if (profile.lastMessageRewardAt === today) return { profile, claimed: false };

  const next = {
    ...profile,
    driedFish: profile.driedFish + 1,
    affection: clamp(profile.affection + 2),
    lastMessageRewardAt: today,
  };
  saveCatProfile(next);
  return { profile: next, claimed: true };
}

export function feedCat(): { profile: CatProfile; fed: boolean } {
  const profile = loadCatProfile();
  if (profile.cans <= 0) return { profile, fed: false };

  const next = {
    ...profile,
    cans: profile.cans - 1,
    hunger: clamp(profile.hunger + 22),
    affection: clamp(profile.affection + 4),
    lastFedAt: Date.now(),
  };
  saveCatProfile(next);
  return { profile: next, fed: true };
}

export function petCat(): { profile: CatProfile; petted: boolean; cooldownMs: number } {
  const profile = loadCatProfile();
  const now = Date.now();
  const cooldownMs = 8_000;
  if (profile.lastPetAt && now - profile.lastPetAt < cooldownMs) {
    return { profile, petted: false, cooldownMs: cooldownMs - (now - profile.lastPetAt) };
  }

  const next = {
    ...profile,
    affection: clamp(profile.affection + 3),
    hunger: clamp(profile.hunger - 1),
    lastPetAt: now,
  };
  saveCatProfile(next);
  return { profile: next, petted: true, cooldownMs: 0 };
}
