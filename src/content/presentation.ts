import type { CollectionEntry } from "astro:content";
import { getEntryDate, trimSlugPrefix } from "./utils";

export type SiteEntry = CollectionEntry<"blog"> | CollectionEntry<"docs">;
export type DocEntry = CollectionEntry<"docs">;

type CollectionType = SiteEntry["collection"];

const DEFAULT_STATUS: Record<CollectionType, string> = {
  blog: "LOGGED",
  docs: "ACTIVE",
};

const DEFAULT_SECURITY: Record<CollectionType, string> = {
  blog: "AMBER",
  docs: "BLUE",
};

const DEFAULT_TRACK: Record<CollectionType, string> = {
  blog: "FIELD JOURNAL",
  docs: "KNOWLEDGE MAP",
};

function normalizeOptionalText(value: string | undefined | null): string | undefined {
  const text = value?.trim();
  return text ? text : undefined;
}

function stripMarkdown(value: string): string {
  return value
    .replace(/^---[\s\S]*?---/m, "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!\[[^\]]*]\([^)]+\)/g, " ")
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "")
    .replace(/^\s*\d+\.\s+/gm, "")
    .replace(/[>*_~|]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function getEntryPrefix(entry: SiteEntry): string {
  return entry.collection === "docs" ? "DOC" : "LOG";
}

function getEntryCollectionLabel(entry: SiteEntry): string {
  return normalizeOptionalText(entry.data.category) ?? DEFAULT_TRACK[entry.collection];
}

export function getEntrySummary(entry: SiteEntry): string {
  const explicit = normalizeOptionalText(entry.data.summary) ?? normalizeOptionalText(entry.data.description);
  if (explicit) return explicit;

  const stripped = stripMarkdown(entry.body);
  if (!stripped) return entry.collection === "docs" ? "Knowledge node waiting for annotation." : "Field log waiting for summary.";

  const maxLength = entry.collection === "docs" ? 92 : 108;
  return stripped.length > maxLength ? `${stripped.slice(0, maxLength).trim()}...` : stripped;
}

export function getEntryStatus(entry: SiteEntry): string {
  return normalizeOptionalText(entry.data.status)?.toUpperCase() ?? DEFAULT_STATUS[entry.collection];
}

export function getEntrySecurity(entry: SiteEntry): string {
  return normalizeOptionalText(entry.data.security)?.toUpperCase() ?? DEFAULT_SECURITY[entry.collection];
}

export function getEntryCode(entry: SiteEntry, index: number): string {
  return normalizeOptionalText(entry.data.code)?.toUpperCase()
    ?? `${getEntryPrefix(entry)}-${String(index + 1).padStart(3, "0")}`;
}

export function getEntryUpdatedLabel(entry: SiteEntry): string {
  const date = getEntryDate(entry);
  if (!date) return "UNSTAMPED";

  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}.${month}.${day}`;
}

function getDocSegmentParts(segment: string): { order?: string; label: string } {
  const match = segment.match(/^(\d+)_+(.+)$/);
  if (!match) return { label: segment };

  return {
    order: match[1],
    label: match[2],
  };
}

export type DocMapItem = {
  href: string;
  slug: string;
  label: string;
  cluster: string;
  depth: number;
  pathLabel: string;
  code: string;
  active: boolean;
  index: number;
};

export function getDocMapItems(entries: DocEntry[], currentSlug?: string): DocMapItem[] {
  const normalizedCurrent = currentSlug ? trimSlugPrefix(currentSlug) : "";

  return entries.map((entry, index) => {
    const normalizedSlug = trimSlugPrefix(entry.slug);
    const segments = normalizedSlug.split("/");
    const parsedSegments = segments.map(getDocSegmentParts);
    const leaf = parsedSegments.at(-1);
    const cluster = parsedSegments[0]?.label ?? "ROOT";
    const numericPath = parsedSegments
      .map((part, segmentIndex) => part.order ?? String(segmentIndex + 1).padStart(2, "0"))
      .join(".");

    return {
      href: `${import.meta.env.BASE_URL}docs/${normalizedSlug}`,
      slug: normalizedSlug,
      label: entry.data.title ?? leaf?.label ?? normalizedSlug,
      cluster,
      depth: Math.max(1, segments.length),
      pathLabel: numericPath,
      code: normalizeOptionalText(entry.data.code)?.toUpperCase() ?? `D-${String(index + 1).padStart(2, "0")}`,
      active: normalizedSlug === normalizedCurrent,
      index,
    };
  });
}

export function getCollectionDescriptor(entry: SiteEntry): string {
  return getEntryCollectionLabel(entry).toUpperCase();
}
