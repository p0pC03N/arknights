import type { CollectionEntry } from "astro:content";

export type BlogEntry = CollectionEntry<"blog">;
export type DocEntry = CollectionEntry<"docs">;
export type SiteEntry = BlogEntry | DocEntry;

const base = import.meta.env.BASE_URL;
const BLOG_DATE_PREFIX_RE = /^(\d{4})-(\d{2})-(\d{2})(?:_|$)/;
const FLEXIBLE_DATE_RE =
  /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2})(?::(\d{1,2}))?(?::(\d{1,2}))?)?$/;

function normalizeInputDate(value: Date | string | undefined | null): Date | undefined {
  if (!value) return undefined;

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? undefined : value;
  }

  const match = value.match(FLEXIBLE_DATE_RE);
  if (match) {
    const [, year, month, day, hour = "0", minute = "0", second = "0"] = match;
    return new Date(Date.UTC(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
    ));
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function parseBlogDateFromId(id: string): Date | undefined {
  const match = id.match(BLOG_DATE_PREFIX_RE);
  if (!match) return undefined;

  const [, year, month, day] = match;
  return new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));
}

export function trimSlugPrefix(slug: string): string {
  return slug
    .split("/")
    .map((segment) => (segment.includes("_") ? segment.split("_").slice(1).join("_") : segment))
    .join("/");
}

export function filterPublishedEntries<T extends SiteEntry>(entries: T[]): T[] {
  return entries.filter((entry) => !entry.data.draft);
}

export function getEntryDate(entry: SiteEntry): Date | undefined {
  return normalizeInputDate(entry.data.date) ?? (entry.collection === "blog" ? parseBlogDateFromId(entry.id) : undefined);
}

export function formatDate(date: Date | undefined, fallback = "未设置日期"): string {
  if (!date) return fallback;

  const year = String(date.getUTCFullYear());
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");

  return `${year} // ${month} / ${day}`;
}

export function getEntryDisplayDate(entry: SiteEntry, fallback = "未设置日期"): string {
  return formatDate(getEntryDate(entry), fallback);
}

export function getEntrySlug(entry: SiteEntry): string {
  return entry.collection === "docs" ? trimSlugPrefix(entry.slug) : entry.slug;
}

export function getEntryUrl(entry: SiteEntry): string {
  return `${base}${entry.collection}/${getEntrySlug(entry)}`;
}

export function sortBlogEntries(entries: BlogEntry[]): BlogEntry[] {
  return entries.slice().sort((left, right) => {
    const timeDiff = (getEntryDate(right)?.getTime() ?? 0) - (getEntryDate(left)?.getTime() ?? 0);
    return timeDiff || right.id.localeCompare(left.id, "zh-CN");
  });
}

export function sortDocEntries(entries: DocEntry[]): DocEntry[] {
  return entries.slice().sort((left, right) => {
    const orderDiff = (left.data.order ?? Number.MAX_SAFE_INTEGER) - (right.data.order ?? Number.MAX_SAFE_INTEGER);
    return orderDiff || left.slug.localeCompare(right.slug, "zh-CN");
  });
}
