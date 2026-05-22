import type { APIContext } from "astro";
import { getCollection } from "astro:content";
import {
  filterPublishedEntries,
  getEntryDate,
  getEntryDisplayDate,
  getEntryUrl,
  type SiteEntry,
} from "../content/utils";

function sortByNewest<T extends SiteEntry>(entries: T[]): T[] {
  return entries.slice().sort((left, right) => {
    const timeDiff = (getEntryDate(right)?.getTime() ?? 0) - (getEntryDate(left)?.getTime() ?? 0);
    return timeDiff || right.slug.localeCompare(left.slug, "zh-CN");
  });
}

function toFeedItem(entry: SiteEntry) {
  return {
    title: entry.data.title ?? entry.slug,
    date: getEntryDisplayDate(entry),
    summary: entry.data.summary ?? entry.data.description ?? "",
    href: getEntryUrl(entry),
  };
}

export async function GET({}: APIContext) {
  const docs = sortByNewest(filterPublishedEntries(await getCollection("docs"))).map(toFeedItem);
  const blog = sortByNewest(filterPublishedEntries(await getCollection("blog"))).map(toFeedItem);

  return new Response(
    JSON.stringify({ docs, blog }),
    {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
      },
    },
  );
}
