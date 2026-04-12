import type { APIContext } from "astro";
import { getCollection } from "astro:content";
import type { BreakingNewsItemProps } from "../../_types/RootPageViews.ts";
import {
    filterPublishedEntries,
    getEntryDisplayDate,
    getEntryUrl,
    sortBlogEntries,
    sortDocEntries,
} from "../../content/utils";

export async function GET({}: APIContext) {
    const allDocs = sortDocEntries(filterPublishedEntries(await getCollection("docs")));
    const allBlog = sortBlogEntries(filterPublishedEntries(await getCollection("blog")));

    const docsList = allDocs
        .map((item) => ({
            title: item.data.title ?? item.slug,
            date: getEntryDisplayDate(item),
            href: getEntryUrl(item),
            category: "DOCS",
        })) as BreakingNewsItemProps[];

    const blogList = allBlog
        .map((item) => ({
            title: item.data.title ?? item.slug,
            date: getEntryDisplayDate(item, item.id.substring(0, 10)),
            href: getEntryUrl(item),
            category: "BLOG",
        })) as BreakingNewsItemProps[];

    return new Response(
        JSON.stringify([
            {
                name: "文档",
                list: docsList,
            },
            {
                name: "博客",
                list: blogList,
            },
        ]),
        {
            headers: {
                "Content-Type": "application/json; charset=utf-8",
            },
        }
    );
}
