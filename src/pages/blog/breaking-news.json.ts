import type { APIContext } from "astro";
import { getCollection } from "astro:content";
import type { BreakingNewsItemProps } from "../../_types/RootPageViews.ts";

function formatDate(input: Date | string | undefined, fallback = "") {
    if (!input) return fallback;
    const date = typeof input === "string" ? new Date(input) : input;
    if (Number.isNaN(date.getTime())) return fallback;

    return `${date.getFullYear()} // ${date.getMonth() + 1} / ${date.getDate()}`;
}

export async function GET({}: APIContext) {
    const base = import.meta.env.BASE_URL;

    const allDocs = await getCollection("docs");
    const allBlog = await getCollection("blog");

    const docsList = allDocs
        .slice()
        .reverse()
        .map((item) => ({
            title: item.data.title ?? item.slug,
            date: formatDate(
                item.data.date as string | Date | undefined,
                "DOCS"
            ),
            href: base + "docs/" + item.slug,
            category: item.data.category ?? "文档",
        })) as BreakingNewsItemProps[];

    const blogList = allBlog
        .slice()
        .reverse()
        .map((item) => ({
            title: item.data.title ?? item.slug,
            date: formatDate(
                item.data.date as string | Date | undefined,
                item.id.substring(0, 10)
            ),
            href: base + "blog/" + item.slug,
            category: item.data.category ?? "博客",
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
