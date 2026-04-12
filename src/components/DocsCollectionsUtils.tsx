import { getCollection } from "astro:content";
import type { SubNavigationItem } from "../_types/SubNavigationItem";
import { filterPublishedEntries, sortDocEntries, trimSlugPrefix } from "../content/utils";

const base = import.meta.env.BASE_URL;
const allDocs = sortDocEntries(filterPublishedEntries(await getCollection("docs")));

/**
 * 去除 slug 的前缀
 * 
 * @param {string} slug 示例输入：`01_用户文档/01_项目介绍`
 * @returns {string} 示例输出：`用户文档/项目介绍`
 */
export function getDocsUrlBySlug(slug: string): string {
    return base + "docs/" + trimSlugPrefix(slug);
}

export function getDocsSubNavigationItems(): SubNavigationItem[] {
    return allDocs.map(({ id, slug, data }) => ({
        title: data.title ?? trimSlugPrefix(slug).split("/").at(-1) ?? id,
        href: getDocsUrlBySlug(slug),
    }));
}
