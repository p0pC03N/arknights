import { defineCollection, z } from "astro:content";

const optionalText = z
  .string()
  .trim()
  .optional()
  .nullable()
  .transform((value) => (value ? value : undefined));

/**
 * 定义集合
 * [参考](https://docs.astro.build/zh-cn/guides/content-collections/#%E5%AE%9A%E4%B9%89%E9%9B%86%E5%90%88)
 *
 * Defining Collections
 * [Reference](https://docs.astro.build/en/guides/content-collections/#defining-collections)
 */
export const config = {
  blog: defineCollection({
    type: "content",
    schema: z.object({
      title: z.string().trim().min(1, "博客文章必须填写 title"),
      description: optionalText,
      date: z.coerce.date(),
      thumbnail: optionalText,
      category: optionalText,
      draft: z.boolean().default(false),
    }),
  }),
  docs: defineCollection({
    type: "content",
    schema: z.object({
      title: z.string().trim().min(1, "文档必须填写 title"),
      description: optionalText,
      date: z.coerce.date(),
      thumbnail: optionalText,
      category: optionalText,
      order: z.number().int().optional(),
      draft: z.boolean().default(false),
    }),
  }),
};
