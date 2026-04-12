# 发文与发布规范

这个仓库现在已经把博客和文档的内容格式做成了可校验模式。`pnpm build` 或 GitHub Actions 构建时，格式不对会直接报错。

## 1. 博客

- 目录：`src/content/blog/`
- 推荐命名：`YYYY-MM-DD_文章标题.md`
- 说明：博客路由直接使用文件名生成 slug，所以建议一直保留日期前缀。

最小示例：

```md
---
title: 文章标题
description: 一句话摘要
date: "2026-04-12 20:00:00"
thumbnail: DeveloperConversation.png
category: 日志
draft: false
---

# 文章标题

正文内容
```

字段规则：

- `title`：必填
- `date`：必填，支持常见日期时间字符串
- `description`：可选，建议填写，后续可以直接用于 SEO 摘要
- `thumbnail`：可选，对应 `public/info-thumbnail/` 下的文件名
- `category`：可选，不填时默认显示 `BLOG`
- `draft`：可选，设为 `true` 后不会出现在列表页，也不会生成静态页面

## 2. 文档

- 目录：`src/content/docs/`
- 推荐命名：
  - 单篇：`文章标题.md`
  - 分组：`01_专题/01_文章标题.md`
- 说明：文档页支持用数字前缀控制目录顺序，实际访问链接会自动去掉前缀。

最小示例：

```md
---
title: 文档标题
description: 这篇文档讲什么
date: "2026-04-12"
order: 10
thumbnail: ACTIVITY.jpg
category: DOCS
draft: false
---

# 文档标题

正文内容
```

字段规则：

- `title`：必填
- `date`：必填
- `description`：可选，建议填写
- `order`：可选，数值越小越靠前；没有时按文件路径排序
- `thumbnail`：可选，对应 `public/info-thumbnail/` 下的文件名
- `category`：可选，不填时默认显示 `DOCS`
- `draft`：可选，设为 `true` 后不会公开

## 3. 缩略图与静态资源

- 博客/文档卡片缩略图：放在 `public/info-thumbnail/`
- 页面内引用的大图、音频、视频：放在 `public/` 对应子目录
- 不要把 `.psd`、源工程文件直接当线上资源使用，建议移出 `public/`

## 4. 加密文档

加密文档不走 `src/content/docs/`，而是走 payload：

- 密文目录：`src/content/secret/`
- 路由入口：`/terra-omnia/<id>`

生成方式：

```powershell
node .\src\scripts\encrypt-doc.mjs input.html .\src\content\secret\secret-03.payload.json your-password
```

生成后还需要在 `arknights.config.tsx` 的 `rootPage.MEDIA.articles` 里补一条入口。

## 5. 发布流程

本地检查：

```powershell
corepack pnpm install
corepack pnpm build
```

发布：

```powershell
git add .
git commit -m "Add new post"
git push origin main
```

推送到 `main` 后，GitHub Actions 会自动部署到 GitHub Pages。
