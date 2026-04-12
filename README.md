# 玉米王国

`玉米王国` 是 `p0pC03N` 的个人站点仓库，用来发布博客、技术文档和带密码入口的封存档案。站点基于 Astro 构建，当前部署目标为 GitHub Pages。

## 内容结构

- 博客：`src/content/blog`
- 文档：`src/content/docs`
- 加密档案：`src/content/secret`
- 站点说明：`CONTENT_GUIDE.md`

博客和文档都使用内容集合管理。发文时请优先填写 frontmatter，并按 `CONTENT_GUIDE.md` 里的规则放置缩略图和文件名。

## 本地运行

```bash
git clone https://github.com/p0pC03N/arknights.git
cd arknights
corepack pnpm install
corepack pnpm dev
```

默认开发地址：`http://localhost:4321/arknights/`

## 构建与发布

```bash
corepack pnpm build
git add .
git commit -m "your message"
git push origin main
```

推送到 `main` 后会触发 GitHub Actions 部署。

## 许可证

本仓库保留上游模板的 `MIT License`。当前站点基于 [Yue-plus/astro-arknights](https://github.com/Yue-plus/astro-arknights) 二次开发，后续视觉和内容会逐步替换为个人站点版本。
