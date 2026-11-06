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

## 塔罗友链

`/#operator` 保留整副牌的随机抽取玩法，友链统一维护在 `src/data/friend-links.json`：

```json
{ "id": "unique-name", "name": "朋友的名字", "url": "https://example.com" }
```

新增时向数组添加一项，使用唯一的 `id` 和完整的 HTTPS 地址，然后重新构建发布即可。牌组、加载失败时的直达链接和星门过渡页共用这份列表，不需要单独配置动画或素材。

牌组与星门分别位于 `src/pages/friend-links.astro`、`src/pages/friend-links-gate.astro`，交互脚本位于 `src/scripts/friend-links-*.js`。牌图使用 `public/friend-links-deck/*.webp`；首次只加载共享牌背，翻牌时才加载对应牌面。页面离开时暂停渲染，返回时复用场景。加载失败时提供重试和直接访问友链的入口。

## 暂停展示的功能

小猫功能通过 `src/features.ts` 中的 `CAT_ENABLED = false` 暂停展示：首页唤猫、CAT 导航与页面、文章阅读奖励均不启用，旧 `#more` 链接返回首页。实现、素材和浏览器本地存档保留；以后可将开关改为 `true` 后重新构建发布。

## 封存档案与粒子守档人

独立 WORLD 页已从导航和运行时页面列表撤下，旧 `#world` 链接转到 `#media`。封存页采用细线目录、按需加载的加密档案和粒子罗小黑：`src/pages/_views/04-Media.tsx`、`src/components/ArchiveGuardian.tsx`、`src/_styles/archive.css`。

粒子从轻量矢量轮廓 `public/images/archive/xiaohei.svg` 采样，支持鼠标拨散、归位、呼吸和眨眼，离开栏目或切到后台时暂停；减少动态效果模式显示静态粒子。它只负责视觉效果，与暂停中的养猫功能和存档无关。打开档案后阅读区展开，手机端保留独立的正文滚动区。

## 许可证

本仓库保留上游模板的 `MIT License`。当前站点基于 [Yue-plus/astro-arknights](https://github.com/Yue-plus/astro-arknights) 二次开发，后续视觉和内容会逐步替换为个人站点版本。
