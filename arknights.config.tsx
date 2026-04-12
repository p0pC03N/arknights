import type { ArknightsConfig } from "./src/_types/ArknightsConfig";
import { CopyrightMini, IconArchive, IconGitHub } from "./src/components/SvgIcons";

const base = import.meta.env.BASE_URL;

const config: ArknightsConfig = {
  title: "玉米王国",
  description: "逆向、CTF 与个人记录站",
  language: "zh",

  bgm: {
    autoplay: false,
    src: base + "audios/bgm.mp3",
  },

  navbar: {
    logo: {
      element: () => (
        <div className="w-full h-full flex flex-col justify-center text-white leading-none pointer-events-none select-none">
          <div className="font-oswaldMedium text-[1.65rem] portrait:text-[2.2rem] tracking-[0.18em]">玉米</div>
          <div className="text-[0.55rem] portrait:text-[0.8rem] tracking-[0.35em] text-[#bdbdbd] mt-1">
            CORN KINGDOM
          </div>
        </div>
      ),
      alt: "玉米王国",
    },

    items: [
      { title: "INDEX", subtitle: "首页", href: base + "#index" },
      { title: "SIGNAL", subtitle: "动态", href: base + "#information" },
      { title: "PROFILE", subtitle: "名片", href: base + "#operator" },
      { title: "DOSSIER", subtitle: "归档", href: base + "#world" },
      { title: "ARCHIVE", subtitle: "封存", href: base + "#media" },
      { title: "MORE", subtitle: "更多内容", href: base + "#more" },
    ],

    toolbox: {
      Email: "mailto:1433209484@qq.com",
      GitHub: "https://github.com/p0pC03N/arknights",
    },

    ownerInfo: {
      name: "p0pC03N",
      slogan: "Cause you and I,we are born to die",
      footerLinks: [
        { label: "GitHub", url: "https://github.com/p0pC03N" },
        { label: "Email", url: "mailto:1433209484@qq.com" },
      ],
    },
  },

  pageTracker: {
    microInfo: "CORN KINGDOM",
    labels: ["HOMEPAGE", "SIGNAL", "PROFILE", "DOSSIER", "ARCHIVE", "MORE"],
  },

  rootPage: {
    INDEX: {
      title: "CORN KINGDOM",
      subtitle: "PERSONAL ARCHIVE",
      url: "HTTPS://P0PC03N.GITHUB.IO/ARKNIGHTS/",
      copyright: <CopyrightMini className="pointer-events-none" />,
      heroActions: [
        {
          icon: <IconArchive className="w-full h-auto pointer-events-none" />,
          label: "文档",
          subLabel: "Documentation",
          target: "_self",
          href: base + "docs/",
          className: "text-black bg-ark-blue border-[#2bf] hover:border-white font-bold font-benderBold",
        },
        {
          icon: (
            <svg className="w-full h-auto pointer-events-none" fillRule="evenodd" fill="currentColor" viewBox="0 0 1024 1024">
              <path d="M856.874667 448l51.285333 30.762667a21.333333 21.333333 0 0 1 0 36.608L512 753.066667l-396.16-237.696a21.333333 21.333333 0 0 1 0-36.608l51.285333-30.762667L512 654.933333l344.874667-206.933333z m0 200.533333l51.285333 30.762667a21.333333 21.333333 0 0 1 0 36.608l-374.186667 224.512a42.666667 42.666667 0 0 1-43.946666 0l-374.186667-224.512a21.333333 21.333333 0 0 1 0-36.608l51.285333-30.762667L512 855.466667l344.874667-206.933334zM533.930667 55.850667l374.229333 224.512a21.333333 21.333333 0 0 1 0 36.608L512 554.666667 115.84 316.970667a21.333333 21.333333 0 0 1 0-36.608l374.186667-224.512a42.666667 42.666667 0 0 1 43.946666 0z" />
            </svg>
          ),
          label: "博客日志",
          subLabel: "Blog Journal",
          target: "_self",
          href: base + "blog/",
          className: "text-black bg-end-yellow border-[#fe2] hover:border-white font-bold font-benderBold",
        },
        {
          icon: <IconGitHub className="w-full h-auto pointer-events-none" />,
          label: "GitHub",
          subLabel: "Repository",
          target: "_blank",
          href: "https://github.com/p0pC03N",
          className: "text-white bg-black border-[#333] hover:border-white font-benderBold",
        },
      ],
    },

    INFORMATION: {
      swiper: {
        autoplay: { delay: 5000 },
        data: [
          {
            title: "技术文档",
            subtitle: "Technical Notes",
            date: "2026 // 01 / 14",
            url: "HTTPS://P0PC03N.GITHUB.IO/ARKNIGHTS/",
            href: base + "docs/",
            image: base + "info-swiper/UserDocumentation.jpg",
          },
          {
            title: "博客日志",
            subtitle: "Blog Journal",
            date: "2026 // 01 / 01",
            url: "HTTPS://P0PC03N.GITHUB.IO/ARKNIGHTS/",
            href: base + "blog/",
            image: base + "info-swiper/DeveloperDocumentation.jpg",
          },
          {
            title: "封存档案",
            subtitle: "Secret Gate",
            date: "2026 // 01 / 23",
            url: "HTTPS://P0PC03N.GITHUB.IO/ARKNIGHTS/",
            href: base + "#media",
            image: base + "info-swiper/Blog.jpg",
          },
        ],
      },
    },

    OPERATOR: {
      friendLinks: [
        {
          name: "xiexie",
          url: "https://xiexie-qiuligao.github.io",
          desc: "长发快乐男（本人如是说）",
          avatar: "/images/friends/xiexie_friendlink.png",
        },
      ],
    },

    WORLD: {
      items: [
        {
          title: "逆向工程",
          subTitle: "REVERSE",
          imageUrl: "/images/03-world/originiums.png",
          description: "拆程序，记思路，少走弯路。",
        },
        {
          title: "CTF 题解",
          subTitle: "WRITEUPS",
          imageUrl: "/images/03-world/originium_arts.png",
          description: "打过的题，顺手记下来。",
        },
        {
          title: "工具链",
          subTitle: "TOOLCHAIN",
          imageUrl: "/images/03-world/reunion.png",
          description: "脚本、配置，还有那些省事小玩意。",
        },
        {
          title: "站点文档",
          subTitle: "DOCS",
          imageUrl: "/images/03-world/infected.png",
          description: "写给未来的自己，免得又忘。",
        },
        {
          title: "年度记录",
          subTitle: "YEARBOOK",
          imageUrl: "/images/03-world/nomadic_city.png",
          description: "一年到头，总得有个地方收着。",
        },
        {
          title: "封存档案",
          subTitle: "ARCHIVE",
          imageUrl: "/images/03-world/rhodes_island.png",
          description: "这块得先敲门，再看。",
        },
      ],
    },

    MEDIA: {
      rightImage: base + "images/terra/right.jpg",
      articles: [
        {
          title: "封存档案-01",
          subTitle: "SEALED",
          date: "2026 // 01 / 18",
          href: base + "terra-omnia/secret-01",
          locked: true,
        },
        {
          title: "封存档案-02",
          subTitle: "SEALED",
          date: "2026 // 01 / 23",
          href: base + "terra-omnia/secret-02",
          locked: true,
        },
      ],
    },
  },
};

export default config;
