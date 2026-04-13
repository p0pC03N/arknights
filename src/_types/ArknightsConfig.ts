import React from "react";
import type { AutoplayOptions } from "swiper/types";
import type { HeroActionButtonProps, SwiperData } from "./RootPageViews.ts";

export type NavbarItem = {
  title: string;
  subtitle: string;
  href: string;
};

export type OwnerInfoFooterLink = {
  label: string;
  url: string;
  portraitHidden?: boolean;
};

export type FriendLink = {
  name: string;
  url: string;
  desc?: string;
  avatar?: string;
  status?: string;
  code?: string;
};

// ✅ 泰拉万象（MEDIA）文章条目
export type TerraOmniaArticle = {
  title: string;
  subTitle?: string;
  date?: string;
  href: string;
  locked?: boolean; // 🔒 是否加密
  secretId?: string; // 🔒 对应 src/content/secret/<id>.payload.json 的 <id>
  keyHint?: string;  // 🔒 输入框提示文案（例如“提示：Xi3xi3”）
  rememberKey?: string; // 🔒 localStorage 的 key（不同文档可用不同 key）
};

export type ArknightsConfig = {
  title: string;
  description: string;
  language: string;

  bgm: {
    autoplay: boolean;
    src: string;
  };

  navbar: {
    logo: {
      element: () => React.JSX.Element;
      alt: string;
    };
    items: NavbarItem[];
    toolbox: {
      Skland?: string;
      Bilibili?: string;
      WeChat?: string;
      Weibo?: string;
      TapTap?: string;
      GitHub?: string;

      // ✅ 你要加邮箱就加这个
      Email?: string;
    };
    ownerInfo: {
      name?: string;
      slogan?: string;
      footerLinks?: OwnerInfoFooterLink[];
    };
  };

  pageTracker: {
    microInfo: string;
    labels: string[];
  };

  rootPage: {
    INDEX: {
      title: string;
      subtitle: string;
      url: string;
      copyright: React.JSX.Element;
      heroActions: HeroActionButtonProps[];
    };

    INFORMATION: {
      swiper: {
        autoplay?: boolean | AutoplayOptions | undefined;
        data: SwiperData[];
      };
    };

    // ✅ 干员页（用来挂友链数据）
    OPERATOR?: {
      friendLinks?: FriendLink[];
    };

    WORLD: {
      items: {
        title: string;
        subTitle: string;
        imageUrl: string;
        description: string;
      }[];
    };

    // ✅ 新增：MEDIA（泰拉万象）
    MEDIA?: {
      rightImage: string; // 右侧固定一张图（像友链那样）
      articles: TerraOmniaArticle[]; // 左侧 3/10 列表
    };
  };
};

