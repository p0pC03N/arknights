import React from "react";

// 01-INDEX =====================================

export type HeroActionButtonProps = {
    icon: React.JSX.Element
    label: string
    subLabel?: string
    target?: "_blank" | "_top" | "_parent" | "_self"
    href: string
    className?: string
}

// 02-INFORMATION ===============================

export type BreakingNewsItemProps = {
    title: string,
    date: string,
    href: string,
    category: string,
}

export type SwiperData = {
    title: string,
    subtitle?: string,
    date?: string,
    url?: string,
    href: string,
    image?: string,
}

// 05-MEDIA ===========================

export type TerraOmniaArticle = {
  title: string
  subTitle?: string
  date?: string
  href: string
  locked?: boolean // 🔒 是否加密文章
}

export type TerraOmniaViewProps = {
  rightImage: string            // 右侧固定图片（像友链那样一直显示）
  articles: TerraOmniaArticle[] // 左侧 3/10 列表
}
