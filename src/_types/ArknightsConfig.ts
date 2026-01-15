export type TerraOmniaArticle = {
  title: string
  subTitle?: string
  date?: string
  href: string
  locked?: boolean   // 🔒 是否加密
}

export type ArknightsConfig = {
  // ...前面不动

  rootPage: {
    INDEX: {
      title: string
      subtitle: string
      url: string
      copyright: React.JSX.Element
      heroActions: HeroActionButtonProps[]
    },

    INFORMATION: {
      swiper: {
        autoplay?: boolean | AutoplayOptions | undefined
        data: SwiperData[]
      }
    },

    OPERATOR?: {
      friendLinks?: FriendLink[]
    },

    WORLD: {
      items: {
        title: string,
        subTitle: string,
        imageUrl: string,
        description: string,
      }[]
    },

    // ✅ 新增：MEDIA（泰拉万象）
    MEDIA?: {
      rightImage: string            // 右侧固定一张图（像友链那样）
      articles: TerraOmniaArticle[] // 左侧 3/10 列表
    }
  }
}
