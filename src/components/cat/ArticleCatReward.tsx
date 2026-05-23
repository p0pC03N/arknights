import { useEffect, useState } from "react";
import { claimArticleReward } from "./catProfile";

export default function ArticleCatReward({ articleId }: { articleId: string }) {
  const [message, setMessage] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const result = claimArticleReward(articleId);
      if (result.claimed) {
        setMessage(`${result.profile.name} 读完文章，叼来 1 个罐头。`);
        window.setTimeout(() => setMessage(""), 4200);
      }
    }, 2400);

    return () => window.clearTimeout(timer);
  }, [articleId]);

  if (!message) return null;

  return (
    <div className="fixed bottom-8 right-8 z-[80] max-w-[20rem] border-2 border-black bg-[#ffee22] px-4 py-3 font-bold text-black shadow-[6px_6px_0_#000] portrait:left-4 portrait:right-4">
      {message}
    </div>
  );
}
