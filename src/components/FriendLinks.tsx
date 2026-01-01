import React from "react";

const base = import.meta.env.BASE_URL;

function withBase(url?: string) {
  if (!url) return url;
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith("/")) return base + url.slice(1);
  return base + url;
}

export type FriendLink = {
  name: string;
  url: string;
  desc?: string;
  avatar?: string;
};

export default function FriendLinks({ links }: { links: FriendLink[] }) {
  if (!links || links.length === 0) {
    return (
      <div className="w-full max-w-5xl mx-auto p-6 text-white/80">
        <div className="text-xl font-bold mb-2">友链</div>
        <div className="text-sm opacity-80">
          暂无友链（去 arknights.config.tsx 添加 friendLinks）
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-5xl mx-auto p-6 text-white">
      <div className="mb-4">
        <div className="text-2xl font-bold">友链</div>
        <div className="text-sm opacity-70">Links / Friends</div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {links.map((it) => (
          <a
            key={it.url}
            href={it.url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-4 rounded-xl border border-white/10 hover:border-white/30 bg-black/30 p-4 transition"
          >
            {it.avatar ? (
              <img
                src={withBase(it.avatar)}
                alt={it.name}
                className="w-12 h-12 rounded-full object-cover"
                loading="lazy"
              />
            ) : (
              <div className="w-12 h-12 rounded-full bg-white/10" />
            )}

            <div className="min-w-0">
              <div className="font-semibold text-lg truncate">{it.name}</div>
              {it.desc && (
                <div className="text-sm opacity-80 truncate">{it.desc}</div>
              )}
              <div className="text-xs opacity-60 truncate">{it.url}</div>
            </div>
          </a>
        ))}
      </div>
    </div>
  );
}
