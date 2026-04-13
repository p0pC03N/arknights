import React from "react";

const base = import.meta.env.BASE_URL;

function withBase(url?: string) {
  if (!url) return url;
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith("/")) return base + url.slice(1);
  return base + url;
}

function getHostLabel(url: string) {
  try {
    return new URL(url).host.replace(/^www\./i, "");
  } catch {
    return url.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }
}

function getGlyph(name: string) {
  const clean = name.trim();
  return clean ? clean[0].toUpperCase() : "?";
}

const panelStatuses = ["ONLINE", "TRUSTED", "RELAY", "DIRECT", "KNOWN"];

export type FriendLink = {
  name: string;
  url: string;
  desc?: string;
  avatar?: string;
};

export default function FriendLinks({
  links,
  active = false,
}: {
  links: FriendLink[];
  active?: boolean;
}) {
  if (!links || links.length === 0) {
    return (
      <div className="friend-link-empty">
        <div className="friend-link-empty-kicker">PROFILE</div>
        <div className="friend-link-empty-title">NO LINKS CONFIGURED</div>
        <div className="friend-link-empty-copy">
          Add <code>rootPage.OPERATOR.friendLinks</code> in
          <code> arknights.config.tsx</code>.
        </div>
      </div>
    );
  }

  return (
    <div className="friend-link-grid" data-root-scroll-lock="true">
      {links.map((it, index) => {
        const status = panelStatuses[index % panelStatuses.length];
        const host = getHostLabel(it.url);

        return (
          <a
            key={it.url}
            href={it.url}
            target="_blank"
            rel="noreferrer"
            className={`friend-link-panel ${active ? "is-active" : ""}`}
            style={
              {
                "--panel-delay": `${index * 120}ms`,
              } as React.CSSProperties
            }
          >
            <span className="friend-link-panel-scan" />
            <div className="friend-link-panel-meta">
              <span className="friend-link-panel-id">
                LINK-{String(index + 1).padStart(2, "0")}
              </span>
              <span className="friend-link-panel-state">{status}</span>
            </div>

            <div className="friend-link-panel-main">
              <div className="friend-link-avatar-shell">
                {it.avatar ? (
                  <img
                    src={withBase(it.avatar)}
                    alt={it.name}
                    className="friend-link-avatar"
                    loading="lazy"
                  />
                ) : (
                  <div className="friend-link-avatar-fallback">
                    {getGlyph(it.name)}
                  </div>
                )}
              </div>

              <div className="friend-link-panel-copy">
                <div className="friend-link-panel-title">{it.name}</div>
                <div className="friend-link-panel-desc">
                  {it.desc || "No note attached."}
                </div>
              </div>
            </div>

            <div className="friend-link-panel-footer">
              <span className="friend-link-panel-host">{host}</span>
              <span className="friend-link-panel-enter">ENTER</span>
            </div>
          </a>
        );
      })}
    </div>
  );
}
