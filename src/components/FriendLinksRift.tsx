import type { CSSProperties } from "react";
import type { FriendLink } from "../_types/ArknightsConfig";

const base = import.meta.env.BASE_URL;
const fallbackStatuses = ["ONLINE", "TRACE", "ACCESS", "ARCHIVED", "RELAY"];
const panelSlots = ["west", "east", "south", "north", "south-east"];
const slotRevealOrder: Record<string, number> = {
  relay: 0,
  west: 0,
  east: 1,
  south: 2,
  north: 3,
  "south-east": 4,
};

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

function getPanelCode(link: FriendLink, index: number) {
  return link.code ?? `NODE ${String(index + 1).padStart(2, "0")}`;
}

function getPanelStatus(link: FriendLink, index: number) {
  return (link.status ?? fallbackStatuses[index % fallbackStatuses.length]).toUpperCase();
}

function getPanelSlot(count: number, index: number) {
  if (count <= 1) return "relay";
  if (count === 2) return ["west", "east"][index] ?? "east";
  if (count === 3) return ["west", "east", "south"][index] ?? "south";
  if (count === 4) return ["west", "east", "north", "south"][index] ?? "south";
  return panelSlots[index % panelSlots.length];
}

type FriendLinksRiftProps = {
  links: FriendLink[];
  active?: boolean;
  reducedMotion?: boolean;
};

export default function FriendLinksRift({
  links,
  active = false,
  reducedMotion = false,
}: FriendLinksRiftProps) {
  if (!links || links.length === 0) {
    return (
      <div className="rift-links-empty">
        <div className="rift-links-empty-kicker">PROFILE</div>
        <div className="rift-links-empty-title">NO RELAYS CONFIGURED</div>
        <div className="rift-links-empty-copy">
          Add <code>rootPage.OPERATOR.friendLinks</code> in
          <code> arknights.config.tsx</code>.
        </div>
      </div>
    );
  }

  return (
    <div
      className={`rift-links-panel-field rift-links-panel-field--count-${Math.min(
        links.length,
        5,
      )}`}
      data-root-scroll-lock="true"
    >
      {links.map((link, index) => {
        const slot = getPanelSlot(links.length, index);
        const status = getPanelStatus(link, index);
        const code = getPanelCode(link, index);
        const host = getHostLabel(link.url);
        const revealOrder = slotRevealOrder[slot] ?? index;

        return (
          <a
            key={link.url}
            href={link.url}
            target="_blank"
            rel="noreferrer"
            aria-label={`${link.name} - ${status}`}
            className={`rift-link-panel rift-link-panel--${slot} ${
              active ? "is-active" : ""
            } ${reducedMotion ? "is-reduced" : ""}`}
            style={
              {
                "--panel-delay": reducedMotion ? "0ms" : `${260 + revealOrder * 150}ms`,
              } as CSSProperties
            }
          >
            <span className="rift-link-panel-scan" />
            <span className="rift-link-panel-noise" />

            <div className="rift-link-panel-head">
              <span className="rift-link-panel-code">{code}</span>
              <span className="rift-link-panel-status">
                <span className="rift-link-panel-status-dot" />
                {status}
              </span>
            </div>

            <div className="rift-link-panel-body">
              <div className="rift-link-panel-avatar-shell" aria-hidden="true">
                {link.avatar ? (
                  <img
                    src={withBase(link.avatar)}
                    alt=""
                    className="rift-link-panel-avatar"
                    loading="lazy"
                  />
                ) : (
                  <div className="rift-link-panel-avatar-fallback">
                    {getGlyph(link.name)}
                  </div>
                )}
              </div>

              <div className="rift-link-panel-copy">
                <h3 className="rift-link-panel-title">{link.name}</h3>
                <p className="rift-link-panel-desc">
                  {link.desc || "No annotation attached."}
                </p>
              </div>
            </div>

            <div className="rift-link-panel-foot">
              <span className="rift-link-panel-host">{host}</span>
              <span className="rift-link-panel-action">ACCESS</span>
            </div>
          </a>
        );
      })}
    </div>
  );
}
