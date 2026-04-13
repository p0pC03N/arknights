import type { CSSProperties } from "react";
import type { FriendLink } from "../_types/ArknightsConfig";

const fallbackStatuses = ["ONLINE", "TRACE", "ACCESS"];
const nodeSlots = ["west", "east"];

function getNodeCode(link: FriendLink, index: number) {
  return link.code ?? `NODE ${String(index + 1).padStart(2, "0")}`;
}

function getNodeStatus(link: FriendLink, index: number) {
  return (link.status ?? fallbackStatuses[index % fallbackStatuses.length]).toUpperCase();
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
  const nodes = links.slice(0, 2);

  if (nodes.length === 0) {
    return null;
  }

  return (
    <div className={`rift-relay-node-layer ${active ? "is-visible" : ""}`}>
      {nodes.map((link, index) => {
        const slot = nodeSlots[index] ?? "east";
        const code = getNodeCode(link, index);
        const status = getNodeStatus(link, index);

        return (
          <a
            key={link.url}
            href={link.url}
            target="_blank"
            rel="noreferrer"
            className={`rift-relay-node rift-relay-node--${slot} ${
              active ? "is-active" : ""
            } ${reducedMotion ? "is-reduced" : ""}`}
            style={
              {
                "--node-delay": reducedMotion ? "0ms" : `${220 + index * 160}ms`,
              } as CSSProperties
            }
          >
            <div className="rift-relay-node-head">
              <span className="rift-relay-node-code">{code}</span>
              <span className="rift-relay-node-dot" />
            </div>
            <div className="rift-relay-node-name">{link.name}</div>
            <div className="rift-relay-node-status">{status}</div>
          </a>
        );
      })}
    </div>
  );
}
