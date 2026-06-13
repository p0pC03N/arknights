import type { CatCoatId } from "./catProfile";

type PixelCatProps = {
  coat: CatCoatId;
  outfit?: {
    head?: string;
    face?: string;
    collar?: string;
    clothes?: string;
    tail?: string;
  };
  mood?: "idle" | "happy" | "hungry";
  onClick?: () => void;
  className?: string;
};

const compositeState = ["none", "sunglasses", "blueScarf", "bell", "sunglasses-blueScarf", "sunglasses-bell"] as const;
const suitState = ["red-ribbon-bow", "sleep-cap", "headphones", "explorer-backpack", "rain-poncho", "star-charm-collar"] as const;

type CompositeState = (typeof compositeState)[number];
type SuitState = (typeof suitState)[number];

function compositeAsset(coat: CatCoatId, state: CompositeState) {
  return `/images/cat/composites/${coat}-${state}.png`;
}

function suitAsset(coat: CatCoatId, state: SuitState) {
  return `/images/cat/upload-ready/v2-accessories/cat-${coat}-${state}.png`;
}

function isSuitState(value: string | undefined): value is SuitState {
  return Boolean(value && (suitState as readonly string[]).includes(value));
}

const itemBadgeAsset: Record<string, string> = {
  "face:sunglasses": "/images/cat/composites/tabbyWhite-sunglasses.png",
  "collar:bell": "/images/cat/composites/tabbyWhite-bell.png",
  "collar:blueScarf": "/images/cat/composites/tabbyWhite-blueScarf.png",
  "clothes:red-ribbon-bow": "/images/cat/upload-ready/v2-accessories/cat-tabbyWhite-red-ribbon-bow.png",
  "clothes:sleep-cap": "/images/cat/upload-ready/v2-accessories/cat-tabbyWhite-sleep-cap.png",
  "clothes:headphones": "/images/cat/upload-ready/v2-accessories/cat-tabbyWhite-headphones.png",
  "clothes:explorer-backpack": "/images/cat/upload-ready/v2-accessories/cat-tabbyWhite-explorer-backpack.png",
  "clothes:rain-poncho": "/images/cat/upload-ready/v2-accessories/cat-tabbyWhite-rain-poncho.png",
  "clothes:star-charm-collar": "/images/cat/upload-ready/v2-accessories/cat-tabbyWhite-star-charm-collar.png",
};

function layerKeys(outfit: PixelCatProps["outfit"]) {
  return [
    outfit?.face ? `face:${outfit.face}` : "",
    outfit?.collar ? `collar:${outfit.collar}` : "",
    outfit?.clothes ? `clothes:${outfit.clothes}` : "",
  ].filter(Boolean);
}

export default function PixelCat({ coat, outfit = {}, mood = "idle", onClick, className = "" }: PixelCatProps) {
  const equippedBadges = layerKeys(outfit).filter((key) => Boolean(itemBadgeAsset[key]));
  const suit = isSuitState(outfit.clothes) ? outfit.clothes : undefined;
  const state: CompositeState =
    outfit.face === "sunglasses" && outfit.collar === "blueScarf"
      ? "sunglasses-blueScarf"
      : outfit.face === "sunglasses" && outfit.collar === "bell"
        ? "sunglasses-bell"
        : outfit.collar === "blueScarf"
          ? "blueScarf"
          : outfit.collar === "bell"
            ? "bell"
            : outfit.face === "sunglasses"
              ? "sunglasses"
              : "none";

  return (
    <button
      type="button"
      onClick={onClick}
      className={`group relative inline-flex min-h-[27rem] min-w-[27rem] items-center justify-center border-2 border-black bg-[#fff7df] p-6 shadow-[7px_7px_0_#000] transition-transform hover:-translate-y-1 active:translate-x-[3px] active:translate-y-[3px] active:shadow-none ${mood === "happy" ? "cat-cover-pop" : ""} ${mood === "hungry" ? "cat-hungry-wiggle" : ""} ${className}`}
      aria-label="摸摸小猫"
    >
      <span className="relative block flex-none" style={{ width: "24rem", height: "32rem" }}>
        <img
          src={suit ? suitAsset(coat, suit) : compositeAsset(coat, state)}
          alt=""
          draggable={false}
          className="absolute inset-0 h-full w-full object-contain [image-rendering:pixelated]"
        />
      </span>
      <div className="absolute bottom-3 left-3 flex max-w-[18rem] flex-wrap gap-2">
        {equippedBadges.map((key) => (
          <span key={key} className="grid h-12 w-12 place-items-center border-2 border-black bg-white shadow-[3px_3px_0_#000]">
            <img src={itemBadgeAsset[key]} alt="" draggable={false} className="h-10 w-10 object-contain [image-rendering:pixelated]" />
          </span>
        ))}
      </div>
    </button>
  );
}
