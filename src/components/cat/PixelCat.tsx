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

type CompositeState = (typeof compositeState)[number];

function compositeAsset(coat: CatCoatId, state: CompositeState) {
  return `/images/cat/composites/${coat}-${state}.png`;
}

const itemBadgeAsset: Record<string, string> = {
  "face:sunglasses": "/images/cat/composites/tabbyWhite-sunglasses.png",
  "collar:bell": "/images/cat/composites/tabbyWhite-bell.png",
  "collar:blueScarf": "/images/cat/composites/tabbyWhite-blueScarf.png",
};

function layerKeys(outfit: PixelCatProps["outfit"]) {
  return [
    outfit?.face ? `face:${outfit.face}` : "",
    outfit?.collar ? `collar:${outfit.collar}` : "",
  ].filter(Boolean);
}

export default function PixelCat({ coat, outfit = {}, mood = "idle", onClick, className = "" }: PixelCatProps) {
  const equippedBadges = layerKeys(outfit).filter((key) => Boolean(itemBadgeAsset[key]));
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
      className={`group relative inline-flex min-h-[27rem] min-w-[27rem] items-center justify-center border-2 border-black bg-[#fff7df] p-6 shadow-[7px_7px_0_#000] transition-transform hover:-translate-y-1 active:translate-x-[3px] active:translate-y-[3px] active:shadow-none ${mood === "happy" ? "animate-[cat-cover-pop_.68s_steps(5,end)]" : ""} ${className}`}
      aria-label="摸摸小猫"
    >
      <span className="relative block flex-none" style={{ width: "24rem", height: "32rem" }}>
        <img
          src={compositeAsset(coat, state)}
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
