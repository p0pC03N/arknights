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

const poseAsset: Record<NonNullable<PixelCatProps["mood"]>, string> = {
  idle: "/images/cat/cat-idle.png",
  happy: "/images/cat/cat-happy.png",
  hungry: "/images/cat/cat-feed.png",
};

const coatAsset: Record<CatCoatId, string> = {
  tabbyWhite: "/images/cat/cat-card-tabby-white.png",
  whitePaws: "/images/cat/cat-card-white-paws.png",
  orange: "/images/cat/cat-card-orange.png",
  black: "/images/cat/cat-card-black.png",
  calico: "/images/cat/cat-card-calico.png",
};

const outfitAsset: Record<string, string> = {
  "face:sunglasses": "/images/cat/cat-sunglasses.png",
  "face:roundGlasses": "/images/cat/cat-glasses.png",
  "head:tinyHat": "/images/cat/cat-hat.png",
  "collar:bell": "/images/cat/cat-bell.png",
  "clothes:blueScarf": "/images/cat/cat-scarf.png",
};

const badgeAsset: Record<string, string> = {
  "head:tinyHat": "/images/cat/item-straw-hat.png",
  "face:sunglasses": "/images/cat/item-sunglasses.png",
  "face:roundGlasses": "/images/cat/item-round-glasses.png",
  "collar:bell": "/images/cat/item-bell-collar.png",
  "clothes:blueScarf": "/images/cat/item-blue-scarf.png",
  "tail:yarn": "/images/cat/item-yarn.png",
  "tail:luckyFish": "/images/cat/item-lucky-fish.png",
};

function selectedCatAsset(coat: CatCoatId, outfit: PixelCatProps["outfit"], mood: NonNullable<PixelCatProps["mood"]>) {
  const keys = [
    outfit?.face ? `face:${outfit.face}` : "",
    outfit?.head ? `head:${outfit.head}` : "",
    outfit?.clothes ? `clothes:${outfit.clothes}` : "",
  ];
  const found = keys.map((key) => outfitAsset[key]).find(Boolean);
  if (found) return found;
  if (mood !== "idle") return poseAsset[mood];
  if (coat === "tabbyWhite" && outfit?.collar === "bell") return outfitAsset["collar:bell"];
  return coatAsset[coat];
}

export default function PixelCat({ coat, outfit = {}, mood = "idle", onClick, className = "" }: PixelCatProps) {
  const equippedBadges = [
    outfit.head ? `head:${outfit.head}` : "",
    outfit.face ? `face:${outfit.face}` : "",
    outfit.collar ? `collar:${outfit.collar}` : "",
    outfit.clothes ? `clothes:${outfit.clothes}` : "",
    outfit.tail ? `tail:${outfit.tail}` : "",
  ].filter((key) => Boolean(key && badgeAsset[key]));

  return (
    <button
      type="button"
      onClick={onClick}
      className={`group relative inline-flex min-h-[21rem] min-w-[21rem] items-center justify-center border-2 border-black bg-[#fff7df] p-6 shadow-[7px_7px_0_#000] transition-transform hover:-translate-y-1 active:translate-x-[3px] active:translate-y-[3px] active:shadow-none ${className}`}
      aria-label="摸摸小猫"
    >
      <img
        src={selectedCatAsset(coat, outfit, mood)}
        alt=""
        draggable={false}
        className="max-h-[19rem] max-w-[19rem] object-contain [image-rendering:pixelated] group-hover:rotate-[-1deg]"
      />
      <div className="absolute bottom-3 left-3 flex max-w-[18rem] flex-wrap gap-2">
        {equippedBadges.map((key) => (
          <span key={key} className="grid h-12 w-12 place-items-center border-2 border-black bg-white shadow-[3px_3px_0_#000]">
            <img src={badgeAsset[key]} alt="" draggable={false} className="h-10 w-10 object-contain [image-rendering:pixelated]" />
          </span>
        ))}
      </div>
    </button>
  );
}
