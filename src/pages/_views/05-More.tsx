import { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore.ts";
import { directions } from "../../components/store/lineDecoratorStore";
import PixelCat from "../../components/cat/PixelCat";
import {
  CAT_PROFILE_EVENT,
  claimMessageReward,
  feedCat,
  loadCatProfile,
  petCat,
  saveCatProfile,
} from "../../components/cat/catProfile";
import type { CatCoatId, CatOutfitSlot, CatProfile } from "../../components/cat/catProfile";

type WardrobeItem = {
  id: string;
  label: string;
  icon: string;
  slot: CatOutfitSlot | "coat";
  value: string;
  rarity: "普通" | "史诗" | "传说";
  price?: {
    kind: "cans" | "driedFish";
    amount: number;
  };
};

const wardrobeTabs: Array<WardrobeItem["slot"]> = ["coat", "face", "collar"];
const wardrobeTabLabels: Record<WardrobeItem["slot"], string> = {
  coat: "毛色",
  head: "头部",
  face: "面部",
  collar: "项圈",
  clothes: "衣服",
  tail: "玩具",
};

const wardrobeItems: WardrobeItem[] = [
  { id: "coat:tabbyWhite", label: "狸花白胸", icon: "/images/cat/composites/tabbyWhite-none.png", slot: "coat", value: "tabbyWhite", rarity: "普通" },
  { id: "coat:whitePaws", label: "四脚踏雪", icon: "/images/cat/composites/whitePaws-none.png", slot: "coat", value: "whitePaws", rarity: "普通" },
  { id: "coat:orange", label: "纯橘猫", icon: "/images/cat/composites/orange-none.png", slot: "coat", value: "orange", rarity: "史诗" },
  { id: "coat:black", label: "纯黑猫", icon: "/images/cat/composites/black-none.png", slot: "coat", value: "black", rarity: "史诗" },
  { id: "coat:white", label: "纯白猫", icon: "/images/cat/composites/white-none.png", slot: "coat", value: "white", rarity: "史诗" },
  { id: "coat:cow", label: "奶牛猫", icon: "/images/cat/composites/cow-none.png", slot: "coat", value: "cow", rarity: "史诗" },
  { id: "coat:calico", label: "三花幸运", icon: "/images/cat/composites/calico-none.png", slot: "coat", value: "calico", rarity: "传说" },
  { id: "coat:gray", label: "纯灰猫", icon: "/images/cat/composites/gray-none.png", slot: "coat", value: "gray", rarity: "普通" },
  { id: "collar:bell", label: "小铃铛", icon: "/images/cat/composites/tabbyWhite-bell.png", slot: "collar", value: "bell", rarity: "普通" },
  { id: "collar:blueScarf", label: "蓝围巾", icon: "/images/cat/composites/tabbyWhite-blueScarf.png", slot: "collar", value: "blueScarf", rarity: "普通" },
  { id: "face:sunglasses", label: "黑色墨镜", icon: "/images/cat/composites/tabbyWhite-sunglasses.png", slot: "face", value: "sunglasses", rarity: "传说" },
];

function resourceName(kind: "cans" | "driedFish") {
  return kind === "cans" ? "罐头" : "小鱼干";
}

function clampName(name: string) {
  const value = name.trim();
  return value ? value.slice(0, 10) : "米线";
}

function isItemEquipped(profile: CatProfile, item: WardrobeItem) {
  if (item.slot === "coat") return profile.coat === item.value;
  return profile.outfit[item.slot] === item.value;
}

function canBuy(profile: CatProfile, item: WardrobeItem) {
  if (!item.price) return true;
  return profile[item.price.kind] >= item.price.amount;
}

function buyOrEquip(profile: CatProfile, item: WardrobeItem): { profile: CatProfile; message: string } {
  const owned = profile.ownedItems.includes(item.id);
  if (!owned && !canBuy(profile, item)) {
    return { profile, message: `${resourceName(item.price!.kind)}不够，先去投喂/阅读/留言吧。` };
  }

  const next: CatProfile = {
    ...profile,
    ownedItems: owned ? profile.ownedItems : [...profile.ownedItems, item.id],
    outfit: { ...profile.outfit },
  };

  if (!owned && item.price) {
    next[item.price.kind] -= item.price.amount;
  }

  if (item.slot === "coat") {
    next.coat = item.value as CatCoatId;
  } else {
    next.outfit[item.slot] = isItemEquipped(profile, item) ? undefined : item.value;
  }

  saveCatProfile(next);
  return { profile: next, message: owned ? `已换上 ${item.label}` : `解锁并换上 ${item.label}` };
}

type OwnerCodeReward = {
  label: string;
  items?: string[];
  cans?: number;
  driedFish?: number;
};

const ownerCodes: Record<string, OwnerCodeReward> = {
  "MIXIAN-ALL": {
    label: "站长全解锁口令",
    items: wardrobeItems.map((item) => item.id),
    cans: 9,
    driedFish: 9,
  },
  "MIXIAN-FASHION": {
    label: "装扮解锁口令",
    items: wardrobeItems.filter((item) => item.slot !== "tail").map((item) => item.id),
  },
  "MIXIAN-SNACK": {
    label: "补给口令",
    cans: 6,
    driedFish: 6,
  },
};

function normalizeCode(value: string) {
  return value.trim().toUpperCase().replace(/\s+/g, "-");
}

function redeemOwnerCode(profile: CatProfile, rawCode: string): { profile: CatProfile; message: string; ok: boolean } {
  const code = normalizeCode(rawCode);
  const reward = ownerCodes[code as keyof typeof ownerCodes];

  if (!reward) return { profile, message: "口令无效。", ok: false };
  if (profile.redeemedCodes.includes(code)) return { profile, message: "这个口令已经用过了。", ok: false };

  const next: CatProfile = {
    ...profile,
    cans: profile.cans + (reward.cans ?? 0),
    driedFish: profile.driedFish + (reward.driedFish ?? 0),
    ownedItems: Array.from(new Set([...profile.ownedItems, ...(reward.items ?? [])])),
    redeemedCodes: [...profile.redeemedCodes, code],
  };

  saveCatProfile(next);
  return { profile: next, message: `${reward.label}生效，米线的仓库已更新。`, ok: true };
}

function Meter({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="border-2 border-black bg-white p-2 shadow-[3px_3px_0_#000]">
      <div className="flex items-center justify-between font-benderBold text-xs">
        <span>{label}</span>
        <span>{Math.round(value)}</span>
      </div>
      <div className="mt-2 h-3 border-2 border-black bg-[#101010]">
        <div className={`h-full ${color}`} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
      </div>
    </div>
  );
}

export default function More() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);
  const [profile, setProfile] = useState<CatProfile>(() => loadCatProfile());
  const [draftName, setDraftName] = useState(profile.name);
  const [tab, setTab] = useState<WardrobeItem["slot"]>("coat");
  const [redeemCode, setRedeemCode] = useState("");
  const [message, setMessage] = useState("点击小猫可以抚摸，读文章会带回罐头。");
  const [mood, setMood] = useState<"idle" | "happy" | "hungry">("idle");

  useEffect(() => {
    const isActive = $viewIndex === 5 && $readyToTouch;
    if (isActive) directions.set({ top: false, right: false, bottom: true, left: false });
    setActive(isActive);
  }, [$viewIndex, $readyToTouch]);

  useEffect(() => {
    const handleProfile = (event: Event) => {
      const next = (event as CustomEvent<CatProfile>).detail ?? loadCatProfile();
      setProfile(next);
      setDraftName(next.name);
    };

    window.addEventListener(CAT_PROFILE_EVENT, handleProfile);
    return () => window.removeEventListener(CAT_PROFILE_EVENT, handleProfile);
  }, []);

  const filteredItems = useMemo(() => wardrobeItems.filter((item) => item.slot === tab), [tab]);
  const ownedCount = profile.ownedItems.length;

  const handleSaveName = () => {
    const next = { ...profile, name: clampName(draftName) };
    saveCatProfile(next);
    setProfile(next);
    setMessage(`以后就叫 ${next.name}。`);
  };

  const handleFeed = () => {
    const result = feedCat();
    setProfile(result.profile);
    setMood(result.fed ? "happy" : "hungry");
    setMessage(result.fed ? `${result.profile.name} 吃掉一个罐头，发出了满意的咕噜声。` : "没有罐头了，去读一篇文章吧。");
  };

  const handlePet = () => {
    const result = petCat();
    setProfile(result.profile);
    setMood(result.petted ? "happy" : "idle");
    setMessage(result.petted ? `${result.profile.name} 被摸到眯起了眼睛。` : `小猫正在回味，${Math.ceil(result.cooldownMs / 1000)} 秒后再摸。`);
  };

  const handleMessageReward = () => {
    const result = claimMessageReward();
    setProfile(result.profile);
    setMood(result.claimed ? "happy" : "idle");
    setMessage(result.claimed ? "留言奖励领取成功，小猫叼来 1 条小鱼干。" : "今天的小鱼干已经领过了，明天再来。");
  };

  const handleWardrobe = (item: WardrobeItem) => {
    const result = buyOrEquip(profile, item);
    setProfile(result.profile);
    setMessage(result.message);
  };

  const handleRedeemCode = () => {
    const result = redeemOwnerCode(profile, redeemCode);
    setProfile(result.profile);
    setMessage(result.message);
    if (result.ok) setRedeemCode("");
  };

  return (
    <div className={`absolute inset-0 overflow-y-auto bg-[#f7edcf] text-black transition-opacity duration-700 ${active ? "opacity-100" : "opacity-0"}`} data-root-scroll-lock="true">
      <div className="absolute inset-0 opacity-[0.32] [background-image:linear-gradient(#d5c08a_1px,transparent_1px),linear-gradient(90deg,#d5c08a_1px,transparent_1px)] [background-size:26px_26px]" />
      <div className="absolute left-[7%] top-[11rem] h-24 w-24 rotate-[-10deg] rounded-full border-4 border-black bg-[#ffdc4a] opacity-80" />
      <div className="absolute right-[8%] top-[18rem] h-20 w-32 rotate-[8deg] border-4 border-black bg-[#8dd6ff] opacity-70" />
      <div className="relative mx-auto min-h-full max-w-[102rem] px-5 pb-16 pt-[7.5rem] portrait:px-3 portrait:pt-[8.5rem]">
        <div className="mb-5 flex items-end justify-between gap-4 portrait:block">
          <div>
            <div className="inline-block border-2 border-black bg-[#ffee22] px-3 py-1 font-benderBold text-xs text-black shadow-[4px_4px_0_#000]">
              PIXEL CAT / LOCAL PROFILE
            </div>
            <h1 className="mt-3 font-benderBold text-5xl leading-none text-[#1f2937] [text-shadow:4px_4px_0_#ffee22] portrait:text-4xl">
              {profile.name} 的主页
            </h1>
          </div>
          <div className="grid grid-cols-2 gap-2 font-benderBold text-sm portrait:mt-4">
            <div className="border-2 border-black bg-white px-3 py-2 shadow-[4px_4px_0_#000]">罐头 {profile.cans}</div>
            <div className="border-2 border-black bg-white px-3 py-2 shadow-[4px_4px_0_#000]">小鱼干 {profile.driedFish}</div>
          </div>
        </div>

        <div className="grid gap-5 landscape:grid-cols-[minmax(0,1.05fr)_minmax(24rem,.95fr)] portrait:grid-cols-1">
          <section className="border-2 border-black bg-[#f7f1df] p-5 shadow-[8px_8px_0_#000]">
            <div className="min-h-[34rem] border-2 border-black bg-[linear-gradient(180deg,#eef6ff,#fff8df)] p-4 shadow-[inset_0_0_0_2px_rgba(255,255,255,.55)] portrait:min-h-[28rem]">
              <div className="flex min-h-[30rem] items-center justify-center portrait:min-h-[24rem]">
                <PixelCat coat={profile.coat} outfit={profile.outfit} mood={mood} onClick={handlePet} className="scale-[1.1] portrait:scale-100" />
              </div>
            </div>

            <div className="mt-5 grid grid-cols-2 gap-3 portrait:grid-cols-1">
              <Meter label="亲密度" value={profile.affection} color="bg-[#fb7185]" />
              <Meter label="饱食度" value={profile.hunger} color="bg-[#84cc16]" />
            </div>

            <div className="mt-5 grid grid-cols-[1fr_7rem] gap-3 portrait:grid-cols-1">
              <input
                value={draftName}
                onChange={(event) => setDraftName(event.target.value)}
                maxLength={10}
                className="border-2 border-black bg-white px-3 py-3 font-bold outline-none shadow-[4px_4px_0_#000]"
              />
              <button onClick={handleSaveName} className="border-2 border-black bg-[#22d3ee] px-3 py-3 font-benderBold shadow-[4px_4px_0_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none">
                改名
              </button>
            </div>

            <div className="mt-5 grid grid-cols-3 gap-3 portrait:grid-cols-1">
              <button onClick={handlePet} className="border-2 border-black bg-[#ffee22] px-3 py-3 font-benderBold shadow-[4px_4px_0_#000]">抚摸</button>
              <button onClick={handleFeed} className="border-2 border-black bg-[#f97316] px-3 py-3 font-benderBold text-white shadow-[4px_4px_0_#000]">投喂罐头</button>
              <button onClick={handleMessageReward} className="border-2 border-black bg-[#84cc16] px-3 py-3 font-benderBold shadow-[4px_4px_0_#000]">留言奖励</button>
            </div>

            <div className="mt-5 border-2 border-black bg-white p-4 font-bold leading-7 shadow-[4px_4px_0_#000]">
              {message}
            </div>

            <div className="mt-5 border-2 border-black bg-[#fff4c0] p-4 shadow-[4px_4px_0_#000]">
              <div className="font-benderBold text-sm">站长口令 / OWNER CODE</div>
              <p className="mt-2 text-xs font-bold leading-5 text-[#4b4030]">
                这是站长偷偷塞进猫窝的小纸条。米线看不懂，但会认真把它叼进仓库。
              </p>
              <div className="mt-3 grid grid-cols-[1fr_6rem] gap-3 portrait:grid-cols-1">
                <input
                  value={redeemCode}
                  onChange={(event) => setRedeemCode(event.target.value)}
                  placeholder="输入口令"
                  className="border-2 border-black bg-white px-3 py-2 font-bold uppercase outline-none"
                />
                <button onClick={handleRedeemCode} className="border-2 border-black bg-black px-3 py-2 font-benderBold text-[#ffee22] shadow-[3px_3px_0_#000]">
                  兑换
                </button>
              </div>
            </div>
          </section>

          <section className="border-2 border-black bg-[#fff4c0] shadow-[8px_8px_0_#000]">
            <div className="flex items-center border-b-2 border-black bg-black text-white">
              <div className="h-8 w-8 border-r-2 border-black bg-[#ff4f8b]" />
              <div className="px-3 py-2 font-benderBold">WARDROBE</div>
              <div className="ml-auto border-l-2 border-black px-3 py-2 font-benderBold text-xs text-[#ffee22]">拥有 {ownedCount}</div>
            </div>

            <div className="flex overflow-x-auto border-b-2 border-black">
              {wardrobeTabs.map((item) => (
                <button
                  key={item}
                  onClick={() => setTab(item)}
                  className={`min-w-[5.5rem] border-r-2 border-black px-3 py-3 font-bold ${tab === item ? "bg-black text-[#ffee22]" : "bg-white text-black"}`}
                >
                  {wardrobeTabLabels[item]}
                </button>
              ))}
            </div>

            <div className="grid max-h-[38rem] grid-cols-2 gap-4 overflow-y-auto p-5 portrait:grid-cols-1">
              {filteredItems.map((item) => {
                const owned = profile.ownedItems.includes(item.id);
                const equipped = isItemEquipped(profile, item);
                const affordable = canBuy(profile, item);

                return (
                  <button
                    key={item.id}
                    onClick={() => handleWardrobe(item)}
                    className={`min-h-[11rem] border-2 border-black p-3 text-left shadow-[5px_5px_0_#000] transition-transform hover:-translate-y-1 ${
                      equipped ? "bg-[#22d3ee]" : owned ? "bg-white" : affordable ? "bg-[#f8f1d1]" : "bg-[#d8d0c8]"
                    }`}
                  >
                    <div className="flex items-center justify-between font-benderBold text-xs">
                      <span className="bg-black px-2 py-1 text-white">{item.rarity}</span>
                      <span>{equipped ? "EQUIPPED" : owned ? "OWNED" : "LOCKED"}</span>
                    </div>
                    <div className="mt-4 grid place-items-center">
                      <div className="grid h-40 w-32 place-items-center border-2 border-black bg-[#fff7df] shadow-[4px_4px_0_#000]">
                        <img src={item.icon} alt="" draggable={false} className="h-36 w-28 object-contain [image-rendering:pixelated]" />
                      </div>
                    </div>
                    <div className="mt-4 text-2xl font-black">{item.label}</div>
                    <div className="mt-3 text-sm font-bold">
                      {owned
                        ? "点击切换"
                        : item.price
                          ? `${item.price.amount} ${resourceName(item.price.kind)} 解锁`
                          : "免费"}
                    </div>
                  </button>
                );
              })}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
