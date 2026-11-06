import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "@nanostores/react";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";
import arknightsConfig from "../../../arknights.config";
import EncryptedArticle, { type EncryptedPayload } from "../../components/EncryptedArticle";
import ArchiveGuardian from "../../components/ArchiveGuardian";
import "../../_styles/archive.css";

type MediaArticle = NonNullable<NonNullable<typeof arknightsConfig.rootPage.MEDIA>["articles"]>[number];
const payloadModules = import.meta.glob<{ default: EncryptedPayload }>("/src/content/secret/*.payload.json");
const mediaIndex = arknightsConfig.navbar.items.findIndex((item) => item.href.endsWith("#media"));

function getArticleId(article: MediaArticle) {
  return article.secretId ?? article.href.split("?")[0].split("#")[0].split("/").filter(Boolean).pop() ?? "secret";
}

export default function Media() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const active = $viewIndex === mediaIndex && $readyToTouch;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loadedPayload, setLoadedPayload] = useState<{ id: string; value: EncryptedPayload } | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [signal, setSignal] = useState(0);
  const closeRef = useRef<HTMLButtonElement>(null);
  const pageRef = useRef<HTMLDivElement>(null);
  const directoryScroll = useRef(0);
  const returnFocus = useRef<number | null>(null);
  const rowRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const articles = useMemo(() => arknightsConfig.rootPage.MEDIA?.articles ?? [], []);
  const selectedArticle = articles.find((article) => getArticleId(article) === selectedId) ?? null;
  const selectedIndex = selectedArticle ? articles.indexOf(selectedArticle) : -1;
  const payload = loadedPayload?.id === selectedId ? loadedPayload.value : null;

  useEffect(() => {
    if (active) directions.set({ top: false, right: true, bottom: true, left: false });
    if (active) document.documentElement.dataset.archiveOpen = "true";
    else delete document.documentElement.dataset.archiveOpen;
    return () => { delete document.documentElement.dataset.archiveOpen; };
  }, [active]);

  useEffect(() => {
    if (active && selectedId) document.documentElement.dataset.archiveReading = "true";
    else delete document.documentElement.dataset.archiveReading;
    return () => { delete document.documentElement.dataset.archiveReading; };
  }, [active, selectedId]);

  useEffect(() => {
    setLoadedPayload(null);
    setLoadError(false);
    if (!selectedId) return;
    let cancelled = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const loader = payloadModules[`/src/content/secret/${selectedId}.payload.json`];
    Promise.race([
      loader ? loader() : Promise.reject(new Error("Missing archive")),
      new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error("Archive timed out")), 10000); }),
    ]).then((module) => {
      if (!cancelled) setLoadedPayload({ id: selectedId, value: module.default });
    }).catch(() => {
      if (!cancelled) setLoadError(true);
    }).finally(() => clearTimeout(timeout));
    return () => { cancelled = true; clearTimeout(timeout); };
  }, [selectedId, retry]);

  useEffect(() => {
    if (!active) return;
    if (!selectedId) {
      const index = returnFocus.current;
      if (index === null) return;
      returnFocus.current = null;
      // Wait for the directory's visibility transition before restoring keyboard focus.
      const timer = window.setTimeout(() => {
        pageRef.current?.scrollTo({ top: directoryScroll.current, behavior: "auto" });
        rowRefs.current[index]?.focus({ preventScroll: true });
      }, 420);
      return () => window.clearTimeout(timer);
    }
    closeRef.current?.focus({ preventScroll: true });
    const handleEscape = (event: KeyboardEvent) => {
      // A focused reader consumes Escape; the archive directory stays on this page.
      if (event.key === "Escape") closeArchive();
    };
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [active, selectedId]);

  function openArchive(article: MediaArticle) {
    if (!selectedId) directoryScroll.current = pageRef.current?.scrollTop ?? 0;
    pageRef.current?.scrollTo({ top: 0, behavior: "auto" });
    setSelectedId(getArticleId(article));
    setSignal((value) => value + 1);
  }

  function closeArchive() {
    returnFocus.current = selectedIndex;
    setSelectedId(null);
  }

  return (
    <div ref={pageRef} id="media" data-root-scroll-lock="true" className={`archive-page ${active ? "is-active" : ""} ${selectedArticle ? "is-reading" : ""}`}>
      <div className="archive-watermark" aria-hidden="true">SEALED</div>
      <div className="archive-atmosphere" aria-hidden="true">
        {Array.from({ length: 20 }, (_, index) => <i key={index} style={{ left: `${(index * 37 + 9) % 100}%`, top: `${(index * 23 + 19) % 100}%`, animationDelay: `${-index * 1.7}s`, animationDuration: `${17 + index % 9}s` }} />)}
      </div>
      <div className="archive-edition" aria-hidden="true">PERSONAL RECORDS / CORN KINGDOM</div>
      <div className="archive-layout">
        <section className="archive-index" aria-label="封存档案目录" aria-hidden={!!selectedArticle}>
          <header>
            <p className="archive-eyebrow"><span className="archive-tick" /> SEALED ARCHIVE</p>
            <h1>封存档案<span className="archive-heading-dot">.</span></h1>
          </header>
          <nav className="archive-list" aria-label="选择档案">
            {articles.map((article, index) => <button key={getArticleId(article)} ref={(node) => { rowRefs.current[index] = node; }} className="archive-row" onClick={() => openArchive(article)}>
              <span className="archive-number">{String(index).padStart(2, "0")}</span>
              <span className="archive-row-copy"><span className="archive-row-title">{article.title}</span><time className="archive-row-date">{article.date}</time></span>
              <span className="archive-row-state">{article.locked ? "LOCKED" : "OPEN"}<span aria-hidden="true">↗</span></span>
            </button>)}
          </nav>
          <div className="archive-index-footer"><span>INDEX / {String(articles.length).padStart(2, "0")}</span><span>SELECT A RECORD TO UNSEAL</span></div>
        </section>

        <figure className="archive-guardian">
          <ArchiveGuardian active={active} resting={!!selectedArticle} signal={signal} />
          <figcaption><span className="archive-eyebrow">THE QUIET KEEPER</span><span>Move closer. The dust remembers.</span></figcaption>
        </figure>

        {selectedArticle && <section className="archive-reader" aria-label={`阅读${selectedArticle.title}`}>
          <div className="archive-reader-topbar">
            <button ref={closeRef} type="button" className="archive-back" onClick={closeArchive}><span aria-hidden="true">←</span> DIRECTORY <span className="archive-back-cn">返回目录</span></button>
            <span className="archive-reader-id">RECORD / {String(selectedIndex).padStart(2, "0")}</span>
          </div>
          <div className="archive-reader-layout">
            <nav className="archive-rail" aria-label="切换档案">{articles.map((article, index) => <button key={getArticleId(article)} onClick={() => openArchive(article)} aria-label={article.title} aria-current={index === selectedIndex ? "page" : undefined}>{String(index).padStart(2, "0")}</button>)}</nav>
            <div className="archive-reader-body">
              {payload ? <EncryptedArticle key={selectedId} presentation="panel" payload={payload} title={selectedArticle.title} hint={selectedArticle.keyHint} /> : <div className="archive-load-state" role="status">
                <span className="archive-eyebrow">{loadError ? "SIGNAL INTERRUPTED" : "RETRIEVING RECORD"}</span>
                <p>{loadError ? "档案暂未连接，请稍后重试。" : "正在读取封存档案…"}</p>
                {loadError && <button onClick={() => setRetry((value) => value + 1)}>RETRY / 重试</button>}
              </div>}
            </div>
          </div>
        </section>}
      </div>
      <div className="archive-bottom-note"><span>PRIVATE MEMORIES, QUIETLY KEPT.</span><span>SEALED / {String(articles.length).padStart(2, "0")}</span></div>
    </div>
  );
}
