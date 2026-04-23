"use strict";

(function () {
  const INTERACTIVE_SELECTOR =
    "a,button,input,textarea,select,summary,[role='button'],[data-cursor='interactive']";
  const IFRAME_CURSOR_STYLE_ID = "arknights-cursor-bridge-style";

  function queryOrThrow(root, selector) {
    const element = root.querySelector(selector);
    if (!element) {
      throw new Error("Unknown HTML");
    }

    return element;
  }

  class Cursor {
    constructor() {
      this.position = { x: 0, y: 0 };
      this.firstMove = true;
      this.lastFrameAt = 0;
      this.isAnimating = false;
      this.isFading = false;
      this.boundDocuments = new WeakSet();

      const container = document.createElement("div");
      container.id = "cursor-container";
      container.innerHTML = '<div id="cursor-outer"></div><div id="cursor-effect"></div>';
      document.body.appendChild(container);

      this.outer = queryOrThrow(container, "#cursor-outer").style;
      this.effect = queryOrThrow(container, "#cursor-effect").style;
      this.outer.top = "-100%";
      this.effect.transform = "translate(-50%, -50%) scale(0)";
      this.effect.opacity = "1";

      this.animate = (timestamp) => {
        const currentX = parseFloat(this.outer.left || "0");
        const currentY = parseFloat(this.outer.top || "0");
        const deltaX = (this.position.x - currentX) * 0.3;
        const deltaY = (this.position.y - currentY) * 0.3;

        if (timestamp - this.lastFrameAt > 15) {
          this.outer.left = `${(currentX + deltaX).toFixed(2)}px`;
          this.outer.top = `${(currentY + deltaY).toFixed(2)}px`;
          this.lastFrameAt = timestamp;
        }

        if (Math.abs(deltaX) > 0.2 || Math.abs(deltaY) > 0.2) {
          window.requestAnimationFrame(this.animate);
          return;
        }

        this.isAnimating = false;
      };

      this.track = (point) => {
        this.position = point;

        if (this.firstMove) {
          this.firstMove = false;
          this.outer.left = `${point.x}px`;
          this.outer.top = `${point.y}px`;
        }

        if (!this.isAnimating) {
          this.isAnimating = true;
          window.requestAnimationFrame(this.animate);
        }
      };

      this.pulse = (point) => {
        if (this.isFading) {
          return;
        }

        this.isFading = true;
        this.effect.left = `${point.x}px`;
        this.effect.top = `${point.y}px`;
        this.effect.transition =
          "transform .5s cubic-bezier(0.22, 0.61, 0.21, 1), opacity .5s cubic-bezier(0.22, 0.61, 0.21, 1)";
        this.effect.transform = "translate(-50%, -50%) scale(1)";
        this.effect.opacity = "0";

        window.setTimeout(() => {
          this.isFading = false;
          this.effect.transition = "";
          this.effect.transform = "translate(-50%, -50%) scale(0)";
          this.effect.opacity = "1";
        }, 500);
      };

      this.hold = () => {
        this.outer.height = "24px";
        this.outer.width = "24px";
        this.outer.background = "rgba(255, 255, 255, 0.5)";
      };

      this.relax = () => {
        this.outer.height = "36px";
        this.outer.width = "36px";
        this.outer.background = "unset";
      };

      this.bindDocument(document, null);
      this.observeFrames(document);
    }

    getPoint(event, frameElement) {
      if (!frameElement) {
        return { x: event.clientX, y: event.clientY };
      }

      const rect = frameElement.getBoundingClientRect();
      return {
        x: rect.left + event.clientX,
        y: rect.top + event.clientY,
      };
    }

    findInteractiveTarget(node) {
      if (!(node instanceof Element)) {
        return null;
      }

      return node.closest(INTERACTIVE_SELECTOR);
    }

    bindDocument(doc, frameElement) {
      if (!doc || this.boundDocuments.has(doc)) {
        return;
      }

      this.boundDocuments.add(doc);

      if (frameElement) {
        this.injectIframeCursorStyle(doc);
      }

      doc.addEventListener(
        "mousemove",
        (event) => {
          this.track(this.getPoint(event, frameElement));
        },
        { passive: true },
      );

      doc.addEventListener(
        "click",
        (event) => {
          this.pulse(this.getPoint(event, frameElement));
        },
        { passive: true },
      );

      doc.addEventListener(
        "mouseover",
        (event) => {
          if (this.findInteractiveTarget(event.target)) {
            this.hold();
          }
        },
        { passive: true },
      );

      doc.addEventListener(
        "mouseout",
        (event) => {
          const current = this.findInteractiveTarget(event.target);
          const related = this.findInteractiveTarget(event.relatedTarget);

          if (current && current !== related) {
            this.relax();
          }
        },
        { passive: true },
      );

      this.observeFrames(doc);
    }

    injectIframeCursorStyle(doc) {
      if (doc.getElementById(IFRAME_CURSOR_STYLE_ID)) {
        return;
      }

      const style = doc.createElement("style");
      style.id = IFRAME_CURSOR_STYLE_ID;
      style.textContent = "* { cursor: none !important; }";
      (doc.head || doc.documentElement).appendChild(style);
    }

    bindFrame(frame) {
      if (frame.dataset.nativeCursor === "true") {
        return;
      }

      const attach = () => {
        try {
          if (!frame.contentDocument) {
            return;
          }

          this.bindDocument(frame.contentDocument, frame);
        } catch (error) {
          console.warn("Cursor bridge skipped iframe:", error);
        }
      };

      frame.addEventListener("load", attach, { passive: true });
      attach();
    }

    observeFrames(doc) {
      doc.querySelectorAll("iframe").forEach((frame) => this.bindFrame(frame));

      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (!(node instanceof Element)) {
              return;
            }

            if (node.matches("iframe")) {
              this.bindFrame(node);
            }

            if (!node.querySelectorAll) {
              return;
            }

            node.querySelectorAll("iframe").forEach((frame) => this.bindFrame(frame));
          });
        });
      });

      observer.observe(doc, { childList: true, subtree: true });
    }
  }

  window.addEventListener("load", () => {
    new Cursor();
  });
})();
