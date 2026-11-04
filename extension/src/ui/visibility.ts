/**
 * Self-visibility check for extension iframes injected into untrusted pages.
 * IntersectionObserver v2 (`trackVisibility`) reports whether the frame is
 * occluded, transformed or made transparent by the embedding page.
 */

let visible = true;
let supported = false;

export function watchVisibility(target: Element): void {
  try {
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          const v2 = (e as any).isVisible;
          if (typeof v2 === "boolean") {
            supported = true;
            visible = v2;
          }
        }
      },
      { threshold: [1.0], trackVisibility: true, delay: 100 } as any,
    );
    io.observe(target);
  } catch {
    supported = false;
  }
}

/** True unless IOv2 is supported and reports the frame as obscured. */
export function isFrameVisible(): boolean {
  return supported ? visible : true;
}
