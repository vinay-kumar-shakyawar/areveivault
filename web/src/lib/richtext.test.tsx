// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { fromMarkdown, markdownToNotes, notesToMarkdown, parseNotes, RichText, safeHref, type Doc } from "./richtext";

const html = (doc: Doc) => renderToStaticMarkup(<RichText doc={doc} />);

describe("rich text", () => {
  it("parses the markdown subset into an allow-listed doc", () => {
    const d = fromMarkdown("# Title\n\nHello **bold** and *it* and `code`\n\n- a\n- b\n\n1. x\n\n```\nraw <b>\n```\n\n> quote");
    expect(d.blocks.map((b) => b.k)).toEqual(["h", "p", "ul", "ol", "code", "quote"]);
  });

  it("round-trips through storage", () => {
    const md = "Line with [link](https://acme.com) and **bold**\n\n- one\n- two";
    expect(notesToMarkdown(markdownToNotes(md))).toBe(md);
  });

  it("never interprets HTML in text", () => {
    const out = html(fromMarkdown('<img src=x onerror=alert(1)> <script>alert(1)</script>'));
    expect(out).not.toContain("<img");
    expect(out).not.toContain("<script");
    expect(out).toContain("&lt;img");
  });

  it("drops javascript: and data: links, keeps https and mailto", () => {
    expect(safeHref("javascript:alert(1)")).toBeUndefined();
    expect(safeHref(" JaVaScRiPt:alert(1)")).toBeUndefined();
    expect(safeHref("data:text/html,<x>")).toBeUndefined();
    expect(safeHref("https://ok.com")).toBe("https://ok.com");
    expect(safeHref("mailto:a@b.c")).toBe("mailto:a@b.c");
    const out = html(fromMarkdown("[click](javascript:alert(1))"));
    expect(out).not.toContain("href");
  });

  it("treats a hostile stored doc (from another user) as untrusted", () => {
    const hostile = JSON.stringify({
      v: 1,
      blocks: [
        { k: "p", c: [{ t: "x", href: "javascript:alert(1)" }, { t: { evil: 1 } }] },
        { k: "script", c: [{ t: "alert(1)" }] },
        { k: "ul", items: "nope" },
        { k: "code", text: "<svg onload=alert(1)>" },
      ],
    });
    const out = html(parseNotes(hostile));
    expect(out).not.toContain("javascript:");
    expect(out).not.toContain("<script");
    expect(out).not.toContain("<svg");
    expect(out).toContain("&lt;svg");
  });

  it("links open safely", () => {
    const out = html(fromMarkdown("[docs](https://example.com)"));
    expect(out).toContain('rel="noopener noreferrer nofollow"');
    expect(out).toContain('target="_blank"');
  });

  it("plain-text notes (imports) stay plain text", () => {
    expect(parseNotes("line1\n\nline2").blocks).toHaveLength(2);
    expect(parseNotes("{not json").blocks[0]).toMatchObject({ k: "p" });
  });
});
