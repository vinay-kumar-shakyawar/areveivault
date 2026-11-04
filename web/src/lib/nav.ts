export type AdminTab = "members" | "invites" | "projects" | "audit";

export type View =
  | { k: "all" }
  | { k: "vault"; id: string }
  | { k: "client"; id: string }
  | { k: "favorites" }
  | { k: "authenticators" }
  | { k: "tag"; tag: string }
  | { k: "trash" }
  | { k: "security" }
  | { k: "tools" }
  | { k: "generator" }
  | { k: "settings" }
  | { k: "admin"; tab: AdminTab };

export const isListView = (v: View) => ["all", "vault", "client", "favorites", "authenticators", "tag", "trash"].includes(v.k);

export const sameView = (a: View, b: View) => JSON.stringify(a) === JSON.stringify(b);
