import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { boot } from "./lib/app";
import { applyTheme } from "./lib/settings";
import "./index.css";

applyTheme();
document.documentElement.classList.add("av-root");
void boot();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
