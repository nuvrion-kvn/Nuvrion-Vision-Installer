"use client";

import { useEffect, useState } from "react";
import type { Locale } from "../lib/pokemon";

const MIN_PLAYERS = 75;
const MAX_PLAYERS = 168;

export function PresenceCounter({ locale }: { locale: Locale }) {
  const [count, setCount] = useState(MIN_PLAYERS);

  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState === "visible") {
        setCount(MIN_PLAYERS + Math.floor(Math.random() * (MAX_PLAYERS - MIN_PLAYERS + 1)));
      }
    };
    const firstUpdate = window.setTimeout(refresh, 0);
    const interval = window.setInterval(refresh, 45_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearTimeout(firstUpdate);
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  return (
    <div className="presence-counter">
      <span className="presence-light" aria-hidden="true" />
      <span>{locale === "ru" ? "Сейчас в игре" : "In game now"}</span>
      <b>{count}</b>
    </div>
  );
}
