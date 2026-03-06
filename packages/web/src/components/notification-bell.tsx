"use client";

import { useState, useEffect, useRef } from "react";
import { createSupabaseBrowser } from "@/lib/supabase-browser";
import { useTranslations } from "next-intl";
import type { Notification } from "@/lib/types";

export function NotificationBell() {
  const t = useTranslations("notifications");
  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter((n) => !n.read_at).length;

  useEffect(() => {
    const supabase = createSupabaseBrowser();
    supabase
      .from("notifications")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(20)
      .then(({ data }) => {
        if (data) setNotifications(data as Notification[]);
      });
  }, []);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  const markAllRead = async () => {
    setLoading(true);
    const supabase = createSupabaseBrowser();
    const unread = notifications.filter((n) => !n.read_at);
    if (unread.length > 0) {
      await supabase
        .from("notifications")
        .update({ read_at: new Date().toISOString() })
        .in("id", unread.map((n) => n.id));

      setNotifications((prev) =>
        prev.map((n) => (n.read_at ? n : { ...n, read_at: new Date().toISOString() }))
      );
    }
    setLoading(false);
  };

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="relative p-1.5 text-gray-400 hover:text-white transition-colors"
        aria-label="Notifications"
      >
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-600 text-white text-[10px] font-bold rounded-full flex items-center justify-center">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-gray-900 border border-gray-800 rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
            <span className="text-white text-sm font-medium">{t("title")}</span>
            {unreadCount > 0 && (
              <button
                onClick={markAllRead}
                disabled={loading}
                className="text-gray-400 hover:text-white text-xs transition-colors"
              >
                {t("markAllRead")}
              </button>
            )}
          </div>

          <div className="max-h-80 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-gray-500 text-sm">
                {t("empty")}
              </div>
            ) : (
              notifications.map((n) => (
                <a
                  key={n.id}
                  href={n.link ?? "#"}
                  className={`block px-4 py-3 hover:bg-gray-800/50 transition-colors border-b border-gray-800/50 last:border-0 ${
                    !n.read_at ? "bg-gray-800/20" : ""
                  }`}
                >
                  <div className="flex items-start gap-2">
                    {!n.read_at && (
                      <span className="w-2 h-2 rounded-full bg-red-500 mt-1.5 shrink-0" />
                    )}
                    <div className={!n.read_at ? "" : "pl-4"}>
                      <p className="text-white text-sm">{n.title}</p>
                      {n.message && (
                        <p className="text-gray-500 text-xs mt-0.5">{n.message}</p>
                      )}
                      <p className="text-gray-600 text-[10px] mt-1">
                        {new Date(n.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                </a>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
