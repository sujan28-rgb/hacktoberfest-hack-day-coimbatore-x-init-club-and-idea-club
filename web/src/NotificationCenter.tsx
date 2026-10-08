import { useEffect, useState } from "react";
import { getNotifications, markNotificationRead } from "./api";
import type { InvestigationNotification } from "./api";

export function NotificationCenter({caseIds, onOpen}: {caseIds: string[], onOpen: (item: InvestigationNotification) => void}) {
  const [items, setItems] = useState<InvestigationNotification[]>([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const caseKey = caseIds.join(",");
  useEffect(() => {
    let active = true;
    let inFlight = false;
    const poll = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const results = await Promise.allSettled(caseKey ? caseKey.split(",").map(getNotifications) : []);
        if (!active) return;
        const batches = results.flatMap(r => r.status === "fulfilled" ? [r.value] : []);
        setItems(batches.flatMap(b => b.items).sort((a, b) => b.created_at.localeCompare(a.created_at)));
        setUnread(batches.reduce((sum, b) => sum + b.unread, 0));
        setError(results.some(r => r.status === "rejected") ? "Some investigations could not be reached. Notifications may be incomplete." : "");
      } finally { inFlight = false; }
    };
    void poll();
    const timer = window.setInterval(poll, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [caseKey, refresh]);
  const openInvestigation = async (item: InvestigationNotification) => {
    try {
      await markNotificationRead(item);
      setRefresh(r => r + 1);
      onOpen(item);
      setOpen(false);
    } catch (err) { setError(String(err)); }
  };
  return <section aria-label="Notification center">
    <button aria-expanded={open} onClick={() => setOpen(v => !v)}>🔔 Notifications ({unread} unread)</button>
    {error && <p role="alert">{error}</p>}
    {open && <div className="notification-panel">
      <h2>Recent investigation changes</h2>
      <p>Latest 30 notifications per investigation in this browser session.</p>
      {items.length === 0 && <p>No investigation notifications.</p>}
      {items.map(item => <article key={item.notification_id} className="notification-item">
        <h3>{!item.read && "● "}{item.title}</h3>
        <p>{item.type} · {new Date(item.created_at).toLocaleString()}</p>
        <p>Host: {item.host || "Not reported"} · {item.entities.join(", ")}</p>
        <p>{item.predicate} — {item.historical ? "Previous status" : "Status"}: <strong>{item.status}</strong></p>
        <p>Supporting evidence: {item.supporting_evidence_count} records.</p>
        <p>{item.message}</p>
        <button onClick={() => openInvestigation(item)}>Open Investigation</button>
      </article>)}
    </div>}
  </section>;
}
