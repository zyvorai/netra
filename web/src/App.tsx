import { useEffect, useState } from "react";

type Tab = "flows" | "policy" | "drops" | "ebpf";

const headers = (): HeadersInit => {
  const key = localStorage.getItem("netraApiKey") || "";
  return key ? { Authorization: `Bearer ${key}` } : {};
};

export function App() {
  const [tab, setTab] = useState<Tab>("flows");
  const [status, setStatus] = useState<string>("…");
  const [lines, setLines] = useState<string[]>([]);
  const [selector, setSelector] = useState("app=payments");
  const [to, setTo] = useState("api.example.com");
  const [dryRun, setDryRun] = useState(true);
  const [policyMsg, setPolicyMsg] = useState("");

  useEffect(() => {
    fetch("/api/v1/status", { headers: headers() })
      .then((r) => r.json())
      .then((j) => setStatus(JSON.stringify(j, null, 2)))
      .catch((e) => setStatus(String(e)));
  }, []);

  useEffect(() => {
    if (tab !== "flows") return;
    const es = new EventSource("/api/v1/flows/stream?direction=EGRESS&number=200");
    const onFlow = (ev: MessageEvent) => {
      setLines((prev) => [ev.data, ...prev].slice(0, 200));
    };
    es.addEventListener("flow", onFlow);
    es.onerror = () => es.close();
    return () => es.close();
  }, [tab]);

  async function buildAndApply() {
    setPolicyMsg("");
    const sel: Record<string, string> = {};
    for (const part of selector.split(",")) {
      const [k, v] = part.split("=");
      if (!k || !v) {
        setPolicyMsg("Selector must be key=value (refused empty — Cilium egress can default-deny).");
        return;
      }
      sel[k.trim()] = v.trim();
    }
    const built = await fetch("/api/v1/policies/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers() },
      body: JSON.stringify({
        name: "payments-egress",
        namespace: "payments",
        selector: sel,
        kind: "fqdn",
        to,
        port: 443,
        includeDNS: true,
      }),
    });
    const doc = await built.text();
    if (!built.ok) {
      setPolicyMsg(doc);
      return;
    }
    const apply = await fetch(`/api/v1/policies/apply?dryRun=${dryRun}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers() },
      body: doc,
    });
    setPolicyMsg(await apply.text());
  }

  return (
    <div className="page">
      <header className="hero">
        <h1 className="brand">Netra</h1>
        <p className="lede">Cilium policy · Hubble flows · optional eBPF fast path</p>
      </header>

      <nav className="tabs">
        {(["flows", "policy", "drops", "ebpf"] as Tab[]).map((t) => (
          <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </nav>

      {tab === "flows" && (
        <section>
          <p className="hint">Live egress from Hubble Relay (metadata only — no payloads).</p>
          <pre className="terminal">{lines.length ? lines.join("\n") : "waiting for flows…"}</pre>
        </section>
      )}

      {tab === "policy" && (
        <section className="panel">
          <p className="hint">
            Selecting an endpoint with egress policy can move it to egress default-deny in Cilium.
            Empty selectors are refused. Use dry-run before Apply.
          </p>
          <label>
            Selector
            <input value={selector} onChange={(e) => setSelector(e.target.value)} />
          </label>
          <label>
            FQDN
            <input value={to} onChange={(e) => setTo(e.target.value)} />
          </label>
          <label className="row">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
            Server-side dry-run
          </label>
          <div className="actions">
            <button onClick={buildAndApply}>{dryRun ? "Dry-run" : "Apply"}</button>
          </div>
          <pre className="terminal">{policyMsg || status}</pre>
        </section>
      )}

      {tab === "drops" && <Drops />}
      {tab === "ebpf" && <Ebpf />}
    </div>
  );
}

function Drops() {
  const [text, setText] = useState("…");
  useEffect(() => {
    fetch("/api/v1/drops/explain", { headers: headers() })
      .then((r) => r.text())
      .then(setText)
      .catch((e) => setText(String(e)));
  }, []);
  return (
    <section>
      <p className="hint">Why was this dropped? Hubble verdict + Netra suggestions.</p>
      <pre className="terminal">{text}</pre>
    </section>
  );
}

function Ebpf() {
  const [text, setText] = useState("…");
  useEffect(() => {
    Promise.all([
      fetch("/api/v1/ebpf/config", { headers: headers() }).then((r) => r.json()),
      fetch("/api/v1/agents", { headers: headers() }).then((r) => r.json()),
    ])
      .then(([cfg, agents]) => setText(JSON.stringify({ cfg, agents }, null, 2)))
      .catch((e) => setText(String(e)));
  }, []);
  return (
    <section>
      <p className="hint">Exact destination counters and sampled header events from Netra maps only.</p>
      <pre className="terminal">{text}</pre>
    </section>
  );
}
