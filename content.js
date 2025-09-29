// Listens for background messages and highlights links (demo)
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "HIGHLIGHT") return;

  const links = Array.from(document.querySelectorAll("a[href]"));
  links.forEach((a) => {
    a.style.outline = "2px solid red";
    a.title = "PhishNet demo: highlighted link";
  });

  // Optional: small toast
  try {
    const t = document.createElement("div");
    t.textContent = `PhishNet: highlighted ${links.length} links`;
    Object.assign(t.style, {
      position: "fixed", right: "12px", bottom: "12px",
      padding: "8px 12px", background: "#111", color: "#fff",
      borderRadius: "8px", fontSize: "12px", zIndex: 999999
    });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2000);
  } catch {}
});
