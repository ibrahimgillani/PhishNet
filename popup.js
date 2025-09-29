document.getElementById("scan").addEventListener("click", async () => {
  // Ask background to tell the content script to highlight
  await chrome.runtime.sendMessage({ type: "SCAN_PAGE" });
  window.close();
});
