const MAX_VISIBLE_TEXT_LENGTH = 5000;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "TRUSTTRACE_COLLECT_PAGE") {
    return false;
  }

  sendResponse({
    pageTitle: document.title || "",
    visibleText: getVisibleBodyText().slice(0, MAX_VISIBLE_TEXT_LENGTH)
  });

  return true;
});

function getVisibleBodyText() {
  const bodyText = document.body?.innerText || "";
  return bodyText.replace(/\s+/g, " ").trim();
}
