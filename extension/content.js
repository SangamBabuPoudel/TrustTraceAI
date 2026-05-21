const MAX_VISIBLE_TEXT_LENGTH = 5000;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "TRUSTTRACE_COLLECT_PAGE") {
    return false;
  }

  sendResponse({
    pageTitle: document.title || "",
    visibleText: getVisibleBodyText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    forms: collectFormMetadata()
  });

  return true;
});

function getVisibleBodyText() {
  const bodyText = document.body?.innerText || "";
  return bodyText.replace(/\s+/g, " ").trim();
}

function collectFormMetadata() {
  return Array.from(document.forms).map((form) => {
    const inputs = Array.from(form.querySelectorAll("input"));
    const submitButton = form.querySelector(
      "button[type='submit'], input[type='submit'], button:not([type])"
    );

    return {
      action: form.getAttribute("action") || "",
      method: (form.getAttribute("method") || "get").toLowerCase(),
      has_password_field: inputs.some((input) => input.type === "password"),
      has_email_or_username_field: inputs.some(isEmailOrUsernameInput),
      input_count: inputs.length,
      hidden_input_count: inputs.filter((input) => input.type === "hidden").length,
      submit_text: getSubmitText(submitButton)
    };
  });
}

function isEmailOrUsernameInput(input) {
  const inputType = input.type.toLowerCase();
  const inputName = `${input.name || ""} ${input.id || ""} ${input.placeholder || ""}`.toLowerCase();

  return (
    inputType === "email" ||
    inputName.includes("email") ||
    inputName.includes("user") ||
    inputName.includes("login")
  );
}

function getSubmitText(submitButton) {
  if (!submitButton) {
    return "";
  }

  if (submitButton.tagName.toLowerCase() === "input") {
    return submitButton.value || "";
  }

  return submitButton.innerText || submitButton.textContent || "";
}
