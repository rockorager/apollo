const messageList = document.querySelector("#message-list");
let isAtBottom = false;

if (messageList) {
  messageList.addEventListener("htmx:sseBeforeMessage", () => {
    // See: https://stackoverflow.com/questions/9439725/how-to-detect-if-browser-window-is-scrolled-to-bottom.
    isAtBottom =
      window.innerHeight + Math.round(window.scrollY) >=
      document.body.offsetHeight;
  });

  messageList.addEventListener("htmx:sseMessage", () => {
    if (!isAtBottom) return;

    document.querySelector("#bottom")?.scrollIntoView();
  });
}
