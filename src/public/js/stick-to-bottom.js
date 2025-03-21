function scrollToBottom() {
  document.querySelector("#bottom")?.scrollIntoView();
}

/**
 * Scroll to the bottom on page load if there's no fragment in the URL to designate a particular
 * location we should be scrolling to.
 */
window.addEventListener("DOMContentLoaded", () => {
  const currentFragment = window.location.hash;
  if (currentFragment) return;

  scrollToBottom();
});

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

    scrollToBottom();
  });
}
