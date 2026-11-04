(() => {
  const panel = document.querySelector("[data-receipts-url]");
  const rows = document.querySelector("#checkin-receipt-rows");
  const reviewRows = document.querySelector("#checkin-review-rows");
  const reviewHeading = document.querySelector("#checkin-review-heading");
  const pendingCount = document.querySelector("#checkin-pending-review-count");
  const status = document.querySelector("#checkin-receipt-live-status");
  const actionStatus = document.querySelector("#checkin-receipt-action-status");
  const lateOnly = document.querySelector("#checkin-late-only");
  const noLateReceipts = document.querySelector("#checkin-no-late-receipts");
  const liveMessage = "Live · updates every 5 seconds";
  let refreshRequest;
  let acknowledging = false;
  let sessionExpired = false;
  const renderedMarkup = new Map();

  function applyFilter() {
    for (const row of rows.rows) {
      row.hidden = lateOnly.checked && !row.hasAttribute("data-late-receipt");
    }
    noLateReceipts.hidden = !lateOnly.checked || !!rows.querySelector("[data-late-receipt]");
  }

  function showStatus(message) {
    if (status.textContent !== message) status.textContent = message;
  }

  async function request(url, options) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(url, {
        cache: "no-store",
        redirect: "manual",
        signal: controller.signal,
        ...options,
      });
      if (response.type === "opaqueredirect" || [401, 403].includes(response.status)) {
        sessionExpired = true;
        showStatus("Live updates stopped. Sign in as dispatch and reopen this dashboard.");
      }
      return { response, data: response.status === 200 ? await response.json() : null };
    } finally {
      clearTimeout(timeout);
    }
  }

  function updateRows(body, markup, focusFallback) {
    if (markup === renderedMarkup.get(body)) return;
    const active = document.activeElement;
    const focusedAction = body.contains(active) && active.closest("form[data-receipt-ack]")?.action;
    body.innerHTML = markup;
    renderedMarkup.set(body, markup);
    if (focusedAction) {
      const replacement = [...body.querySelectorAll("form[data-receipt-ack]")]
        .find((form) => form.action === focusedAction);
      (replacement?.querySelector("button") || focusFallback).focus({ preventScroll: true });
    }
  }

  async function loadReceipts() {
    try {
      const { response, data } = await request(panel.dataset.receiptsUrl);
      if (sessionExpired) return;
      if (!response.ok) throw new Error("Could not load check-in receipts");
      if (!acknowledging) {
        updateRows(rows, data.receipts, lateOnly);
        updateRows(reviewRows, data.review, reviewHeading);
        applyFilter();
        const label = `${data.pending_count} awaiting acknowledgement`;
        if (pendingCount.textContent !== label) pendingCount.textContent = label;
      }
      showStatus(liveMessage);
    } catch {
      showStatus("Live updates unavailable. Showing the last received list and retrying.");
    }
  }

  function refreshReceipts() {
    if (refreshRequest || acknowledging || document.hidden || sessionExpired) return;
    refreshRequest = loadReceipts().finally(() => { refreshRequest = undefined; });
  }

  panel.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("form[data-receipt-ack]")) return;
    event.preventDefault();
    if (acknowledging) return;
    if (sessionExpired) {
      actionStatus.textContent = "Sign in as dispatch before acknowledging a check-in.";
      return;
    }

    acknowledging = true;
    const button = form.querySelector("button");
    button.disabled = true;
    actionStatus.textContent = "Saving acknowledgement…";
    try {
      const { response } = await request(form.action, {
        method: "POST",
        headers: { Accept: "application/json" },
        body: new FormData(form),
      });
      if (response.status === 204) {
        actionStatus.textContent = "Check-in acknowledged.";
        if (document.activeElement === document.body) {
          (reviewRows.contains(form) ? reviewHeading : lateOnly).focus({ preventScroll: true });
        }
      } else if (response.status === 409) {
        actionStatus.textContent = "This check-in no longer qualifies as late.";
      } else if (sessionExpired || response.status === 400) {
        actionStatus.textContent = "Reopen the dispatcher dashboard and try again.";
      } else {
        throw new Error("Acknowledgement could not be confirmed");
      }
    } catch {
      actionStatus.textContent = "Could not confirm acknowledgement. Try again.";
    } finally {
      await refreshRequest;
      acknowledging = false;
      button.disabled = false;
      refreshReceipts();
    }
  });

  document.querySelector("#checkin-receipt-filter").hidden = false;
  lateOnly.addEventListener("change", applyFilter);
  applyFilter();
  status.hidden = false;
  showStatus("Connecting to live updates…");
  document.addEventListener("visibilitychange", refreshReceipts);
  window.addEventListener("online", refreshReceipts);
  setInterval(refreshReceipts, 5000);
  void refreshReceipts();
})();
