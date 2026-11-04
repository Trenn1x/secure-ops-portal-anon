(async () => {
  const form = document.querySelector("[data-checkin-queue]");
  if (!form || !window.indexedDB || !window.crypto?.randomUUID) return;

  const panel = document.querySelector("#checkin-queue");
  const status = document.querySelector("#checkin-sync-status");
  const errors = document.querySelector("#checkin-sync-errors");
  const retry = document.querySelector("#checkin-sync-now");
  const submit = form.querySelector("button[type='submit']");
  let guardId = form.dataset.guardId;
  let syncing = false;

  const database = new Promise((resolve, reject) => {
    const request = indexedDB.open("omega-guard-checkins", 2);
    request.onupgradeneeded = (event) => {
      if (event.oldVersion < 1) {
        const queue = request.result.createObjectStore("queue", { autoIncrement: true });
        queue.createIndex("guard", "guard_id");
      }
      request.result.createObjectStore("offline");
    };
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("Close other portal tabs and reload."));
  });

  async function inStore(name, mode, operation) {
    const db = await database;
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(name, mode);
      const request = operation(transaction.objectStore(name));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  async function queuedEntries() {
    const db = await database;
    return new Promise((resolve, reject) => {
      const entries = [];
      const transaction = db.transaction("queue", "readonly");
      const request = transaction.objectStore("queue").index("guard").openCursor(guardId);
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;
        entries.push({ key: cursor.primaryKey, entry: cursor.value });
        cursor.continue();
      };
      transaction.oncomplete = () => resolve(entries);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  function showQueue(entries, message) {
    const pending = entries.filter(({ entry }) => !entry.error).length;
    const rejected = entries.length - pending;
    status.textContent = [message, pending ? `${pending} waiting to sync.` : "",
      rejected ? `${rejected} need attention.` : ""].filter(Boolean).join(" ");
    errors.replaceChildren();
    for (const { entry } of entries.filter(({ entry }) => entry.error)) {
      const item = document.createElement("li");
      item.textContent = `Assignment #${entry.assignment_id} · ${entry.check_type} · ${entry.captured_at} · ${entry.error}`;
      errors.append(item);
    }
  }

  function request(url, options = {}) {
    return fetch(url, {
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout?.(15000),
      ...options,
    });
  }

  async function sync() {
    if (syncing) return;
    syncing = true;
    retry.disabled = true;
    let message = "";
    let sent = 0;

    try {
      const entries = await queuedEntries();
      const pending = entries.filter(({ entry }) => !entry.error);
      if (pending.length && navigator.onLine) {
        const auth = await request(form.dataset.sessionUrl);
        if (!auth.ok) {
          message = "Sign in again with this guard account to sync.";
        } else {
          const session = await auth.json();
          if (session.guard_id !== guardId) {
            message = "Switch back to the guard account that saved these check-ins.";
          } else {
            for (const { key, entry } of pending) {
              const response = await request(form.dataset.syncUrl, {
                method: "POST",
                body: new URLSearchParams({ ...entry, csrf_token: session.csrf_token }),
              });
              if (response.ok) {
                const receipt = await response.json();
                if (receipt.event_id !== entry.event_id || !receipt.synced_at) {
                  throw new Error("Invalid sync receipt");
                }
                await inStore("queue", "readwrite", (store) => store.delete(key));
                sent++;
              } else if ([404, 409, 422].includes(response.status)) {
                const { error } = await response.json();
                // A concurrent tab may already have removed this record.
                await inStore("queue", "readwrite", (store) => {
                  const read = store.get(key);
                  read.onsuccess = () => {
                    if (read.result) store.put({ ...read.result, error }, key);
                  };
                  return read;
                });
              } else {
                message = response.status === 0 || response.status === 403
                  ? "Sign in again with this guard account to sync."
                  : "Sync paused. Your check-ins are saved on this device.";
                break;
              }
            }
          }
        }
      } else if (pending.length) {
        message = "Offline. Check-ins are saved on this device.";
      }
    } catch {
      message = "Sync unavailable. Pending check-ins will be retried.";
    }

    try {
      const entries = await queuedEntries();
      showQueue(entries, [sent ? `${sent} synced to dispatch.` : "", message].filter(Boolean).join(" ")
        || (entries.length ? "" : "No check-ins waiting to sync."));
    } catch {
      status.textContent = "Device storage unavailable. Keep this page open and check your browser settings.";
    } finally {
      syncing = false;
      retry.disabled = false;
    }
  }

  panel.hidden = false;
  const settings = document.querySelector("#checkin-offline-settings");
  if (settings && "serviceWorker" in navigator) {
    settings.hidden = false;
    const enable = document.querySelector("#checkin-offline-enable");
    const disable = document.querySelector("#checkin-offline-disable");
    const link = document.querySelector("#checkin-offline-link");
    const offlineStatus = document.querySelector("#checkin-offline-status");
    try {
      const saved = await inStore("offline", "readonly", (store) => store.get("profile"));
      link.hidden = saved?.guardId !== guardId;
      disable.hidden = !saved;
    } catch {
      settings.hidden = true;
    }
    enable.addEventListener("click", async () => {
      enable.disabled = disable.disabled = true;
      try {
        const auth = await request(form.dataset.sessionUrl);
        if (!auth.ok || (await auth.json()).guard_id !== guardId) {
          throw new Error("Sign in with this guard account first.");
        }
        const registration = await navigator.serviceWorker.register(enable.dataset.workerUrl);
        const worker = registration.installing || registration.waiting || registration.active;
        if (worker.state !== "activated") {
          await new Promise((resolve, reject) => {
            const onStateChange = () => {
              if (worker.state === "activated" || worker.state === "redundant") {
                worker.removeEventListener("statechange", onStateChange);
                if (worker.state === "activated") resolve();
                else reject(new Error("Offline page could not be installed."));
              }
            };
            worker.addEventListener("statechange", onStateChange);
            onStateChange();
          });
        }
        const assignments = Array.from(form.elements.assignment_id.options)
          .filter((option) => option.value)
          .map((option) => [option.value, option.textContent]);
        await inStore("offline", "readwrite", (store) => store.put({ guardId, assignments }, "profile"));
        link.hidden = disable.hidden = false;
        offlineStatus.textContent = "Offline page ready. Bookmark it before you lose connection.";
      } catch {
        offlineStatus.textContent = "Offline access could not be prepared. Sign in online and try again.";
      } finally {
        enable.disabled = disable.disabled = false;
      }
    });
    disable.addEventListener("click", async () => {
      try {
        await inStore("offline", "readwrite", (store) => store.delete("profile"));
        link.hidden = disable.hidden = true;
        offlineStatus.textContent = "Saved assignments removed. Pending check-ins are retained.";
      } catch {
        offlineStatus.textContent = "Saved assignments could not be removed. Try again.";
      }
    });
  }

  if (!guardId) {
    try {
      const profile = await inStore("offline", "readonly", (store) => store.get("profile"));
      if (!profile) {
        status.textContent = "Sign in online and enable offline access on the guard dashboard first.";
        return;
      }
      let auth;
      try {
        auth = await request(form.dataset.sessionUrl);
      } catch {
        // An unreachable server is expected when using this page in the field.
      }
      if (auth && (!auth.ok || (await auth.json()).guard_id !== profile.guardId)) {
        status.textContent = "Sign in with the guard account that enabled offline access.";
        return;
      }
      guardId = profile.guardId;
      for (const [value, label] of profile.assignments) {
        form.elements.assignment_id.add(new Option(label, value));
      }
      form.querySelector("fieldset").disabled = false;
      form.hidden = false;
    } catch {
      status.textContent = "Saved assignments could not be opened on this device.";
      return;
    }
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    submit.disabled = true;
    const fields = new FormData(form);
    try {
      await inStore("queue", "readwrite", (store) => store.add({
        guard_id: guardId,
        event_id: crypto.randomUUID(),
        captured_at: new Date().toISOString(),
        assignment_id: fields.get("assignment_id"),
        check_type: fields.get("check_type"),
        note: fields.get("note"),
      }));
      form.elements.note.value = "";
      status.textContent = "Check-in saved on this device.";
    } catch {
      status.textContent = "Check-in could not be saved. Your form is still filled in.";
      return;
    } finally {
      submit.disabled = false;
    }
    void sync();
  });

  retry.addEventListener("click", sync);
  window.addEventListener("online", sync);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) void sync();
  });
  setInterval(sync, 30000);
  void sync();
})();
