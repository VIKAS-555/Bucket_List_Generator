/* Per-user lists: PBKDF2-SHA-256 and AES-GCM. localStorage holds ciphertext only. */
(function () {
  "use strict";

  var PBKDF2_ITERATIONS = 100000;
  var STORAGE_PREFIX = "blg.vault.v1.";
  var KDF = "PBKDF2-SHA-256";

  var CATEGORIES = {
    travel: { tag: "tag-travel", label: "Travel & Adventure" },
    career: { tag: "tag-career", label: "Learning & Career" },
    fitness: { tag: "tag-fitness", label: "Health & Fitness" },
    experiences: { tag: "tag-experiences", label: "Experiences" }
  };

  var TAG_LABELS = {
    "tag-travel": "Travel & Adventure",
    "tag-career": "Learning & Career",
    "tag-fitness": "Health & Fitness",
    "tag-experiences": "Experiences"
  };

  var accountForm = document.getElementById("account-form");
  var usernameInput = document.getElementById("account-username");
  var passcodeInput = document.getElementById("account-passcode");
  var accountError = document.getElementById("account-error");
  var accountStatus = document.getElementById("account-status");
  var signInBtn = document.getElementById("sign-in-btn");
  var createBtn = document.getElementById("create-account-btn");
  var signOutBtn = document.getElementById("sign-out-btn");
  var navSession = document.getElementById("nav-session");
  var sessionUser = document.getElementById("session-user");
  var suggestForm = document.querySelector("#suggest .suggest-form");
  var grid = document.querySelector(".milestones-grid");
  var saveError = document.getElementById("save-error");

  var sampleGoals = [];
  var session = null;
  var saveQueue = Promise.resolve();

  if (!accountForm || !usernameInput || !passcodeInput || !accountError || !accountStatus || !signInBtn || !createBtn || !signOutBtn || !navSession || !sessionUser || !suggestForm || !grid) {
    return;
  }

  sampleGoals = snapshotGoals();
  grid.textContent = "";
  refreshProgress();

  if (!window.crypto || !crypto.subtle) {
    setAccountError("This browser cannot keep a private list. Open the page on localhost or HTTPS.");
  }

  accountForm.addEventListener("submit", function (event) {
    event.preventDefault();
    unlock(false);
  });

  createBtn.addEventListener("click", function () {
    unlock(true);
  });

  signOutBtn.addEventListener("click", function () {
    signOut();
  });

  suggestForm.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!session) return;
    var name = suggestForm.elements["user-name"].value.trim();
    var category = suggestForm.elements["goal-category"].value;
    var details = suggestForm.elements["goal-details"].value.trim();
    if (addCard(name, category, details)) {
      suggestForm.reset();
      persist();
    }
  });

  grid.addEventListener("change", function (event) {
    if (!session || !event.target.classList.contains("goal-check")) return;
    refreshProgress();
    persist();
  });

  function unlock(creating) {
    if (signInBtn.disabled) return;
    setAccountError("");
    var displayName = usernameInput.value.trim();
    var username = displayName.toLowerCase();
    var passcode = passcodeInput.value;

    if (!username || !passcode) {
      setAccountError("Enter a username and a secret passcode.");
      return;
    }
    if (username.length > 64) {
      setAccountError("Use a username of 64 characters or fewer.");
      return;
    }
    if (!window.crypto || !crypto.subtle) {
      setAccountError("This browser cannot keep a private list. Open the page on localhost or HTTPS.");
      return;
    }

    var storageKey = STORAGE_PREFIX + encodeURIComponent(username);
    var existingRaw = null;
    try {
      existingRaw = localStorage.getItem(storageKey);
    } catch (error) {
      setAccountError("This browser blocked local storage, so the list cannot be saved.");
      return;
    }

    if (creating && existingRaw) {
      setAccountError("An account with that username already exists. Sign in instead.");
      return;
    }
    if (!creating && !existingRaw) {
      setAccountError("No account exists for that username.");
      return;
    }

    var record = null;
    if (!creating) {
      try {
        record = JSON.parse(existingRaw);
        if (!isVaultRecord(record)) throw new Error("bad record");
      } catch (error) {
        setAccountError("This account could not be opened.");
        return;
      }
    }

    setBusy(true);
    setAccountStatus(creating ? "Creating your encrypted list…" : "Checking passcode…");

    var salt = creating ? crypto.getRandomValues(new Uint8Array(16)) : base64ToBytes(record.salt);
    var iterations = creating ? PBKDF2_ITERATIONS : record.iterations;

    deriveKey(passcode, salt, iterations).then(function (key) {
      passcode = "";
      passcodeInput.value = "";
      if (creating) {
        if (localStorage.getItem(storageKey)) {
          var clash = new Error("Account already exists.");
          clash.name = "AccountExists";
          throw clash;
        }
        var seeded = cloneGoals(sampleGoals);
        return seal(key, username, seeded).then(function (sealed) {
          var stored = {
            v: 1,
            kdf: KDF,
            iterations: PBKDF2_ITERATIONS,
            salt: bytesToBase64(salt),
            iv: sealed.iv,
            ciphertext: sealed.ciphertext
          };
          localStorage.setItem(storageKey, JSON.stringify(stored));
          beginSession(username, displayName, key, storageKey, stored.salt, stored.iterations, seeded);
        });
      }
      return openSealed(key, username, record).then(function (goals) {
        beginSession(username, displayName, key, storageKey, record.salt, record.iterations, goals);
      });
    }).catch(function (error) {
      signOut();
      if (creating && error && error.name === "AccountExists") {
        setAccountError("An account with that username already exists. Sign in instead.");
      } else if (!creating && error && error.name === "OperationError") {
        setAccountError("That passcode does not unlock this list.");
      } else if (!creating) {
        setAccountError("This account could not be opened.");
      } else {
        setAccountError("Could not create that account.");
      }
    }).then(function () {
      setBusy(false);
      setAccountStatus("");
    });
  }

  function beginSession(username, displayName, key, storageKey, saltB64, iterations, goals) {
    session = {
      username: username,
      displayName: displayName,
      key: key,
      storageKey: storageKey,
      saltB64: saltB64,
      iterations: iterations
    };
    renderGoals(goals);
    document.body.classList.remove("is-locked");
    navSession.hidden = false;
    sessionUser.textContent = displayName;
    setSaveError("");
    setAccountError("");
  }

  function signOut() {
    session = null;
    grid.textContent = "";
    refreshProgress();
    document.body.classList.add("is-locked");
    navSession.hidden = true;
    sessionUser.textContent = "";
    suggestForm.reset();
    passcodeInput.value = "";
    setSaveError("");
  }

  function persist() {
    if (!session) return;
    var current = session;
    var goals = collectGoals();
    saveQueue = saveQueue.then(function () {
      return seal(current.key, current.username, goals).then(function (sealed) {
        var record = {
          v: 1,
          kdf: KDF,
          iterations: current.iterations,
          salt: current.saltB64,
          iv: sealed.iv,
          ciphertext: sealed.ciphertext
        };
        localStorage.setItem(current.storageKey, JSON.stringify(record));
        if (session === current) setSaveError("");
      });
    }).catch(function () {
      if (session === current) setSaveError("Could not save this list. Try again.");
    });
  }

  function deriveKey(passcode, salt, iterations) {
    return crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(passcode),
      "PBKDF2",
      false,
      ["deriveKey"]
    ).then(function (material) {
      return crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: iterations,
          hash: "SHA-256"
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    });
  }

  function seal(key, username, goals) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var plain = new TextEncoder().encode(JSON.stringify({ goals: goals }));
    return crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: new TextEncoder().encode(username)
      },
      key,
      plain
    ).then(function (buf) {
      return {
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(new Uint8Array(buf))
      };
    });
  }

  function openSealed(key, username, record) {
    return crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(record.iv),
        additionalData: new TextEncoder().encode(username)
      },
      key,
      base64ToBytes(record.ciphertext)
    ).then(function (buf) {
      var payload = JSON.parse(new TextDecoder().decode(new Uint8Array(buf)));
      if (!payload || !Array.isArray(payload.goals)) {
        var invalid = new Error("bad payload");
        invalid.name = "DataError";
        throw invalid;
      }
      return payload.goals.map(function (goal) {
        return {
          id: typeof goal.id === "string" ? goal.id : "",
          completed: !!goal.completed,
          categoryClass: typeof goal.categoryClass === "string" ? goal.categoryClass : "",
          categoryLabel: typeof goal.categoryLabel === "string" ? goal.categoryLabel : "",
          title: typeof goal.title === "string" ? goal.title : "",
          description: typeof goal.description === "string" ? goal.description : "",
          suggestedBy: typeof goal.suggestedBy === "string" ? goal.suggestedBy : ""
        };
      });
    });
  }

  function isVaultRecord(record) {
    if (!record || record.v !== 1 || record.kdf !== KDF) return false;
    if (record.iterations !== PBKDF2_ITERATIONS) return false;
    if (typeof record.salt !== "string" || typeof record.iv !== "string" || typeof record.ciphertext !== "string") {
      return false;
    }
    try {
      return base64ToBytes(record.salt).length === 16 &&
        base64ToBytes(record.iv).length === 12 &&
        base64ToBytes(record.ciphertext).length > 0;
    } catch (error) {
      return false;
    }
  }

  function bytesToBase64(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function base64ToBytes(value) {
    var bin = atob(value);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function cloneGoals(goals) {
    return goals.map(function (goal) {
      return {
        id: goal.id,
        completed: !!goal.completed,
        categoryClass: goal.categoryClass,
        categoryLabel: goal.categoryLabel,
        title: goal.title,
        description: goal.description,
        suggestedBy: goal.suggestedBy
      };
    });
  }

  function snapshotGoals() {
    return collectGoals();
  }

  function collectGoals() {
    var goals = [];
    grid.querySelectorAll(".card-wrapper").forEach(function (wrapper) {
      goals.push(readCard(wrapper));
    });
    return goals;
  }

  function readCard(wrapper) {
    var input = wrapper.querySelector(".goal-check");
    var tag = wrapper.querySelector(".category-tag");
    var title = wrapper.querySelector(".card-title");
    var desc = wrapper.querySelector(".card-desc");
    var byline = wrapper.querySelector(".suggested-by");
    var categoryClass = "tag-experiences";
    if (tag) {
      tag.className.split(/\s+/).forEach(function (cls) {
        if (TAG_LABELS[cls]) categoryClass = cls;
      });
    }
    var suggestedBy = "";
    if (byline) suggestedBy = byline.textContent.replace(/^Suggested by\s+/, "");
    return {
      id: input ? input.id : "",
      completed: !!(input && input.checked),
      categoryClass: categoryClass,
      categoryLabel: tag ? tag.textContent : (TAG_LABELS[categoryClass] || ""),
      title: title ? title.textContent : "",
      description: desc ? desc.textContent : "",
      suggestedBy: suggestedBy
    };
  }

  function renderGoals(goals) {
    grid.textContent = "";
    var used = {};
    goals.forEach(function (goal) {
      if (!goal.title) return;
      var categoryClass = TAG_LABELS[goal.categoryClass] ? goal.categoryClass : "tag-experiences";
      appendCard({
        id: safeId(goal.id, used),
        completed: !!goal.completed,
        categoryClass: categoryClass,
        categoryLabel: goal.categoryLabel || TAG_LABELS[categoryClass],
        title: goal.title,
        description: goal.description || "",
        suggestedBy: goal.suggestedBy || ""
      }, false);
    });
    refreshProgress();
  }

  function safeId(id, used) {
    if (typeof id === "string" && /^[A-Za-z][\w:-]{0,40}$/.test(id) && !used[id]) {
      used[id] = true;
      return id;
    }
    var n = 1;
    var next = "goal-1";
    while (used[next]) {
      n += 1;
      next = "goal-" + n;
    }
    used[next] = true;
    return next;
  }

  function addCard(name, categoryKey, details) {
    var parsed = parseGoal(details);
    if (!parsed.title) return false;
    var category = CATEGORIES[categoryKey] || CATEGORIES.experiences;
    appendCard({
      id: nextGoalId(),
      completed: false,
      categoryClass: category.tag,
      categoryLabel: category.label,
      title: parsed.title,
      description: parsed.description,
      suggestedBy: name
    }, true);
    refreshProgress();
    return true;
  }

  function nextGoalId() {
    var max = 0;
    grid.querySelectorAll(".goal-check").forEach(function (input) {
      var match = /^goal-(\d+)$/.exec(input.id);
      if (match) max = Math.max(max, Number(match[1]));
    });
    return "goal-" + (max + 1);
  }

  function parseGoal(text) {
    var lines = text.replace(/\r\n/g, "\n").split("\n");
    var title = "";
    var index = 0;
    while (index < lines.length && !lines[index].trim()) index += 1;
    if (index < lines.length) title = lines[index].trim();
    var description = lines.slice(index + 1).join("\n").trim();
    return { title: title, description: description };
  }

  function appendCard(goal, scroll) {
    var wrapper = document.createElement("div");
    wrapper.className = "card-wrapper";

    var input = document.createElement("input");
    input.type = "checkbox";
    input.id = goal.id;
    input.className = "goal-check";
    input.checked = !!goal.completed;

    var label = document.createElement("label");
    label.className = "goal-card";
    label.htmlFor = goal.id;

    var tag = document.createElement("span");
    tag.className = "category-tag " + goal.categoryClass;
    tag.textContent = goal.categoryLabel;
    label.appendChild(tag);

    var title = document.createElement("h3");
    title.className = "card-title";
    title.textContent = goal.title;
    label.appendChild(title);

    if (goal.description) {
      var desc = document.createElement("p");
      desc.className = "card-desc";
      desc.textContent = goal.description;
      label.appendChild(desc);
    }

    if (goal.suggestedBy) {
      var byline = document.createElement("p");
      byline.className = "suggested-by";
      byline.textContent = "Suggested by " + goal.suggestedBy;
      label.appendChild(byline);
    }

    var footer = document.createElement("div");
    footer.className = "card-footer";
    var status = document.createElement("span");
    status.className = "status-text";
    var box = document.createElement("div");
    box.className = "checkbox-visual";
    footer.appendChild(status);
    footer.appendChild(box);
    label.appendChild(footer);

    wrapper.appendChild(input);
    wrapper.appendChild(label);
    grid.appendChild(wrapper);
    if (scroll) wrapper.scrollIntoView({ block: "nearest" });
  }

  function refreshProgress() {
    var checks = grid.querySelectorAll(".goal-check");
    var total = checks.length;
    var completed = 0;
    var categorySet = {};

    checks.forEach(function (input) {
      if (input.checked) completed += 1;
      var tag = input.parentElement && input.parentElement.querySelector(".category-tag");
      if (!tag) return;
      tag.className.split(/\s+/).forEach(function (cls) {
        if (cls.indexOf("tag-") === 0) categorySet[cls] = true;
      });
    });

    var pending = total - completed;
    var percent = total === 0 ? 0 : Math.round((completed / total) * 100);
    var summary = document.querySelector(".milestone-acheived");
    var fill = document.querySelector(".progress-bar-fill");
    var stats = document.querySelectorAll(".milestone-stats .stat-val");

    if (summary) {
      summary.textContent = completed + " of " + total + " acheived (" + percent + "%)";
    }
    if (fill) fill.style.width = percent + "%";
    if (stats.length >= 4) {
      stats[0].textContent = String(total);
      stats[1].textContent = String(completed);
      stats[2].textContent = String(pending);
      stats[3].textContent = String(Object.keys(categorySet).length);
    }
  }

  function setBusy(busy) {
    signInBtn.disabled = busy;
    createBtn.disabled = busy;
    usernameInput.disabled = busy;
    passcodeInput.disabled = busy;
  }

  function setAccountError(message) {
    accountError.textContent = message || "";
    accountError.hidden = !message;
  }

  function setAccountStatus(message) {
    accountStatus.textContent = message || "";
  }

  function setSaveError(message) {
    if (!saveError) return;
    saveError.textContent = message || "";
    saveError.hidden = !message;
  }
})();
