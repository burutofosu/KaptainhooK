(() => {
  const state = {
    config: null,
    configPath: "",
    dirty: false,
    saving: false,
    conflicts: null,
    uiLang: "ja",
    overrideTargetSelected: "",
  };

  const el = {};

  const STRINGS = {
    ja: {
      subtitle: "設定",
      save: "保存",
      tab_targets: "ターゲット",
      tab_friction: "摩擦",
      tab_policy: "ポリシー",
      tab_background: "スキン",
      tab_messages: "メッセージ",
      tab_reactions: "反応",
      tab_language: "言語",
      targets_header: "ターゲット",
      targets_enable_all: "すべて有効",
      targets_disable_all: "すべて無効",
      targets_placeholder: "example.exe",
      targets_add: "追加",
      targets_help: "ターゲットは .exe で終わり、パス区切り文字を含めないでください。",
      targets_remove: "削除",
      friction_header: "摩擦",
      friction_require_hold: "ホールドを要求",
      friction_hold_ms: "ホールド時間 (ms)",
      friction_require_move: "ポインター移動を要求",
      friction_move_threshold: "移動しきい値 (px)",
      friction_emergency_bypass: "緊急バイパス",
      friction_emergency_hold: "緊急ホールド (ms)",
      policy_header: "ポリシー",
      policy_allow_non_interactive: "非対話セッションを許可",
      policy_timeout_seconds: "タイムアウト (秒)",
      policy_auth_mode: "認証方式",
      policy_auth_friction: "摩擦",
      policy_auth_hello: "Windows Hello",
      policy_auto_restore: "自動復元 (秒)",
      paths_header: "検索パス",
      paths_placeholder: "C:\\Program Files\\Example",
      paths_add: "追加",
      paths_help: "ローカル絶対パスのみ（UNC不可）。",
      paths_remove: "削除",
      paths_empty: "追加された検索パスはありません。",
      background_header: "スキン",
      background_image: "スキン",
      background_opacity: "透明度",
      background_note: "スキンは設定画面にのみ適用されます。",
      background_none: "なし",
      background_k_hook: "K-HOOK",
      messages_header: "ナッジメッセージ",
      messages_desc: "確認ダイアログで表示される注意メッセージを設定します。",
      messages_id: "ID",
      messages_id_placeholder: "warn-01",
      messages_text: "テキスト",
      messages_text_placeholder: "表示する注意文...",
      messages_add: "追加",
      messages_remove: "削除",
      messages_empty: "カスタムメッセージがありません。既定のメッセージが使用されます。",
      reactions_header: "反応ルール",
      reactions_preset: "プリセット",
      reactions_preset_all_log: "ログのみ",
      reactions_preset_strong: "強: すべて確認",
      reactions_preset_medium: "中: メール/マクロ=確認・中継=通知",
      reactions_preset_weak: "弱: メール/マクロ=通知・中継=ログ",
      reactions_preset_note: "プリセットは既定ルールのみ更新。上書きは保持。",
      reactions_category: "起動元カテゴリ",
      reactions_action: "対応",
      reactions_mail: "メール",
      reactions_macro: "マクロ",
      reactions_relay: "中継",
      reactions_always: "固定",
      reactions_overrides: "ターゲット別設定",
      reactions_override_select_label: "個別ルール",
      reactions_override_select_empty: "個別ルールなし",
      reactions_override_select_help: "追加したターゲットだけが表示されます。",
      reactions_override_placeholder: "cmd.exe",
      reactions_override_add: "追加",
      reactions_override_remove: "削除",
      reactions_override_forced: "判定方法",
      reactions_kind_log: "ログ",
      reactions_kind_notify: "通知",
      reactions_kind_friction: "確認",
      reactions_forced_none: "起動元で決める",
      reactions_forced_always: "固定",
      reactions_forced_logging: "ログ固定",
      reactions_forced_note:
        "判定方法が固定の場合は「固定」の設定だけが使われます。",
      reactions_overrides_empty: "個別ルールはありません。追加してください。",
      language_header: "言語",
      language_ui: "UI言語",
      language_ja: "日本語",
      language_en: "English",
      config_path_prefix: "設定ファイル: ",
      conflict_title: "競合を検出しました",
      conflict_cancel: "キャンセル",
      conflict_apply: "適用",
      conflict_action_respect: "尊重",
      conflict_action_take_over: "上書き",
      conflict_action_quarantine: "隔離",
      conflict_action_abort: "中止",
      status_conflicts_detected: "競合を検出しました。対処を選択してください。",
      status_conflicts_cancelled: "競合をキャンセルしました。",
      status_conflicts_applying: "競合の適用中…",
    },
    en: {
      subtitle: "Settings",
      save: "Save",
      tab_targets: "Targets",
      tab_friction: "Friction",
      tab_policy: "Policy",
      tab_background: "Skin",
      tab_messages: "Messages",
      tab_reactions: "Reactions",
      tab_language: "Language",
      targets_header: "Targets",
      targets_enable_all: "Enable all",
      targets_disable_all: "Disable all",
      targets_placeholder: "example.exe",
      targets_add: "Add",
      targets_help: "Targets must end with .exe and contain no path separators.",
      targets_remove: "Remove",
      friction_header: "Friction",
      friction_require_hold: "Require hold",
      friction_hold_ms: "Hold duration (ms)",
      friction_require_move: "Require pointer movement",
      friction_move_threshold: "Pointer move threshold (px)",
      friction_emergency_bypass: "Emergency bypass",
      friction_emergency_hold: "Emergency hold (ms)",
      policy_header: "Policy",
      policy_allow_non_interactive: "Allow non-interactive",
      policy_timeout_seconds: "Timeout (seconds)",
      policy_auth_mode: "Auth mode",
      policy_auth_friction: "Friction",
      policy_auth_hello: "Windows Hello",
      policy_auto_restore: "Auto-restore (seconds)",
      paths_header: "Search Paths",
      paths_placeholder: "C:\\Program Files\\Example",
      paths_add: "Add",
      paths_help: "Local absolute paths only (UNC not allowed).",
      paths_remove: "Remove",
      paths_empty: "No custom search paths.",
      background_header: "Skin",
      background_image: "Skin",
      background_opacity: "Opacity",
      background_note: "Skin applies to the settings window only.",
      background_none: "None",
      background_k_hook: "K-HOOK",
      messages_header: "Nudge Messages",
      messages_desc: "Custom messages shown in the confirmation dialog.",
      messages_id: "ID",
      messages_id_placeholder: "warn-01",
      messages_text: "Text",
      messages_text_placeholder: "Warning message to display...",
      messages_add: "Add",
      messages_remove: "Remove",
      messages_empty: "No custom messages. Default message will be used.",
      reactions_header: "Reaction Rules",
      reactions_preset: "Preset",
      reactions_preset_all_log: "Log only",
      reactions_preset_strong: "Strong: always confirm",
      reactions_preset_medium: "Medium: Mail/Macro=confirm, Relay=notify",
      reactions_preset_weak: "Weak: Mail/Macro=notify, Relay=log",
      reactions_preset_note: "Presets update only the default rule. Overrides are kept.",
      reactions_category: "Origin category",
      reactions_action: "Action",
      reactions_mail: "Mail",
      reactions_macro: "Macro",
      reactions_relay: "Relay",
      reactions_always: "Fixed",
      reactions_overrides: "Per-Target Settings",
      reactions_override_select_label: "Override",
      reactions_override_select_empty: "No overrides",
      reactions_override_select_help: "Only added targets appear here.",
      reactions_override_placeholder: "cmd.exe",
      reactions_override_add: "Add",
      reactions_override_remove: "Remove",
      reactions_override_forced: "Decision mode",
      reactions_kind_log: "Log",
      reactions_kind_notify: "Notify",
      reactions_kind_friction: "Confirm",
      reactions_forced_none: "By origin",
      reactions_forced_always: "Fixed",
      reactions_forced_logging: "Logging",
      reactions_forced_note:
        "Fixed uses only the \"Fixed\" setting.",
      reactions_overrides_empty: "No overrides. Add one to edit.",
      language_header: "Language",
      language_ui: "UI Language",
      language_ja: "Japanese",
      language_en: "English",
      config_path_prefix: "Config: ",
      conflict_title: "Conflicts detected",
      conflict_cancel: "Cancel",
      conflict_apply: "Apply",
      conflict_action_respect: "Respect",
      conflict_action_take_over: "Take over",
      conflict_action_quarantine: "Quarantine",
      conflict_action_abort: "Abort",
      status_conflicts_detected: "Conflicts detected. Choose how to proceed.",
      status_conflicts_cancelled: "Conflicts cancelled.",
      status_conflicts_applying: "Applying conflict decisions...",
    },
  };

  const REACTION_KINDS = [
    { value: "log", label: "reactions_kind_log", i18n: true },
    { value: "notify", label: "reactions_kind_notify", i18n: true },
    { value: "friction", label: "reactions_kind_friction", i18n: true },
  ];

  const FORCED_CATEGORIES = [
    { value: "none", label: "reactions_forced_none", i18n: true },
    { value: "always", label: "reactions_forced_always", i18n: true },
    { value: "logging", label: "reactions_forced_logging", i18n: true },
  ];

  const SKIN_OPTIONS = __SKIN_OPTIONS__;
  const SKIN_URLS = __SKIN_URLS__;
  const SKIN_VALUE_MAP = new Map(
    SKIN_OPTIONS.map((opt) => [opt.value.toLowerCase(), opt.value])
  );
  const LEGACY_K_HOOK_VALUE = (() => {
    for (const opt of SKIN_OPTIONS) {
      const v = opt.value.toLowerCase();
      if (v.startsWith("k-hook") || v.startsWith("k_hook")) return opt.value;
    }
    return null;
  })();
  const DEFAULT_BACKGROUND_IMAGE = "kaptain-hook.png";

  const BACKGROUND_OPTIONS = [
    { value: "none", label: "background_none", i18n: true },
    ...SKIN_OPTIONS.map((opt) => ({
      value: opt.value,
      label: opt.label,
      i18n: false,
    })),
  ];

  const PRESET_RULES = {
    all_log: { mail: "log", macro: "log", relay: "log", always: "log" },
    strong: { mail: "friction", macro: "friction", relay: "friction", always: "friction" },
    medium: { mail: "friction", macro: "friction", relay: "notify", always: "friction" },
    weak: { mail: "notify", macro: "notify", relay: "log", always: "notify" },
  };

  function resolveLang(lang) {
    return STRINGS[lang] ? lang : "ja";
  }

  function applyTranslations(lang) {
    const current = resolveLang(lang);
    state.uiLang = current;
    document.documentElement.lang = current;
    const map = STRINGS[current];
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const key = node.dataset.i18n;
      if (map[key]) node.textContent = map[key];
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      const key = node.dataset.i18nPlaceholder;
      if (map[key]) node.placeholder = map[key];
    });
  }

  function t(key) {
    const map = STRINGS[state.uiLang] || STRINGS.ja;
    return map[key] || (STRINGS.ja && STRINGS.ja[key]) || key;
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function post(type, payload) {
    const msg = JSON.stringify(Object.assign({ type }, payload || {}));
    if (window.ipc && window.ipc.postMessage) {
      window.ipc.postMessage(msg);
    } else if (window.chrome && window.chrome.webview && window.chrome.webview.postMessage) {
      window.chrome.webview.postMessage(msg);
    } else {
      console.warn("IPC bridge not found");
    }
  }

  function setStatus(message, level) {
    const status = el.status;
    if (!message) {
      status.hidden = true;
      status.textContent = "";
      status.className = "status";
      return;
    }
    status.hidden = false;
    status.textContent = message;
    status.className = "status " + (level || "ok");
  }

  function updateSaveButton() {
    el.saveBtn.disabled = !state.dirty || state.saving;
  }

  function markDirty() {
    state.dirty = true;
    updateSaveButton();
  }

  function normalizeReactionKind(value) {
    return REACTION_KINDS.some((kind) => kind.value === value) ? value : "log";
  }

  function normalizeForced(value) {
    return FORCED_CATEGORIES.some((kind) => kind.value === value) ? value : "none";
  }

  function normalizeBackgroundOpacity(value) {
    if (value === null || value === undefined || value === "") return 30;
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed)) return 0;
    if (parsed < 0) return 0;
    if (parsed > 100) return 100;
    return parsed;
  }

  function normalizeBackgroundValue(value) {
    const trimmed = (value || "").trim();
    const lower = trimmed.toLowerCase();
    if (lower === "k_hook" || lower === "k-hook") {
      return LEGACY_K_HOOK_VALUE || "none";
    }
    if (trimmed === "none") return "none";
    return SKIN_VALUE_MAP.has(lower) ? SKIN_VALUE_MAP.get(lower) : "none";
  }

  function backgroundMode(value) {
    return normalizeBackgroundValue(value);
  }

  function backgroundUrlFromValue(value) {
    if (value === "none") return "";
    return SKIN_URLS[value] || "";
  }

  function ruleFromPreset(preset) {
    const rule = PRESET_RULES[preset] || PRESET_RULES.all_log;
    return {
      mail: normalizeReactionKind(rule.mail),
      macro: normalizeReactionKind(rule.macro),
      relay: normalizeReactionKind(rule.relay),
      always: normalizeReactionKind(rule.always),
    };
  }

  function normalizeRule(rule) {
    const safe = rule || {};
    return {
      mail: normalizeReactionKind(safe.mail),
      macro: normalizeReactionKind(safe.macro),
      relay: normalizeReactionKind(safe.relay),
      always: normalizeReactionKind(safe.always),
    };
  }

  function normalizeTargetKey(value) {
    return (value || "").trim().toLowerCase();
  }

  function targetLabelForKey(key) {
    if (!state.config) return key;
    const match = state.config.targets.find(
      (t) => normalizeTargetKey(t.exe_name) === key
    );
    return match ? match.exe_name : key;
  }

  function renderOverrideTargetSelect() {
    if (!state.config || !el.overrideTargetSelect) return;
    const select = el.overrideTargetSelect;
    const seen = new Set();
    const overrides = (state.config.reaction.overrides || [])
      .map((o) => ({
        key: normalizeTargetKey(o.target),
        label: targetLabelForKey(normalizeTargetKey(o.target)),
      }))
      .filter((o) => o.key && !seen.has(o.key) && seen.add(o.key));

    overrides.sort((a, b) => a.label.localeCompare(b.label));

    select.innerHTML = "";
    if (overrides.length === 0) {
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = t("reactions_override_select_empty");
      empty.disabled = true;
      empty.selected = true;
      select.appendChild(empty);
      state.overrideTargetSelected = "";
      return;
    }

    overrides.forEach((tgt) => {
      const opt = document.createElement("option");
      opt.value = tgt.key;
      opt.textContent = tgt.label;
      select.appendChild(opt);
    });

    const hasSelected = overrides.some((t) => t.key === state.overrideTargetSelected);
    if (!hasSelected) {
      state.overrideTargetSelected = overrides[0].key;
    }
    select.value = state.overrideTargetSelected;
  }

  function ensureConfigDefaults() {
    if (!state.config) return;
    if (!Array.isArray(state.config.nudge_messages)) {
      state.config.nudge_messages = [];
    }
    if (!Array.isArray(state.config.search_paths)) {
      state.config.search_paths = [];
    }
    if (!state.config.reaction) {
      state.config.reaction = {
        preset: "all_log",
        default_rule: ruleFromPreset("all_log"),
        overrides: [],
      };
    }
    if (!state.config.reaction.default_rule) {
      state.config.reaction.default_rule = ruleFromPreset(state.config.reaction.preset);
    }
    state.config.reaction.default_rule = normalizeRule(state.config.reaction.default_rule);
    if (!Array.isArray(state.config.reaction.overrides)) {
      state.config.reaction.overrides = [];
    }
    state.config.reaction.overrides = state.config.reaction.overrides.map((item) => ({
      target: item && item.target ? item.target : "",
      forced: normalizeForced(item && item.forced ? item.forced : "none"),
      rule: normalizeRule(item && item.rule ? item.rule : ruleFromPreset(state.config.reaction.preset)),
    }));
    if (!state.config.background) {
      state.config.background = { image: DEFAULT_BACKGROUND_IMAGE, opacity: 30 };
    }
    state.config.background.image = normalizeBackgroundValue(state.config.background.image);
    state.config.background.opacity = normalizeBackgroundOpacity(state.config.background.opacity);
  }

  function renderTargets() {
    const list = el.targetsList;
    list.innerHTML = "";
    if (!state.config) return;

    state.config.targets.forEach((target, idx) => {
      const row = document.createElement("div");
      row.className = "target-row";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = !!target.enabled;
      checkbox.addEventListener("change", () => {
        target.enabled = checkbox.checked;
        markDirty();
      });

      const name = document.createElement("div");
      name.className = "target-name";
      name.textContent = target.exe_name;

      const actions = document.createElement("div");
      actions.className = "target-actions";

      const removeBtn = document.createElement("button");
      removeBtn.className = "btn ghost";
      removeBtn.textContent = t("targets_remove");
      removeBtn.addEventListener("click", () => {
        state.config.targets.splice(idx, 1);
        renderTargets();
        markDirty();
      });

      actions.appendChild(removeBtn);
      row.appendChild(checkbox);
      row.appendChild(name);
      row.appendChild(actions);
      list.appendChild(row);
    });

    renderOverrideTargetSelect();
  }

  function renderPaths() {
    const list = el.pathsList;
    list.innerHTML = "";
    if (!state.config) return;

    if (state.config.search_paths.length === 0) {
      const empty = document.createElement("div");
      empty.className = "help";
      empty.textContent = t("paths_empty");
      list.appendChild(empty);
      return;
    }

    state.config.search_paths.forEach((path, idx) => {
      const row = document.createElement("div");
      row.className = "path-row";

      const value = document.createElement("div");
      value.className = "path-value";
      value.textContent = path;

      const removeBtn = document.createElement("button");
      removeBtn.className = "btn ghost";
      removeBtn.textContent = t("paths_remove");
      removeBtn.addEventListener("click", () => {
        state.config.search_paths.splice(idx, 1);
        renderPaths();
        markDirty();
      });

      row.appendChild(value);
      row.appendChild(removeBtn);
      list.appendChild(row);
    });
  }

  function renderMessages() {
    const list = el.messagesList;
    list.innerHTML = "";
    if (!state.config) return;

    if (state.config.nudge_messages.length === 0) {
      const empty = document.createElement("div");
      empty.className = "help";
      empty.textContent = t("messages_empty");
      list.appendChild(empty);
      return;
    }

    state.config.nudge_messages.forEach((message, idx) => {
      const row = document.createElement("div");
      row.className = "message-row";

      const grid = document.createElement("div");
      grid.className = "message-grid";

      const idInput = document.createElement("input");
      idInput.type = "text";
      idInput.value = message.message_id;
      idInput.placeholder = t("messages_id_placeholder");
      idInput.addEventListener("input", () => {
        message.message_id = idInput.value;
        markDirty();
      });

      const textArea = document.createElement("textarea");
      textArea.value = message.text;
      textArea.placeholder = t("messages_text_placeholder");
      textArea.maxLength = 200;
      textArea.addEventListener("input", () => {
        message.text = textArea.value;
        markDirty();
      });

      const removeBtn = document.createElement("button");
      removeBtn.className = "btn ghost";
      removeBtn.textContent = t("messages_remove");
      removeBtn.addEventListener("click", () => {
        state.config.nudge_messages.splice(idx, 1);
        renderMessages();
        markDirty();
      });

      grid.appendChild(idInput);
      grid.appendChild(textArea);
      grid.appendChild(removeBtn);
      row.appendChild(grid);
      list.appendChild(row);
    });
  }

  function fillSelectOptions(select, options, selected) {
    select.innerHTML = "";
    options.forEach((opt) => {
      const node = document.createElement("option");
      node.value = opt.value;
      node.textContent = opt.i18n ? t(opt.label) : opt.label;
      select.appendChild(node);
    });
    select.value = selected;
  }

  function availableBackgroundOptions() {
    return BACKGROUND_OPTIONS;
  }

  function applyBackground() {
    if (!state.config || !state.config.background) return;
    const url = backgroundUrlFromValue(state.config.background.image);
    const imageValue = url ? `url("${url}")` : "none";
    const opacity = normalizeBackgroundOpacity(state.config.background.opacity);
    document.body.style.setProperty("--bg-image", imageValue);
    document.body.style.setProperty("--bg-opacity", (opacity / 100).toString());
    if (el.backgroundOpacityValue) {
      el.backgroundOpacityValue.textContent = `${opacity}%`;
    }
  }

  function renderBackground() {
    if (!state.config || !el.backgroundImage || !el.backgroundOpacity) return;
    const options = availableBackgroundOptions();
    const selected = backgroundMode(state.config.background.image);
    fillSelectOptions(el.backgroundImage, options, selected);
    const opacity = normalizeBackgroundOpacity(state.config.background.opacity);
    state.config.background.opacity = opacity;
    el.backgroundOpacity.value = opacity;
    applyBackground();
  }

  function renderOverrides() {
    const list = el.overridesList;
    list.innerHTML = "";
    if (!state.config) return;

    renderOverrideTargetSelect();

    if (state.config.reaction.overrides.length === 0) {
      const empty = document.createElement("div");
      empty.className = "help";
      empty.textContent = t("reactions_overrides_empty");
      list.appendChild(empty);
      return;
    }

    const selectedKey = normalizeTargetKey(state.overrideTargetSelected);
    if (!selectedKey) return;
    renderOverrideForTarget(selectedKey, list);
  }

  function findOverrideIndex(key) {
    return state.config.reaction.overrides.findIndex(
      (o) => normalizeTargetKey(o.target) === key
    );
  }

  function renderOverrideForTarget(key, list) {
    const idx = findOverrideIndex(key);
    if (idx < 0) return;
    const override = state.config.reaction.overrides[idx];
    const rule = normalizeRule(override.rule);
    const forced = normalizeForced(override.forced);

    const row = document.createElement("div");
    row.className = "override-row";

    const head = document.createElement("div");
    head.className = "override-head";

    const title = document.createElement("div");
    title.textContent = targetLabelForKey(key);

    const removeBtn = document.createElement("button");
    removeBtn.className = "btn ghost";
    removeBtn.textContent = t("reactions_override_remove");
    removeBtn.addEventListener("click", () => {
      state.config.reaction.overrides.splice(idx, 1);
      if (state.config.reaction.overrides.length > 0) {
        state.overrideTargetSelected = normalizeTargetKey(
          state.config.reaction.overrides[0].target
        );
      } else {
        state.overrideTargetSelected = "";
      }
      renderOverrides();
      markDirty();
    });

    head.appendChild(title);
    head.appendChild(removeBtn);

    const grid = document.createElement("div");
    grid.className = "override-grid";

    const forcedLabel = document.createElement("label");
    const forcedText = document.createElement("span");
    forcedText.textContent = t("reactions_override_forced");
    const forcedSelect = document.createElement("select");
    fillSelectOptions(forcedSelect, FORCED_CATEGORIES, forced);
    forcedSelect.addEventListener("change", () => {
      override.forced = normalizeForced(forcedSelect.value);
      markDirty();
      renderOverrides();
    });
    forcedLabel.appendChild(forcedText);
    forcedLabel.appendChild(forcedSelect);
    grid.appendChild(forcedLabel);

    const showFixed = forced === "always";
    const fields = showFixed
      ? [["always", "reactions_always"]]
      : [
          ["mail", "reactions_mail"],
          ["macro", "reactions_macro"],
          ["relay", "reactions_relay"],
        ];

    fields.forEach(([k, labelKey]) => {
      const label = document.createElement("label");
      const text = document.createElement("span");
      text.textContent = t(labelKey);
      const select = document.createElement("select");
      fillSelectOptions(select, REACTION_KINDS, rule[k]);
      select.addEventListener("change", () => {
        override.rule[k] = normalizeReactionKind(select.value);
        markDirty();
      });
      label.appendChild(text);
      label.appendChild(select);
      grid.appendChild(label);
    });

    row.appendChild(head);
    row.appendChild(grid);
    list.appendChild(row);

  }

  function renderReactions() {
    if (!state.config) return;
    const reaction = state.config.reaction;
    if (!reaction) return;

    const preset = PRESET_RULES[reaction.preset] ? reaction.preset : "all_log";
    reaction.preset = preset;
    el.reactionPreset.value = preset;

    const rule = normalizeRule(reaction.default_rule);
    reaction.default_rule = rule;

    fillSelectOptions(el.reactionMail, REACTION_KINDS, rule.mail);
    fillSelectOptions(el.reactionMacro, REACTION_KINDS, rule.macro);
    fillSelectOptions(el.reactionRelay, REACTION_KINDS, rule.relay);

    renderOverrides();
  }

  function syncInputs() {
    if (!state.config) return;

    ensureConfigDefaults();

    const friction = state.config.friction;
    el.requireHold.checked = !!friction.require_hold;
    el.holdMs.value = friction.hold_ms;
    el.requireMove.checked = !!friction.require_pointer_movement;
    el.moveThreshold.value = friction.pointer_move_threshold_px;
    el.emergencyBypass.checked = !!friction.emergency_bypass;
    el.emergencyHold.value = friction.emergency_hold_ms;

    el.allowNonInteractive.checked = !!state.config.policy.allow_non_interactive;
    el.timeoutSeconds.value = state.config.policy.timeout_seconds;
    el.authMode.value = state.config.policy.auth_mode || "friction";
    el.autoRestore.value = state.config.auto_restore_seconds;
    const language = state.config.language || "ja";
    applyTranslations(language);
    el.language.value = language;

    renderTargets();
    renderPaths();
    renderMessages();
    renderReactions();
    renderBackground();

    el.configPath.textContent = state.configPath
      ? t("config_path_prefix") + state.configPath
      : "";
  }

  function switchTab(name) {
    document.querySelectorAll(".tab").forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.tab === name);
    });
    document.querySelectorAll("main .panel").forEach((panel) => {
      panel.hidden = !panel.id.endsWith(name);
    });
  }

  function showConflicts(items) {
    const body = el.conflictBody;
    body.innerHTML = "";
    items.forEach((item) => {
      const wrap = document.createElement("div");
      wrap.className = "conflict-item";
      const title = document.createElement("h4");
      title.textContent = item.target;
      wrap.appendChild(title);

      const details = document.createElement("ul");
      item.details.forEach((d) => {
        const li = document.createElement("li");
        li.textContent = d;
        details.appendChild(li);
      });
      wrap.appendChild(details);

      const actions = document.createElement("div");
      actions.className = "conflict-actions";
      const select = document.createElement("select");
      select.dataset.target = item.target;
      [
        ["respect", "conflict_action_respect"],
        ["take_over", "conflict_action_take_over"],
        ["quarantine", "conflict_action_quarantine"],
        ["abort", "conflict_action_abort"],
      ].forEach(([value, labelKey]) => {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = t(labelKey);
        select.appendChild(opt);
      });
      actions.appendChild(select);
      wrap.appendChild(actions);
      body.appendChild(wrap);
    });

    el.conflictModal.hidden = false;
    el.conflictModal.classList.add("show");
  }

  function hideConflicts() {
    el.conflictModal.hidden = true;
    el.conflictModal.classList.remove("show");
    el.conflictBody.innerHTML = "";
  }

  function bindEvents() {
    el.saveBtn.addEventListener("click", () => {
      if (!state.config) return;
      state.saving = true;
      updateSaveButton();
      post("save", { config: state.config });
    });

    el.enableAll.addEventListener("click", () => {
      if (!state.config) return;
      state.config.targets.forEach((t) => (t.enabled = true));
      renderTargets();
      markDirty();
    });

    el.disableAll.addEventListener("click", () => {
      if (!state.config) return;
      state.config.targets.forEach((t) => (t.enabled = false));
      renderTargets();
      markDirty();
    });

    el.addTarget.addEventListener("click", () => {
      if (!state.config) return;
      const name = el.newTarget.value.trim();
      if (!name) return;
      state.config.targets.push({ exe_name: name, enabled: true });
      el.newTarget.value = "";
      renderTargets();
      markDirty();
    });

    el.addPath.addEventListener("click", () => {
      if (!state.config) return;
      const path = el.newPath.value.trim();
      if (!path) return;
      state.config.search_paths.push(path);
      el.newPath.value = "";
      renderPaths();
      markDirty();
    });

    el.addMessage.addEventListener("click", () => {
      if (!state.config) return;
      const id = el.messageId.value.trim();
      const text = el.messageText.value.trim();
      if (!id || !text) return;
      state.config.nudge_messages.push({ message_id: id, text });
      el.messageId.value = "";
      el.messageText.value = "";
      renderMessages();
      markDirty();
    });

    el.addOverride.addEventListener("click", () => {
      if (!state.config) return;
      const target = el.overrideTarget.value.trim();
      if (!target) return;
      const key = normalizeTargetKey(target);
      const existingIndex = findOverrideIndex(key);
      if (existingIndex >= 0) {
        state.overrideTargetSelected = key;
        el.overrideTarget.value = "";
        renderOverrides();
        return;
      }
      state.config.reaction.overrides.push({
        target: key,
        forced: "none",
        rule: { ...state.config.reaction.default_rule },
      });
      state.overrideTargetSelected = key;
      el.overrideTarget.value = "";
      renderOverrides();
      markDirty();
    });

    if (el.overrideTargetSelect) {
      el.overrideTargetSelect.addEventListener("change", () => {
        state.overrideTargetSelected = el.overrideTargetSelect.value || "";
        renderOverrides();
      });
    }

    el.requireHold.addEventListener("change", () => {
      state.config.friction.require_hold = el.requireHold.checked;
      markDirty();
    });
    el.holdMs.addEventListener("input", () => {
      state.config.friction.hold_ms = parseInt(el.holdMs.value, 10) || 0;
      markDirty();
    });
    el.requireMove.addEventListener("change", () => {
      state.config.friction.require_pointer_movement = el.requireMove.checked;
      markDirty();
    });
    el.moveThreshold.addEventListener("input", () => {
      state.config.friction.pointer_move_threshold_px = parseInt(el.moveThreshold.value, 10) || 0;
      markDirty();
    });
    el.emergencyBypass.addEventListener("change", () => {
      state.config.friction.emergency_bypass = el.emergencyBypass.checked;
      markDirty();
    });
    el.emergencyHold.addEventListener("input", () => {
      state.config.friction.emergency_hold_ms = parseInt(el.emergencyHold.value, 10) || 0;
      markDirty();
    });

    el.allowNonInteractive.addEventListener("change", () => {
      state.config.policy.allow_non_interactive = el.allowNonInteractive.checked;
      markDirty();
    });
    el.timeoutSeconds.addEventListener("input", () => {
      state.config.policy.timeout_seconds = parseInt(el.timeoutSeconds.value, 10) || 0;
      markDirty();
    });
    el.authMode.addEventListener("change", () => {
      state.config.policy.auth_mode = el.authMode.value;
      markDirty();
    });
    el.autoRestore.addEventListener("input", () => {
      let v = parseInt(el.autoRestore.value, 10);
      if (!Number.isFinite(v)) {
        v = state.config.auto_restore_seconds || 2;
      }
      if (v < 1) v = 1;
      if (v > 300) v = 300;
      state.config.auto_restore_seconds = v;
      markDirty();
    });

    el.backgroundImage.addEventListener("change", () => {
      if (!state.config) return;
    const selected = el.backgroundImage.value;
    const previous = state.config.background.image;
    state.config.background.image = normalizeBackgroundValue(selected);
    if (
      state.config.background.image !== "none" &&
      previous === "none" &&
      normalizeBackgroundOpacity(state.config.background.opacity) === 0
    ) {
      state.config.background.opacity = 30;
      if (el.backgroundOpacity) {
        el.backgroundOpacity.value = 30;
      }
    }
    applyBackground();
    markDirty();
  });
    el.backgroundOpacity.addEventListener("input", () => {
      if (!state.config) return;
      state.config.background.opacity = normalizeBackgroundOpacity(el.backgroundOpacity.value);
      applyBackground();
      markDirty();
    });

    bindBackgroundToggle();

    el.reactionPreset.addEventListener("change", () => {
      if (!state.config) return;
      const preset = PRESET_RULES[el.reactionPreset.value]
        ? el.reactionPreset.value
        : "all_log";
      state.config.reaction.preset = preset;
      state.config.reaction.default_rule = ruleFromPreset(preset);
      renderReactions();
      markDirty();
    });

    const reactionSelectHandlers = [
      [el.reactionMail, "mail"],
      [el.reactionMacro, "macro"],
      [el.reactionRelay, "relay"],
    ];
    reactionSelectHandlers.forEach(([select, key]) => {
      select.addEventListener("change", () => {
        if (!state.config) return;
        state.config.reaction.default_rule[key] = normalizeReactionKind(select.value);
        markDirty();
      });
    });

    el.language.addEventListener("change", () => {
      state.config.language = el.language.value;
      applyTranslations(state.config.language);
    renderTargets();
    renderPaths();
    renderMessages();
    renderReactions();
    renderBackground();
      markDirty();
    });

    document.querySelectorAll(".tab").forEach((tab) => {
      tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    });

    el.conflictModal.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.id === "conflict-cancel") {
        hideConflicts();
        setStatus(t("status_conflicts_cancelled"), "ok");
        post("abort_conflicts");
      }
      if (target.id === "conflict-apply") {
        const selects = el.conflictBody.querySelectorAll("select[data-target]");
        const decisions = Array.from(selects).map((select) => ({
          target: select.dataset.target,
          action: select.value,
        }));
        hideConflicts();
        setStatus(t("status_conflicts_applying"), "ok");
        post("resolve_conflicts", { decisions });
      }
    });
  }

  function bindBackgroundToggle() {
    const appRoot = el.app;
    if (!appRoot) return;
    document.addEventListener(
      "pointerdown",
      (event) => {
        if (el.conflictModal && !el.conflictModal.hidden) return;
        if (document.body.classList.contains("ui-hidden")) {
          document.body.classList.remove("ui-hidden");
          return;
        }
        if (!appRoot.contains(event.target)) {
          document.body.classList.add("ui-hidden");
        }
      },
      { passive: true }
    );
  }

  function onHostMessage(message) {
    if (!message || !message.type) return;
    switch (message.type) {
      case "init":
        state.config = message.config;
        state.configPath = message.config_path || "";
        state.dirty = false;
        state.saving = false;
        applyTranslations(state.config.language || "ja");
        updateSaveButton();
        syncInputs();
        setStatus("", "ok");
        break;
      case "status":
        state.saving = false;
        if (message.ok) {
          state.dirty = false;
          updateSaveButton();
        }
        setStatus(message.message, message.ok ? "ok" : "error");
        break;
      case "conflicts":
        state.saving = false;
        updateSaveButton();
        showConflicts(message.items || []);
        setStatus(t("status_conflicts_detected"), "error");
        break;
      default:
        break;
    }
  }

  window.__onHostMessage = onHostMessage;

  document.addEventListener("DOMContentLoaded", () => {
    el.app = byId("app");
    el.saveBtn = byId("save-btn");
    el.status = byId("status");
    el.targetsList = byId("targets-list");
    el.newTarget = byId("new-target");
    el.addTarget = byId("add-target");
    el.enableAll = byId("enable-all");
    el.disableAll = byId("disable-all");
    el.requireHold = byId("require-hold");
    el.holdMs = byId("hold-ms");
    el.requireMove = byId("require-move");
    el.moveThreshold = byId("move-threshold");
    el.emergencyBypass = byId("emergency-bypass");
    el.emergencyHold = byId("emergency-hold");
    el.allowNonInteractive = byId("allow-non-interactive");
    el.timeoutSeconds = byId("timeout-seconds");
    el.authMode = byId("auth-mode");
    el.autoRestore = byId("auto-restore");
    el.backgroundImage = byId("background-image");
    el.backgroundOpacity = byId("background-opacity");
    el.backgroundOpacityValue = byId("background-opacity-value");
    el.pathsList = byId("paths-list");
    el.newPath = byId("new-path");
    el.addPath = byId("add-path");
    el.messagesList = byId("messages-list");
    el.messageId = byId("message-id");
    el.messageText = byId("message-text");
    el.addMessage = byId("add-message");
    el.reactionPreset = byId("reaction-preset");
    el.reactionMail = byId("reaction-mail");
    el.reactionMacro = byId("reaction-macro");
    el.reactionRelay = byId("reaction-relay");
    el.overridesList = byId("overrides-list");
    el.overrideTargetSelect = byId("override-target-select");
    el.overrideTarget = byId("override-target");
    el.addOverride = byId("add-override");
    el.language = byId("language");
    el.configPath = byId("config-path");
    el.conflictModal = byId("conflict-modal");
    el.conflictBody = byId("conflict-body");
    el.conflictCancel = byId("conflict-cancel");
    el.conflictApply = byId("conflict-apply");

    bindEvents();
    post("init");
  });
})();
