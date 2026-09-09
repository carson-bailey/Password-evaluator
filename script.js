/* Password Entropy Evaluator — core analysis logic
 * No dependencies. Works in the browser and is testable under Node.
 */

const COMMON_PASSWORDS = [
  "123456","password","123456789","12345678","12345","qwerty","abc123","password1",
  "111111","123123","1234567","dragon","letmein","monkey","football","iloveyou",
  "admin","welcome","login","princess","sunshine","master","hello","freedom",
  "whatever","qazwsx","trustno1","1q2w3e4r","password123","000000","1234",
  "shadow","superman","batman","michael","jennifer","121212","flower","hottie",
  "loveme","zaq1zaq1","password!","qwertyuiop","asdfghjkl","1qaz2wsx","passw0rd",
  "letmein1","charlie","donald","ashley","bailey","access","master1","696969",
  "starwars","666666","photoshop","1qaz1qaz","666666","987654321","987654",
  "qwerty123","1q2w3e4r5t","zxcvbnm","asdfasdf","ninja","mustang","baseball",
];

const KEYBOARD_ROWS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
  "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "0987654321",
];

function log2(x) {
  return Math.log(x) / Math.log(2);
}

function poolSizeForPassword(pw) {
  let size = 0;
  const flags = {
    lower: /[a-z]/.test(pw),
    upper: /[A-Z]/.test(pw),
    digit: /[0-9]/.test(pw),
    symbol: /[^A-Za-z0-9]/.test(pw) && /^[\x20-\x7E]*$/.test(pw), // printable ASCII symbol
    extended: /[^\x00-\x7F]/.test(pw), // anything outside basic ASCII
  };
  if (flags.lower) size += 26;
  if (flags.upper) size += 26;
  if (flags.digit) size += 10;
  if (flags.symbol) size += 33;
  if (flags.extended) size += 100; // rough allowance for accented/unicode/emoji characters
  return { size: Math.max(size, 1), flags };
}

function longestMonotonicRun(lower) {
  // Detects ascending or descending runs of 4+ consecutive characters,
  // e.g. "abcd", "4321", within letters or digits.
  let best = 0;
  for (let i = 0; i < lower.length - 1; i++) {
    let runUp = 1, runDown = 1;
    let j = i;
    while (j + 1 < lower.length && lower.charCodeAt(j + 1) - lower.charCodeAt(j) === 1) {
      runUp++; j++;
    }
    j = i;
    while (j + 1 < lower.length && lower.charCodeAt(j + 1) - lower.charCodeAt(j) === -1) {
      runDown++; j++;
    }
    best = Math.max(best, runUp, runDown);
  }
  return best;
}

function repeatedCharRun(pw) {
  let best = 1, current = 1;
  for (let i = 1; i < pw.length; i++) {
    if (pw[i] === pw[i - 1]) {
      current++;
      best = Math.max(best, current);
    } else {
      current = 1;
    }
  }
  return best;
}

function isRepeatingBlock(pw) {
  // Detects strings made of a repeated shorter substring, e.g. "abcabcabc".
  return /^(.+?)\1+$/.test(pw);
}

function detectPatterns(pw) {
  const lower = pw.toLowerCase();
  const warnings = [];
  let penalty = 0;

  if (COMMON_PASSWORDS.includes(lower)) {
    warnings.push("Matches a commonly used password");
    penalty += 1000; // effectively floors entropy elsewhere
  }

  const run = longestMonotonicRun(lower);
  if (run >= 4) {
    warnings.push("Contains a sequential run (e.g. abcd, 4321)");
    penalty += 10 * (run - 3);
  }

  for (const row of KEYBOARD_ROWS) {
    for (let len = Math.min(6, row.length); len >= 4; len--) {
      for (let i = 0; i + len <= row.length; i++) {
        if (lower.includes(row.slice(i, i + len))) {
          warnings.push("Contains a keyboard-adjacent sequence (e.g. qwerty, asdf)");
          penalty += 10;
          break;
        }
      }
    }
  }

  const repeat = repeatedCharRun(pw);
  if (repeat >= 3) {
    warnings.push("Contains a repeated character run (e.g. aaa, 111)");
    penalty += 8 * (repeat - 2);
  }

  if (pw.length >= 4 && isRepeatingBlock(pw)) {
    warnings.push("Password is a repeated short block (e.g. abcabcabc)");
    penalty += 20;
  }

  // De-duplicate warnings that may have been added multiple times.
  return { penalty, warnings: [...new Set(warnings)] };
}

function ratingForBits(bits) {
  if (bits < 28) return { label: "Very weak", tier: 1 };
  if (bits < 36) return { label: "Weak", tier: 2 };
  if (bits < 60) return { label: "Fair", tier: 3 };
  if (bits < 80) return { label: "Strong", tier: 4 };
  return { label: "Very strong", tier: 5 };
}

function formatDuration(seconds) {
  if (!isFinite(seconds) || seconds < 0) return "n/a";
  if (seconds < 1) return "instantly";
  const units = [
    ["year", 31557600],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1],
  ];
  // Cap absurdly large spans with a readable order-of-magnitude figure.
  const years = seconds / 31557600;
  if (years >= 1e6) {
    const exp = Math.floor(log2(years) / log2(10));
    return `>10^${exp} years`;
  }
  for (const [name, secs] of units) {
    if (seconds >= secs) {
      const value = seconds / secs;
      const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
      return `${rounded} ${name}${rounded === 1 ? "" : "s"}`;
    }
  }
  return "instantly";
}

const CRACK_SCENARIOS = [
  { label: "Online, rate-limited", rate: 100 / 3600 },
  { label: "Online, no rate limit", rate: 10 },
  { label: "Offline, slow hash (bcrypt)", rate: 1e4 },
  { label: "Offline, fast hash (GPU array)", rate: 1e10 },
];

function analyzePassword(pw) {
  if (!pw) {
    return {
      length: 0, bitsRaw: 0, bitsAdjusted: 0, poolSize: 0, flags: {},
      warnings: [], rating: ratingForBits(0), crackTimes: CRACK_SCENARIOS.map(s => ({ ...s, time: "n/a" })),
    };
  }

  const { size, flags } = poolSizeForPassword(pw);
  const bitsRaw = pw.length * log2(size);
  const { penalty, warnings } = detectPatterns(pw);
  const bitsAdjusted = Math.max(0, bitsRaw - penalty);
  const rating = ratingForBits(bitsAdjusted);

  const guesses = Math.pow(2, bitsAdjusted) / 2; // average-case guesses
  const crackTimes = CRACK_SCENARIOS.map((s) => ({
    label: s.label,
    time: formatDuration(guesses / s.rate),
  }));

  return {
    length: pw.length,
    bitsRaw,
    bitsAdjusted,
    poolSize: size,
    flags,
    warnings,
    rating,
    crackTimes,
  };
}

// ---- DOM wiring (browser only) ----
if (typeof document !== "undefined") {
  const input = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-visibility");
  const bitsValue = document.getElementById("bits-value");
  const ratingLabel = document.getElementById("rating-label");
  const meterSegments = document.querySelectorAll(".meter-segment");
  const compositionList = document.getElementById("composition-list");
  const warningsList = document.getElementById("warnings-list");
  const warningsSection = document.getElementById("warnings-section");
  const crackTableBody = document.getElementById("crack-table-body");

  const TIER_COLORS = {
    1: "var(--accent-red)",
    2: "var(--accent-red)",
    3: "var(--accent-amber)",
    4: "var(--accent-green)",
    5: "var(--accent-green)",
  };

  function renderComposition(flags, length) {
    const items = [
      ["Lowercase letters", flags.lower],
      ["Uppercase letters", flags.upper],
      ["Digits", flags.digit],
      ["Symbols", flags.symbol],
      ["Extended / unicode characters", flags.extended],
    ];
    compositionList.innerHTML = "";
    items.forEach(([label, present]) => {
      const li = document.createElement("li");
      li.className = present ? "present" : "absent";
      li.textContent = label;
      compositionList.appendChild(li);
    });
    const lengthLi = document.createElement("li");
    lengthLi.className = length >= 12 ? "present" : "absent";
    lengthLi.textContent = `Length ${length} (${length >= 12 ? "≥ 12" : "< 12"})`;
    compositionList.appendChild(lengthLi);
  }

  function render(pw) {
    const result = analyzePassword(pw);
    bitsValue.textContent = pw ? result.bitsAdjusted.toFixed(1) : "0.0";
    ratingLabel.textContent = pw ? result.rating.label : "No password entered";
    ratingLabel.style.color = pw ? TIER_COLORS[result.rating.tier] : "var(--text-dim)";

    meterSegments.forEach((seg, i) => {
      const active = pw && i < result.rating.tier * 2;
      seg.style.background = active ? TIER_COLORS[result.rating.tier] : "var(--panel-border)";
    });

    renderComposition(result.flags, result.length);

    warningsList.innerHTML = "";
    if (result.warnings.length && pw) {
      warningsSection.style.display = "block";
      result.warnings.forEach((w) => {
        const li = document.createElement("li");
        li.textContent = w;
        warningsList.appendChild(li);
      });
    } else {
      warningsSection.style.display = "none";
    }

    crackTableBody.innerHTML = "";
    result.crackTimes.forEach((row) => {
      const tr = document.createElement("tr");
      const tdLabel = document.createElement("td");
      tdLabel.textContent = row.label;
      const tdTime = document.createElement("td");
      tdTime.textContent = pw ? row.time : "—";
      tdTime.className = "mono";
      tr.appendChild(tdLabel);
      tr.appendChild(tdTime);
      crackTableBody.appendChild(tr);
    });
  }

  input.addEventListener("input", (e) => render(e.target.value));
  toggleBtn.addEventListener("click", () => {
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleBtn.setAttribute("aria-pressed", String(isPassword));
    toggleBtn.textContent = isPassword ? "Hide" : "Show";
  });

  render("");
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { analyzePassword, formatDuration, poolSizeForPassword, detectPatterns };
}
