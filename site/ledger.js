// Hero illustration: records seal one by one; every so often one is tampered with and the verifier names it.
(() => {
  const rows = document.getElementById("rows");
  const verdict = document.getElementById("verdict");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const VISIBLE = 8;
  let seq = 0;
  let sinceTamper = 0;

  const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");
  const kind = () => {
    const r = Math.random();
    if (r < 0.14) return ["flag", "sensitive_terms"];
    if (r < 0.2) return ["block", "residency"];
    return ["allow", "—"];
  };

  function seal() {
    seq += 1;
    const [decision, hits] = kind();
    const li = document.createElement("li");
    li.className = decision;
    li.dataset.seq = seq;
    for (const [cls, text] of [["seq", seq], ["dec", decision], ["hits", hits], ["hash", hex(6)]]) {
      const s = document.createElement("span");
      s.className = cls;
      s.textContent = text;
      li.appendChild(s);
    }
    rows.prepend(li);
    while (rows.children.length > VISIBLE) rows.lastChild.remove();
    verdict.className = "verdict";
    verdict.textContent = `PASS records=${seq}`;
  }

  function tamper() {
    const items = [...rows.children];
    const target = items[Math.min(4, items.length - 1)];
    const n = Number(target.dataset.seq);
    target.classList.add("broken");
    items.filter((li) => Number(li.dataset.seq) > n).forEach((li) => li.classList.add("after"));
    verdict.className = "verdict fail";
    verdict.textContent = Math.random() < 0.5 ? `FAIL seq=${n} content altered` : `FAIL seq=${n} signature invalid`;
    return new Promise((r) => setTimeout(() => {
      items.forEach((li) => li.classList.remove("broken", "after"));
      r();
    }, 3200));
  }

  for (let i = 0; i < VISIBLE; i++) seal();
  if (reduced) return;

  async function loop() {
    await new Promise((r) => setTimeout(r, 1300));
    sinceTamper += 1;
    if (sinceTamper >= 7) {
      sinceTamper = 0;
      await tamper();
    }
    seal();
    loop();
  }
  loop();
})();
