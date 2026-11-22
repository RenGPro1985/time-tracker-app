// ============================================================
// SMB VS PORTAL — Statement of Work generator (added 2026-11-22)
// Builds one contractor's Statement of Work / Client Assignment Sheet as a PDF.
// The fee rows are computed in the browser by ContractFee._compute (the exact
// numbers on the staff member's My Contract Fee card) and passed in, so the SOW
// and the portal can never disagree. Rendy is pre-signed as Account Coordinator;
// the contractor signs through the normal portal e-sign flow (esign.js stamps
// the "CONTRACTOR — Signature over Printed Name" line).
// Standard PDF fonts can't draw the peso sign or ballot boxes, so amounts read
// "PHP 22,000.00" and checkboxes read [X] / [ ].
// ============================================================
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SIG_RENDY = readFileSync(join(HERE, 'assets', 'sig_rendy.png'));
const NAVY = rgb(0.122, 0.22, 0.392), INK = rgb(0.1, 0.1, 0.1), GREY = rgb(0.38, 0.38, 0.38);
const SHADE = rgb(0.95, 0.95, 0.95), SEC = rgb(0.91, 0.925, 0.953), GOLD = rgb(1, 0.965, 0.867), LINE = rgb(0.55, 0.55, 0.55);
const W = 612, H = 792, M = 54, CW = W - 2 * M;

export const php = v => 'PHP ' + Number(v || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const box = on => (on ? '[X]' : '[ ]');
// keep text inside WinAnsi (standard fonts): swap the few characters that would throw
const clean = s => String(s ?? '').replace(/₱\s?/g, 'PHP ').replace(/[☐]/g, '[ ]').replace(/[☒☑]/g, '[X]').replace(/[^\x00-\xFF–—‘’“”•…×€]/g, '');

export async function buildSowPdf(d) {
  const pdf = await PDFDocument.create();
  const f = {
    r: await pdf.embedFont(StandardFonts.TimesRoman), b: await pdf.embedFont(StandardFonts.TimesRomanBold),
    i: await pdf.embedFont(StandardFonts.TimesRomanItalic)
  };
  const sig = await pdf.embedPng(SIG_RENDY);
  let page, y;
  const newPage = () => { page = pdf.addPage([W, H]); y = H - M; };
  const need = h => { if (y - h < M - 8) newPage(); };
  newPage();

  // rich text: "**bold** normal" → wrapped lines of runs
  function runs(text, base = 'r') {
    const out = []; String(clean(text)).split(/(\*\*[^*]+\*\*)/).forEach(p => {
      if (!p) return; if (p.startsWith('**')) out.push({ t: p.slice(2, -2), f: 'b' }); else out.push({ t: p, f: base });
    }); return out;
  }
  function wrap(text, size, width, base) {
    const words = []; runs(text, base).forEach(r => r.t.split(/(\s+)/).forEach(w => w && words.push({ t: w, f: r.f })));
    const lines = []; let cur = [], cw = 0;
    for (const w of words) {
      const ww = f[w.f].widthOfTextAtSize(w.t, size);
      if (cw + ww > width && cur.length && w.t.trim()) { lines.push(cur); cur = []; cw = 0; if (!w.t.trim()) continue; }
      if (!cur.length && !w.t.trim()) continue;
      cur.push({ ...w, w: ww }); cw += ww;
    }
    if (cur.length) lines.push(cur);
    return lines;
  }
  function drawLines(lines, x, size, color = INK, lead = 1.28) {
    for (const ln of lines) {
      need(size * lead);
      let xx = x; for (const w of ln) { page.drawText(w.t, { x: xx, y: y - size, size, font: f[w.f], color }); xx += w.w; }
      y -= size * lead;
    }
  }
  const para = (t, o = {}) => { const s = o.size || 10.5; drawLines(wrap(t, s, CW - (o.indent || 0), o.italic ? 'i' : 'r'), M + (o.indent || 0), s, o.color || INK); y -= o.after ?? 5; };
  const bullet = t => { const s = 10.5, lines = wrap(t, s, CW - 22); need(s * 1.3); page.drawText('•', { x: M + 8, y: y - s, size: s, font: f.r }); drawLines(lines, M + 22, s); y -= 3; };
  function heading(t) {
    need(40); y -= 8;
    page.drawRectangle({ x: M, y: y - 16, width: CW, height: 16, color: NAVY });
    page.drawText(clean(t), { x: M + 5, y: y - 12, size: 11.5, font: f.b, color: rgb(1, 1, 1) });
    y -= 24;
  }
  // bordered grid: rows of 1 or 2 cells
  function infoGrid(rows) {
    const s = 10, half = CW / 2;
    for (const r of rows) {
      const cells = r.length === 2 ? [[r[0], half], [r[1], half]] : [[r[0], CW]];
      const wrapped = cells.map(([t, w]) => wrap(t, s, w - 12));
      const h = Math.max(...wrapped.map(l => l.length)) * s * 1.28 + 10;
      need(h);
      let x = M;
      cells.forEach(([, w], k) => {
        page.drawRectangle({ x, y: y - h, width: w, height: h, color: SHADE, borderColor: LINE, borderWidth: 0.6 });
        const save = y; y -= 5; drawLines(wrapped[k], x + 6, s); y = save; x += w;
      });
      y -= h;
    }
    y -= 6;
  }
  function feeTable(rows) {
    const s = 10, c = [CW * 0.55, CW * 0.18, CW * 0.27];
    const row = (cells, o = {}) => {
      const cw0 = o.span ? CW - 12 : c[0] - 12;
      const wr = wrap(cells[0], s, cw0); const h = wr.length * s * 1.28 + 8;
      need(h);
      page.drawRectangle({ x: M, y: y - h, width: CW, height: h, color: o.fill || rgb(1, 1, 1), borderColor: LINE, borderWidth: 0.4 });
      const tc = o.head ? rgb(1, 1, 1) : INK, ff = o.head || o.bold ? f.b : f.r;
      const save = y; y -= 4; drawLines(wrap(cells[0], s, cw0, o.head || o.bold ? 'b' : 'r'), M + 6, s, tc); y = save;
      if (cells[1]) page.drawText(clean(cells[1]), { x: M + c[0] + 6, y: y - 4 - s, size: s, font: ff, color: tc });
      if (cells[2]) { const t = clean(cells[2]); const tw = ff.widthOfTextAtSize(t, s); page.drawText(t, { x: M + CW - 6 - tw, y: y - 4 - s, size: s, font: ff, color: tc }); }
      y -= h;
    };
    row(['Item', 'Paid on', 'Amount'], { head: true, fill: NAVY });
    for (const r of rows) {
      if (r.section) { row([`**${r.section}**`, '', ''], { fill: SEC, span: true }); continue; }
      row([r.label + (r.sub ? `  (${r.sub})` : ''), r.paid || '', r.amount], { fill: r.total ? GOLD : undefined, bold: r.total });
    }
    y -= 6;
  }

  // ---------- content ----------
  page.drawText('SMB VIRTUAL STAFFING, LLC', { x: M, y: y - 17, size: 17, font: f.b, color: NAVY }); y -= 22;
  page.drawText('5555 Glenridge Connector, Suite 200, Atlanta, Georgia 30342, United States', { x: M, y: y - 8.5, size: 8.5, font: f.r, color: GREY }); y -= 16;
  heading('STATEMENT OF WORK / CLIENT ASSIGNMENT SHEET');
  para(`${d.sow_no} · issued from the SMB VS Portal on ${d.issued_on} · supersedes any earlier Statement of Work for this contractor`, { italic: true, size: 10, after: 6 });

  heading('1. PARTIES & ASSIGNMENT');
  infoGrid([
    [`**Contractor Name:** ${d.contractor}`, `**Effective Date:** ${d.effective_date}`],
    [`**Client Account:** ${d.client || '— unassigned —'}`, '**Account Coordinator:** Rendy Eligio (Project Manager)'],
    [`**Governing Agreement:** Independent Contractor Service Agreement${d.agreement_signed ? `, signed in the SMB VS Portal on ${d.agreement_signed}` : ' dated ______________'}`]
  ]);

  heading('2. SERVICE DESCRIPTION');
  para(`**Role Summary:** ${d.role_summary || 'Office Support staff for assigned client, as identified by the Project Manager and client.'}`);
  para('**Key Deliverables / Responsibilities:**', { after: 3 });
  bullet('**Inbox & Calendar Management:** Monitor and respond to client emails/messages within agreed timeframes; schedule, confirm, and coordinate appointments or meetings as directed.');
  bullet('**Data Entry & Documentation:** Accurately input, update, and maintain client records, spreadsheets, or CRM/system entries; prepare basic reports or summaries as requested.');
  bullet('**Client & Team Communication Support:** Relay updates between the client and the account team, follow up on pending items, and escalate urgent matters to the Account Coordinator promptly.');

  heading('3. COVERAGE WINDOW');
  infoGrid([
    [`**Coverage Days:** ${d.coverage_days || 'Monday – Friday'}`, `**Coverage Hours (EST):** ${d.coverage_est || '______________'}`],
    ['**Suggested Break Windows:** Refer to the Project Manager or Team Lead instructions', `**Time Zone Note:** ${d.coverage_pht ? d.coverage_pht + ' PHT' : '______________'}`]
  ]);
  para('Per Section 2 of the Service Guidelines, this is a coverage commitment for client continuity, not an employer-set attendance schedule.', { italic: true, size: 9.5 });

  heading('4. COMPENSATION');
  para('The amounts below are the same figures shown on **My Contract Fee** in the SMB VS Portal on the issue date. They assume a full standard month (22 days x 8 contracted hours, no absences or undertime).', { after: 6 });
  const fee = d.fee || {};
  feeTable([
    { section: 'EVERY MONTH' },
    ...(fee.lines || []).map(l => ({ label: l.label, sub: l.sub, paid: l.paid, amount: php(l.amount) })),
    { total: true, label: 'Monthly Contract Fee', amount: php(fee.total) },
    { label: '15th payout', amount: php(fee.mid) },
    { label: 'End-of-month payout', amount: php(fee.eom) },
    ...((fee.also || []).length || (fee.notIn || []).length ? [{ section: 'ALSO EARNED WHEN IT APPLIES (NOT IN THE MONTHLY TOTAL)' }] : []),
    ...(fee.also || []).map(l => ({ label: l.label, sub: l.sub, amount: l.amount == null ? 'varies' : php(l.amount) })),
    ...(fee.notIn || []).map(l => ({ label: l.label, sub: l.sub, paid: 'not yet', amount: php(l.amount) }))
  ]);
  para(`**Reference rate:** ${php(fee.hourly)} per contracted hour (${php(fee.monthly)} ÷ 22 ÷ 8). Invoice cycle: 15th & last day of the month.`, { size: 10 });
  para('Per Section IV of the Service Agreement, the Total Contract Fee is a single, all-inclusive amount and does not itemize or represent any statutory benefit. Allowances, bonuses and incentives are discretionary, contractual payments and do not constitute statutory employee benefits. Overtime, reimbursements, fee advances and adjustments are not shown.', { italic: true, size: 9.5 });
  para('Rate is subject to periodic review (historically annual). Any adjustment is documented by issuing a new, dated Statement of Work superseding this one — it is a matter of practice, not a contractual guarantee of increase.', { italic: true, size: 9.5 });

  heading('5. TOOLS, ACCESS & EQUIPMENT');
  para('**Systems/Tools Required:** As prescribed by the client.');
  para('**Company-Issued Equipment (if any):** Basic workstation setup — PC, headset, chair, and related equipment.');
  const ws = d.work_site || '';
  para(`**Work Site:** ${box(ws === 'remote')} Fully Remote   ${box(ws === 'site')} Shared SMB VS Site   ${box(ws === 'hybrid')} Hybrid`);

  heading('6. REPORTING & REVIEW');
  para('**Reports To (Account Coordinator):** Rendy Eligio, Project Manager');
  const cad = d.cadence || '';
  para(`**Check-in Cadence:** ${box(cad === 'daily')} Daily   ${box(cad === 'weekly')} Weekly   ${box(cad && cad !== 'daily' && cad !== 'weekly')} Other${cad && cad !== 'daily' && cad !== 'weekly' ? ': ' + cad : ''}`);
  para('**Performance Review Point:** Annual Performance review in the SMB VS Portal');

  need(230); // keep the acknowledgment and the signatures on one page
  heading('7. ACKNOWLEDGMENT');
  para("This Statement of Work is issued under, and incorporated by reference into, the Contractor's Independent Contractor Service Agreement with SMB Virtual Staffing, LLC. It may be updated or replaced by mutual written agreement (including email confirmation) without requiring a new signature on the master Agreement. Electronic signatures on this Statement of Work are valid under R.A. 8792.", { after: 10 });

  // signature block (needs ~120pt on one page)
  need(130);
  const colW = CW / 2 - 12, lx = M, rx = M + CW / 2 + 12, top = y;
  const sw = 150, sh = sw * sig.height / sig.width;
  page.drawImage(sig, { x: rx, y: top - 48, width: sw, height: Math.min(sh, 44) });
  [lx, rx].forEach(x => page.drawLine({ start: { x, y: top - 50 }, end: { x: x + colW, y: top - 50 }, thickness: 0.7, color: INK }));
  const t = (s, x, yy, font = f.r, size = 9.5, color = INK) => page.drawText(clean(s), { x, y: yy, size, font, color });
  t('CONTRACTOR — Signature over Printed Name', lx, top - 61, f.r, 8.5);
  t('Name: ________________________________', lx, top - 76, f.r, 10);
  t('Date: ____________________', lx, top - 91, f.r, 10);
  t('ACCOUNT COORDINATOR', rx, top - 61, f.r, 8.5);
  t('Rendy Eligio', rx, top - 75, f.b, 10.5);
  t('Project Manager, SMB Virtual Staffing, LLC', rx, top - 88, f.r, 9.5);
  t(`Date: ${d.issued_on}`, rx, top - 101, f.r, 9.5);
  t(`Electronically signed on ${d.issued_on} (PHT) under R.A. 8792`, rx, top - 113, f.i, 7.5, GREY);
  y = top - 120;

  // footers
  const pages = pdf.getPages();
  pages.forEach((p, k) => {
    const s = clean(`${d.sow_no} · ${d.contractor} · ${d.client || ''}  ·  Page ${k + 1} of ${pages.length}  ·  Contractor Initials: ______`);
    p.drawText(s, { x: (W - f.r.widthOfTextAtSize(s, 7.5)) / 2, y: 26, size: 7.5, font: f.r, color: GREY });
  });
  pdf.setTitle(clean(`Statement of Work ${d.sow_no} — ${d.contractor}`));
  pdf.setAuthor('SMB Virtual Staffing, LLC');
  return Buffer.from(await pdf.save());
}
