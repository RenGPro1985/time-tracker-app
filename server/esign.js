// ============================================================
// SMB VS PORTAL — e-signature stamping (added 2026-11-22)
// Before this, "Submit Signature" only saved a row in portal_signatures;
// the PDF itself was never signed. Now every signature produces a real,
// separate signed copy in Storage:
//   1. the typed name is drawn in script on the contractor signature line
//      (found by searching the PDF text for the CONTRACTOR label), with
//      the printed name and date filled in next to "Name:" / "Date:";
//   2. a "Certificate of Electronic Signature" page is appended with the
//      audit trail (who, when in PHT, IP, device, SHA-256 of the original
//      and the signature ID) — this is what proves the signature under
//      R.A. 8792 / the Rules on Electronic Evidence.
// The original upload is never modified. Non-PDF docs get no stamped copy.
// ============================================================
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT_TTF = readFileSync(join(HERE, 'fonts', 'GreatVibes-Regular.ttf'));
const INK = rgb(0.08, 0.14, 0.36);
const GREY = rgb(0.35, 0.35, 0.35);
const NAVY = rgb(0.12, 0.22, 0.39);

export const sha256 = buf => createHash('sha256').update(buf).digest('hex');

export function phtStamp(iso) {
  const d = new Date(iso || Date.now());
  const date = d.toLocaleDateString('en-US', { timeZone: 'Asia/Manila', year: 'numeric', month: 'long', day: 'numeric' });
  const time = d.toLocaleTimeString('en-US', { timeZone: 'Asia/Manila', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return { date, full: `${date}, ${time} PHT` };
}

// Text items per page with PDF-space coordinates (origin bottom-left).
async function textItems(bytes) {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
  const doc = await pdfjs.getDocument({ data: new Uint8Array(bytes), isEvalSupported: false, useSystemFonts: false, verbosity: 0 }).promise;
  const pages = [];
  for (let p = 1; p <= doc.numPages; p++) {
    const pg = await doc.getPage(p);
    const tc = await pg.getTextContent();
    pages.push(tc.items.filter(it => it.str && it.str.trim()).map(it => ({
      str: it.str, x: it.transform[4], y: it.transform[5], w: it.width, h: Math.abs(it.transform[3]) || 10
    })));
  }
  await doc.destroy();
  return pages;
}

// Where the contractor signs: the LAST item on the document that labels the
// contractor's signature ("CONTRACTOR — Signature over Printed Name",
// "— CONTRACTOR", "Contractor Signature / Date", ...).
function findContractorSlot(pages) {
  const isLabel = s => /contractor/i.test(s) && (/signature/i.test(s) || /—\s*contractor\b/i.test(s) || /^\s*contractor\s*$/i.test(s));
  for (let p = pages.length - 1; p >= 0; p--) {
    const items = pages[p];
    for (let i = items.length - 1; i >= 0; i--) {
      if (!isLabel(items[i].str)) continue;
      const lab = items[i];
      // "Name:" / "Date:" blanks in the same column just below the label
      const near = re => items.find(it => re.test(it.str) && Math.abs(it.x - lab.x) < 40 && it.y < lab.y && lab.y - it.y < 70);
      return { pageIndex: p, label: lab, name: near(/^\s*name\s*:/i), date: near(/^\s*date\s*:/i) };
    }
  }
  return null;
}

function fitSize(font, text, maxW, start) {
  let s = start;
  while (s > 10 && font.widthOfTextAtSize(text, s) > maxW) s -= 1;
  return s;
}

/**
 * Returns { bytes, docHash, signedHash, placedOnLine } for a signed copy.
 * sig: { signature_name, signed_at, ip, user_agent, id }, signer: { full_name, email }, doc: { title }
 */
export async function stampSignedPdf(originalBytes, { sig, signer, doc }) {
  const docHash = sha256(originalBytes);
  const pdf = await PDFDocument.load(originalBytes, { ignoreEncryption: false });
  pdf.registerFontkit(fontkit);
  const script = await pdf.embedFont(SCRIPT_TTF, { subset: true });
  const serif = await pdf.embedFont(StandardFonts.TimesRoman);
  const serifB = await pdf.embedFont(StandardFonts.TimesRomanBold);
  const when = phtStamp(sig.signed_at);
  const typed = String(sig.signature_name || '').trim();

  // 1) stamp on the signature line
  let placedOnLine = false;
  try {
    const slot = findContractorSlot(await textItems(originalBytes));
    if (slot) {
      const page = pdf.getPage(slot.pageIndex);
      const { label } = slot;
      const size = fitSize(script, typed, 210, 22);
      page.drawText(typed, { x: label.x + 4, y: label.y + label.h + 6, size, font: script, color: INK });
      // write on top of the blank ("Name: ________") — or right after the label if it has no blank
      const put = (anchor, text) => {
        if (!anchor) return;
        const u = anchor.str.indexOf('_');
        const x = u > 0 ? anchor.x + anchor.w * (u / anchor.str.length) + 4 : anchor.x + anchor.w + 4;
        page.drawText(text, { x, y: anchor.y + 1.5, size: 10, font: serif, color: INK });
      };
      put(slot.name, typed);
      put(slot.date, when.date);
      page.drawText(`Electronically signed ${when.full} · ID ${String(sig.id || '').slice(0, 8)} · see last page`, {
        x: label.x, y: (slot.date || slot.name || label).y - 11, size: 6.5, font: serif, color: GREY
      });
      placedOnLine = true;
    }
  } catch (e) { console.error('esign: signature-line stamp skipped:', e.message); }

  // 2) certificate page (always)
  const first = pdf.getPage(0);
  const { width, height } = first.getSize();
  const cert = pdf.addPage([width, height]);
  let y = height - 72;
  const L = 60, W = width - 120;
  cert.drawRectangle({ x: L, y: y - 6, width: W, height: 24, color: NAVY });
  cert.drawText('CERTIFICATE OF ELECTRONIC SIGNATURE', { x: L + 8, y: y + 1, size: 13, font: serifB, color: rgb(1, 1, 1) });
  y -= 40;
  const line = (k, v) => {
    cert.drawText(k, { x: L, y, size: 10.5, font: serifB, color: GREY });
    const words = String(v ?? '—').split(/(\s+)/); let row = '', yy = y;
    for (const w of words) {
      if (serif.widthOfTextAtSize(row + w, 10.5) > W - 150) { cert.drawText(row, { x: L + 150, y: yy, size: 10.5, font: serif }); row = w.trimStart(); yy -= 14; }
      else row += w;
    }
    cert.drawText(row, { x: L + 150, y: yy, size: 10.5, font: serif });
    y = yy - 20;
  };
  line('Document', doc.title);
  line('Signer', `${signer.full_name || typed}${signer.email ? ' <' + signer.email + '>' : ''}`);
  line('Typed signature', typed);
  line('Signed at', when.full);
  line('IP address', sig.ip || '—');
  line('Device', sig.user_agent || '—');
  line('Signature ID', sig.id || '—');
  line('Original SHA-256', docHash);
  line('Method', 'Signer logged in to the SMB VS Portal with their own account, opened the document, typed their full name and confirmed "I acknowledge and agree".');
  y -= 6;
  cert.drawText(typed, { x: L, y: y - 30, size: fitSize(script, typed, 260, 30), font: script, color: INK });
  cert.drawLine({ start: { x: L, y: y - 38 }, end: { x: L + 270, y: y - 38 }, thickness: 0.7, color: GREY });
  cert.drawText('Electronic signature of the Contractor', { x: L, y: y - 50, size: 9, font: serif, color: GREY });
  y -= 90;
  const note = 'This electronic signature has the same legal effect as a handwritten signature under the Electronic Commerce Act of 2000 (R.A. 8792). The original document is identified by the SHA-256 value above; any change to it produces a different value.';
  const nw = note.split(' '); let r = '';
  for (const w of nw) { if (serif.widthOfTextAtSize(r + w + ' ', 9) > W) { cert.drawText(r, { x: L, y, size: 9, font: serif, color: GREY }); y -= 12; r = ''; } r += w + ' '; }
  cert.drawText(r, { x: L, y, size: 9, font: serif, color: GREY });

  pdf.setTitle(`${doc.title} — signed by ${typed}`);
  pdf.setModificationDate(new Date(sig.signed_at || Date.now()));
  const bytes = Buffer.from(await pdf.save());
  return { bytes, docHash, signedHash: sha256(bytes), placedOnLine };
}
