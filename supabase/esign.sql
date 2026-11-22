-- E-signature stamped copies (2026-11-22). Safe to re-run.
-- Run once in Supabase → SQL Editor before deploying the server update.
alter table public.portal_signatures add column if not exists signed_path   text;  -- portal-docs/signed/<staff>/<doc>-<ts>.pdf
alter table public.portal_signatures add column if not exists doc_sha256    text;  -- SHA-256 of the original that was signed
alter table public.portal_signatures add column if not exists signed_sha256 text;  -- SHA-256 of the stamped copy
