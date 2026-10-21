-- HAZEL : tables de la connexion bancaire, fermées au public (seule la fonction « banque » y accède)
create table if not exists public.bank_state (
  id int primary key default 1 check (id = 1),
  session_id text, accounts jsonb, aspsp jsonb, valid_until timestamptz,
  last_sync timestamptz, balances jsonb, pending_state text
);
create table if not exists public.bank_tx (
  id text primary key, account text, booking_date date, amount numeric, sens text, label text,
  created_at timestamptz not null default now()
);
alter table public.bank_state enable row level security;
alter table public.bank_tx enable row level security;
revoke all on public.bank_state from anon, authenticated;
revoke all on public.bank_tx from anon, authenticated;
insert into public.bank_state (id) values (1) on conflict (id) do nothing;

-- Synchro automatique toutes les 6 heures (la fonction ignore l'appel si la dernière synchro a moins de 5 h)
create extension if not exists pg_cron;
create extension if not exists pg_net;
select cron.unschedule('hazel-banque') where exists (select 1 from cron.job where jobname = 'hazel-banque');
select cron.schedule('hazel-banque', '7 */6 * * *', $$
  select net.http_post(
    url := 'https://ubkcaufyyrqwwjpptrso.supabase.co/functions/v1/banque',
    headers := '{"Content-Type":"application/json"}'::jsonb,
    body := '{"action":"cron"}'::jsonb
  );
$$);
select jobname, schedule from cron.job;

-- Opérations en attente (à venir), remplacées à chaque synchro
alter table public.bank_state add column if not exists pending jsonb;
