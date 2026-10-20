-- W.A.L.T.E.R : base Supabase (même projet que H.A.Z.E.L, tables à part)
-- À coller une seule fois dans Supabase > SQL Editor, puis Run.
-- Avant de lancer : remplace 1234 (tout en bas) par le code que tu veux pour Walter.

create extension if not exists pgcrypto with schema extensions;

-- Une seule ligne de données : tout l'état de l'appli en JSON
create table if not exists public.walter_data(
  id int primary key default 1 check (id = 1),
  d jsonb not null default '{}'::jsonb,
  maj timestamptz not null default now()
);

-- Le code d'accès n'est stocké que sous forme d'empreinte bcrypt
create table if not exists public.walter_acces(
  id int primary key default 1 check (id = 1),
  code_hash text not null,
  essais int not null default 0,
  bloque_jusqu timestamptz
);

-- Sécurité : RLS activée sans aucune règle = personne ne lit ni n'écrit ces tables directement,
-- même avec la clé publique visible dans la page. Seules les fonctions ci-dessous y accèdent.
alter table public.walter_data enable row level security;
alter table public.walter_acces enable row level security;
revoke all on table public.walter_data from anon, authenticated;
revoke all on table public.walter_acces from anon, authenticated;

-- Vérifie le code : 5 erreurs = blocage 15 minutes
create or replace function public.walter_check(c text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare a public.walter_acces; n int;
begin
  select * into a from public.walter_acces where id = 1 for update;
  if not found then return 'code'; end if;
  if a.bloque_jusqu is not null and a.bloque_jusqu > now() then return 'bloque'; end if;
  if a.code_hash = crypt(coalesce(c, ''), a.code_hash) then
    if a.essais > 0 or a.bloque_jusqu is not null then
      update public.walter_acces set essais = 0, bloque_jusqu = null where id = 1;
    end if;
    return 'ok';
  end if;
  n := a.essais + 1;
  if n >= 5 then
    update public.walter_acces set essais = 0, bloque_jusqu = now() + interval '15 minutes' where id = 1;
    return 'bloque';
  end if;
  update public.walter_acces set essais = n where id = 1;
  return 'code';
end $$;

create or replace function public.get_walter(c text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public.walter_check(c);
  if r <> 'ok' then return jsonb_build_object('_erreur', r); end if;
  return coalesce((select d from public.walter_data where id = 1), '{}'::jsonb);
end $$;

create or replace function public.save_walter(c text, d jsonb) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public.walter_check(c);
  if r <> 'ok' then return r; end if;
  insert into public.walter_data(id, d, maj) values (1, d, now())
    on conflict (id) do update set d = excluded.d, maj = now();
  return 'ok';
end $$;

revoke execute on function public.walter_check(text) from public, anon, authenticated;
revoke execute on function public.get_walter(text) from public;
revoke execute on function public.save_walter(text, jsonb) from public;
grant execute on function public.get_walter(text) to anon, authenticated;
grant execute on function public.save_walter(text, jsonb) to anon, authenticated;

-- Ton code Walter (remplace 1234). Pour le changer plus tard : relance seulement ces 3 lignes.
insert into public.walter_acces(id, code_hash) values (1, crypt('1234', gen_salt('bf')))
  on conflict (id) do update set code_hash = excluded.code_hash, essais = 0, bloque_jusqu = null;
