// HAZEL : fonction Supabase « banque »
// Fait le lien entre l'app et Enable Banking (accès aux comptes, DSP2).
// La clé privée Enable Banking vit uniquement dans le secret EB_PRIVATE_KEY de Supabase.
// Chaque appel de l'app doit fournir le code d'accès HAZEL (vérifié par get_budget, avec blocage après 5 erreurs).
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
import { importPKCS8, SignJWT } from "npm:jose@5.9.6";
import { createPrivateKey } from "node:crypto";

const APP_ID = "55f19905-7c16-45b1-b61e-63c1f16c9a1b"; // identifiant public de l'application Enable Banking
const API = "https://api.enablebanking.com";
const SITE = "https://imhada.github.io/mon-budget/";
const cors = {
  "Access-Control-Allow-Origin": "https://imhada.github.io",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});

// --- jeton signé pour Enable Banking (RS256, 1 h)
let cle: CryptoKey | null = null;
async function jeton() {
  if (!cle) {
    const brut = (Deno.env.get("EB_PRIVATE_KEY") || "").replace(/\\n/g, "\n").trim();
    if (!brut) throw new Error("Clé privée absente : ajoute le secret EB_PRIVATE_KEY dans Supabase.");
    const pkcs8 = createPrivateKey(brut).export({ type: "pkcs8", format: "pem" }).toString();
    cle = await importPKCS8(pkcs8, "RS256");
  }
  const t = Math.floor(Date.now() / 1000);
  return await new SignJWT({ iss: "enablebanking.com", aud: "api.enablebanking.com", iat: t, exp: t + 3600 })
    .setProtectedHeader({ typ: "JWT", alg: "RS256", kid: APP_ID })
    .sign(cle);
}

type Psu = { ip: string; ua: string } | null;
async function eb(chemin: string, opt: { method?: string; body?: unknown } = {}, psu: Psu = null) {
  const h: Record<string, string> = { Authorization: `Bearer ${await jeton()}`, "Content-Type": "application/json" };
  if (psu?.ip) h["Psu-Ip-Address"] = psu.ip; // utilisateur présent : ne compte pas dans le quota d'accès en arrière-plan
  if (psu?.ua) h["Psu-User-Agent"] = psu.ua;
  const r = await fetch(API + chemin, {
    method: opt.method || "GET",
    headers: h,
    body: opt.body ? JSON.stringify(opt.body) : undefined,
  });
  const txt = await r.text();
  if (!r.ok) throw new Error(`Enable Banking ${r.status} : ${txt.slice(0, 300)}`);
  return txt ? JSON.parse(txt) : {};
}

async function empreinte(s: string) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].slice(0, 12).map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function etat() {
  const { data, error } = await db.from("bank_state").select("*").eq("id", 1).single();
  if (error) throw error;
  return data;
}

// --- récupère les opérations et soldes, puis renvoie l'état pour l'app
async function synchro(psu: Psu, cron: boolean) {
  const st = await etat();
  if (!st?.session_id) return { connecte: false };
  if (st.valid_until && new Date(st.valid_until) < new Date()) return { connecte: false, expire: true };

  const age = st.last_sync ? Date.now() - new Date(st.last_sync).getTime() : Infinity;
  const aJour = age < (cron ? 5 * 3600e3 : 10 * 60e3); // limite les accès (la banque plafonne les accès en arrière-plan)
  let erreur: string | null = null;
  if (!aJour) {
    const debut = st.last_sync
      ? new Date(new Date(st.last_sync).getTime() - 7 * 86400e3)
      : new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), 1));
    const soldes: Record<string, unknown> = {};
    try {
      for (const cpt of st.accounts || []) {
        const lignes: any[] = [];
        let suite: string | null = null;
        do {
          const q = new URLSearchParams({ date_from: debut.toISOString().slice(0, 10) });
          if (suite) q.set("continuation_key", suite);
          const r = await eb(`/accounts/${cpt.uid}/transactions?${q}`, {}, psu);
          lignes.push(...(r.transactions || []));
          suite = r.continuation_key || null;
        } while (suite);
        const recs = [];
        for (const t of lignes.filter((t) => !t.status || t.status === "BOOK")) {
          const brut = parseFloat(t.transaction_amount?.amount ?? "0");
          const sens = t.credit_debit_indicator ? (t.credit_debit_indicator === "CRDT" ? "in" : "out") : brut < 0 ? "out" : "in";
          const libelle = ((t.remittance_information || []).join(" ").trim() || t.creditor?.name || t.debtor?.name || "Opération").replace(/\s+/g, " ");
          const date = t.booking_date || t.value_date || t.transaction_date;
          const base = t.entry_reference || t.transaction_id || `${date}|${brut}|${sens}|${libelle}`;
          recs.push({ id: `${String(cpt.uid).slice(0, 8)}:${await empreinte(base)}`, account: cpt.uid, booking_date: date, amount: Math.abs(brut), sens, label: libelle.slice(0, 140) });
        }
        if (recs.length) {
          const { error } = await db.from("bank_tx").upsert(recs, { onConflict: "id", ignoreDuplicates: true });
          if (error) throw error;
        }
        try {
          const b = await eb(`/accounts/${cpt.uid}/balances`, {}, psu);
          const liste = b.balances || [];
          const s = liste.find((x: any) => ["CLBD", "ITAV", "XPCD", "ITBD", "CLAV"].includes(x.balance_type)) || liste[0];
          if (s) soldes[cpt.uid] = { nom: cpt.nom, montant: parseFloat(s.balance_amount.amount), date: s.reference_date || null };
        } catch (_) { /* solde facultatif */ }
      }
      await db.from("bank_state").update({ last_sync: new Date().toISOString(), balances: soldes }).eq("id", 1);
    } catch (e) {
      erreur = String((e as Error).message || e);
    }
  }
  if (cron) return { ok: !erreur, erreur };
  const fin = await etat();
  const depuis = new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth() - 2, 1)).toISOString().slice(0, 10);
  const { data: tx, error } = await db.from("bank_tx").select("id,booking_date,amount,sens,label").gte("booking_date", depuis).order("booking_date");
  if (error) throw error;
  return { connecte: true, valid_until: fin.valid_until, last_sync: fin.last_sync, soldes: fin.balances || {}, comptes: fin.accounts || [], transactions: tx || [], erreur };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const corps = await req.json().catch(() => ({}));
    const action = corps.action;

    // Appel planifié (pg_cron) : ne renvoie aucune donnée, et ne fait rien si la dernière synchro a moins de 5 h.
    if (action === "cron") return json(await synchro(null, true));

    // Tous les autres appels exigent le code d'accès HAZEL.
    const { data: verif, error: e1 } = await db.rpc("get_budget", { c: String(corps.c || "") });
    if (e1) throw e1;
    if (!verif || verif._erreur) return json({ erreur: verif?._erreur || "code" }, 403);

    const psu: Psu = { ip: (req.headers.get("x-forwarded-for") || "").split(",")[0].trim(), ua: req.headers.get("user-agent") || "" };

    if (action === "banques") {
      const r = await eb("/aspsps?country=FR&psu_type=personal&service=AIS");
      return json({ banques: (r.aspsps || []).map((x: any) => x.name).sort() });
    }
    if (action === "connecter") {
      const r0 = await eb("/aspsps?country=FR&psu_type=personal&service=AIS");
      const banque = (r0.aspsps || []).find((x: any) => x.name === corps.banque);
      if (!banque) return json({ erreur: "Banque introuvable" }, 400);
      const secondes = Math.min(banque.maximum_consent_validity || 90 * 86400, 180 * 86400) - 3600;
      const state = crypto.randomUUID();
      const r = await eb("/auth", {
        method: "POST",
        body: { access: { valid_until: new Date(Date.now() + secondes * 1000).toISOString() }, aspsp: { name: banque.name, country: "FR" }, state, redirect_url: SITE, psu_type: "personal" },
      }, psu);
      await db.from("bank_state").update({ pending_state: state, aspsp: { name: banque.name, country: "FR" } }).eq("id", 1);
      return json({ url: r.url });
    }
    if (action === "session") {
      const st = await etat();
      if (!st.pending_state || corps.state !== st.pending_state) return json({ erreur: "Lien de retour invalide, relance la connexion." }, 400);
      const r = await eb("/sessions", { method: "POST", body: { code: corps.code } }, psu);
      const comptes = (r.accounts || []).map((a: any) => ({ uid: a.uid, nom: a.name || a.product || "Compte", fin: String(a.account_id?.iban || "").slice(-4) }));
      await db.from("bank_state").update({ session_id: r.session_id, accounts: comptes, valid_until: r.access?.valid_until || null, pending_state: null, last_sync: null }).eq("id", 1);
      return json(await synchro(psu, false));
    }
    if (action === "sync") return json(await synchro(psu, false));
    if (action === "deconnecter") {
      const st = await etat();
      if (st.session_id) { try { await eb(`/sessions/${st.session_id}`, { method: "DELETE" }); } catch (_) { /* déjà expirée */ } }
      await db.from("bank_state").update({ session_id: null, accounts: null, valid_until: null, balances: null, last_sync: null }).eq("id", 1);
      return json({ connecte: false });
    }
    return json({ erreur: "Action inconnue" }, 400);
  } catch (e) {
    return json({ erreur: String((e as Error).message || e) }, 500);
  }
});
