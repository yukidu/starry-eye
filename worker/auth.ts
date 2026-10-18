import type { Env, LocalUser } from './types';
import { checkCentralAppEntitlement } from './centralAppAccess';
import { clearSessionCookie, json, parseCookies, randomToken, sessionCookie, sha256 } from './security';

const STARRY_ID_ORIGIN = 'https://id.starry.phd';
const APP_ID = 'boxstarry';
const SESSION_DAYS = 30;
const CODE_RE = /^[A-Za-z0-9_-]{30,}$/;

interface CentralMember {
  id: string;
  primaryEmail: string;
  status: string;
  name: string | null;
  avatar: string | null;
  googleAvatar: string | null;
  approvedRank: string | null;
  rank: string | null;
  membershipStatus: string | null;
}

export function startStarryAuth(): Response {
  return Response.redirect(`${STARRY_ID_ORIGIN}/auth/${APP_ID}`, 302);
}

async function consumeCode(env: Env, code: string): Promise<string | null> {
  const codeHash = await sha256(code);
  const row = await env.STARRY_ID_DB.prepare(`
    DELETE FROM starry_app_auth_codes
    WHERE codeHash = ? AND appId = ? AND expiresAt > ?
    RETURNING userId
  `).bind(codeHash, APP_ID, Date.now()).first<{ userId: string }>();
  return row?.userId ? String(row.userId) : null;
}

async function centralMember(env: Env, userId: string): Promise<CentralMember | null> {
  return env.STARRY_ID_DB.prepare(`
    SELECT u.id,u.primaryEmail,u.status,p.name,p.avatar,p.googleAvatar,p.approvedRank,p.rank,
      am.status AS membershipStatus
    FROM users u
    JOIN app_memberships am ON am.userId=u.id AND am.appId=?
    LEFT JOIN profiles p ON p.userId=u.id
    WHERE u.id=? LIMIT 1
  `).bind(APP_ID, userId).first<CentralMember>();
}

async function centralProfileSlug(env: Env, userId: string): Promise<string | null> {
  const row = await env.STARRY_ID_DB.prepare('SELECT slug FROM public_cards WHERE userId=? LIMIT 1')
    .bind(userId).first<{ slug: string | null }>();
  return row?.slug ? String(row.slug) : null;
}

async function resolveLocalUser(env: Env, member: CentralMember): Promise<LocalUser> {
  const email = String(member.primaryEmail || '').trim().toLowerCase();
  if (!email) throw new Error('central_email_missing');
  const mapping = await env.DB.prepare(`
    SELECT u.* FROM starry_identities s JOIN users u ON u.id=s.local_user_id
    WHERE s.starry_user_id=? LIMIT 1
  `).bind(member.id).first<LocalUser>();
  const byEmail = await env.DB.prepare('SELECT * FROM users WHERE lower(email)=lower(?) LIMIT 1')
    .bind(email).first<LocalUser>();
  if (mapping && byEmail && mapping.id !== byEmail.id) throw new Error('local_identity_conflict');

  const id = mapping?.id || byEmail?.id || crypto.randomUUID();
  const name = String(member.name || mapping?.display_name || byEmail?.display_name || '').trim() || null;
  const avatar = String(member.avatar || member.googleAvatar || mapping?.avatar_url || byEmail?.avatar_url || '').trim() || null;
  const slug = await centralProfileSlug(env, member.id);

  await env.DB.batch([
    env.DB.prepare(`INSERT INTO users(id,email,display_name,avatar_url,starry_profile_slug,status,created_at,updated_at,last_login_at)
      VALUES(?,?,?,?,?,'active',datetime('now'),datetime('now'),datetime('now'))
      ON CONFLICT(id) DO UPDATE SET email=excluded.email,display_name=excluded.display_name,avatar_url=excluded.avatar_url,
        starry_profile_slug=excluded.starry_profile_slug,updated_at=datetime('now'),last_login_at=datetime('now')`)
      .bind(id, email, name, avatar, slug),
    env.DB.prepare(`INSERT INTO starry_identities(starry_user_id,local_user_id,linked_at)
      VALUES(?,?,datetime('now')) ON CONFLICT(starry_user_id) DO UPDATE SET local_user_id=excluded.local_user_id`)
      .bind(member.id, id)
  ]);
  const user = await env.DB.prepare('SELECT * FROM users WHERE id=? LIMIT 1').bind(id).first<LocalUser>();
  if (!user) throw new Error('local_user_failed');
  return user;
}

async function createSession(env: Env, userId: string): Promise<string> {
  const token = randomToken(32);
  const hash = await sha256(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString();
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,datetime(\'now\'))')
    .bind(hash, userId, expires).run();
  return token;
}

export async function finishStarryAuth(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code')?.trim() || '';
  if (!CODE_RE.test(code)) return Response.redirect(`${url.origin}/?login=error`, 302);
  try {
    const centralId = await consumeCode(env, code);
    if (!centralId) throw new Error('code_invalid');
    const member = await centralMember(env, centralId);
    if (!member || member.status !== 'active' || member.membershipStatus !== 'active') throw new Error('membership_inactive');
    const access = await checkCentralAppEntitlement(env.STARRY_ID_DB,member.id,APP_ID);
    if (!access.allowed) return Response.redirect(`${url.origin}/?login=denied`,302);
    const user = await resolveLocalUser(env, member);
    const token = await createSession(env, user.id);
    return new Response(null, { status: 302, headers: { location: `${url.origin}/?login=ok`, 'set-cookie': sessionCookie(token) } });
  } catch (error) {
    console.error('Starry ID callback failed', error);
    return Response.redirect(`${url.origin}/?login=error`, 302);
  }
}

export async function currentUser(request: Request, env: Env): Promise<LocalUser | null> {
  const token = parseCookies(request.headers.get('cookie')).box_starry_session || '';
  if (!token) return null;
  const hash = await sha256(token);
  const user = await env.DB.prepare(`
    SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at > datetime('now') AND u.status='active' LIMIT 1
  `).bind(hash).first<LocalUser>();
  if (!user) return null;
  const identity = await env.DB.prepare('SELECT starry_user_id FROM starry_identities WHERE local_user_id=? LIMIT 1')
    .bind(user.id).first<{starry_user_id:string}>();
  if (!identity?.starry_user_id) return null;
  const entitlement = await checkCentralAppEntitlement(env.STARRY_ID_DB,identity.starry_user_id,APP_ID);
  return entitlement.allowed ? user : null;
}


/** One central lookup for the entrypoint; public visitors make no D1 call. */
export async function requestAppAccess(request: Request, env: Env): Promise<'visitor'|'allowed'|'denied'|'needs_login'> {
  const token=parseCookies(request.headers.get('cookie')).box_starry_session||'';
  if(!token)return 'visitor';
  const hash=await sha256(token);
  const mapped=await env.DB.prepare(`SELECT i.starry_user_id
    FROM sessions s
    JOIN users u ON u.id=s.user_id AND u.status='active'
    LEFT JOIN starry_identities i ON i.local_user_id=u.id
    WHERE s.token_hash=? AND s.expires_at > datetime('now') LIMIT 1`)
    .bind(hash).first<{starry_user_id:string|null}>();
  if(!mapped)return 'visitor';
  if(!mapped.starry_user_id)return 'needs_login';
  const state=await checkCentralAppEntitlement(env.STARRY_ID_DB,mapped.starry_user_id,APP_ID);
  return state.allowed?'allowed':'denied';
}

export async function logout(request: Request, env: Env): Promise<Response> {
  const token = parseCookies(request.headers.get('cookie')).box_starry_session || '';
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'set-cookie': clearSessionCookie() });
}

export async function centralRank(env: Env, localUserId: string): Promise<string | null> {
  const row = await env.DB.prepare('SELECT starry_user_id FROM starry_identities WHERE local_user_id=? LIMIT 1')
    .bind(localUserId).first<{ starry_user_id: string }>();
  if (!row) return null;
  const profile = await env.STARRY_ID_DB.prepare('SELECT approvedRank,rank FROM profiles WHERE userId=? LIMIT 1')
    .bind(row.starry_user_id).first<{ approvedRank: string | null; rank: string | null }>();
  return String(profile?.approvedRank || profile?.rank || '').trim() || null;
}
