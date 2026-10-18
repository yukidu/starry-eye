import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const policy=read('worker/centralAppAccess.ts');
const auth=read('worker/auth.ts');
const entry=read('worker/studioRouter.ts');
test('Eye checks central grants for new login and existing cookies',()=>{
 assert.match(auth,/checkCentralAppEntitlement\(env\.STARRY_ID_DB,member\.id,APP_ID\)/);
 assert.match(auth,/requestAppAccess/);
 assert.match(auth,/starry_identities/);
 assert.match(entry,/requestAppAccess\(request,env\)/);
 assert.match(entry,/APP_ACCESS_DENIED/);
 assert.match(entry,/您沒有使用權限/);
});
test('Eye enforces explicit denies and grandfathered access',()=>{
 assert.match(policy,/row\.decision==='deny'/);
 assert.match(policy,/row\.decision==='allow'/);
 assert.match(policy,/STARRY_APP_GRANT_CUTOFF/);
 assert.match(policy,/row\.membershipStatus && row\.membershipStatus!=='active'/);
 assert.match(entry,/url\.pathname==='\/' \|\| url\.pathname\.startsWith\('\/api\/'\)/);
});
