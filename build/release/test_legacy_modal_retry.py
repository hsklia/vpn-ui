"""Exercise the actual create-modal scripts and HTTP response handling with Node."""

import pathlib
import shutil
import subprocess
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = process.argv[1];
const success = { success: true, obj: { applied: true, noRestart: true } };
const pending = { success: false, obj: { persisted: true }, msg: 'activation pending' };

function fixture(kind, outcomes) {
  let sequence = 0, now = 1700000000000;
  const posts = [], releases = [], queue = outcomes.slice();
  function Vue() {}
  Vue.set = (object, key, value) => object[key] = value;
  Vue.prototype.$message = { error() {}, success() {} };
  const context = {
    Vue, themeSwitcher: {}, RESELLER: { isReseller: false, daysPerGb: 0 },
    console: { error() {} },
    Date: { now: () => now },
    RandomUtil: {
      randomUUID: () => '00000000-0000-4000-8000-' + String(++sequence).padStart(12, '0'),
      randomSeq: () => 'credential' + (++sequence),
      randomLowerAndNum: () => 'name' + (++sequence),
    },
    axios: {
      async post(url, body) {
        posts.push({ url, body: JSON.parse(JSON.stringify(body)) });
        assert.ok(queue.length, 'unexpected extra HTTP request');
        const outcome = queue.shift();
        if (outcome === 'dropped') throw new Error('response lost');
        if (outcome === 'hold') return await new Promise(resolve => releases.push(() => resolve({ data: success })));
        return { data: outcome };
      },
    },
  };
  vm.createContext(context);
  const util = fs.readFileSync(path.join(source, 'web/assets/js/util/index.js'), 'utf8');
  vm.runInContext(util.slice(0, util.indexOf('class PromiseUtil')), context);
  const single = kind === 'single';
  const name = single ? 'clientMembershipModal' : 'clientsBulkModal';
  const file = single ? 'client_membership_modal.html' : 'client_bulk_modal.html';
  const html = fs.readFileSync(path.join(source, 'web/html/modals', file), 'utf8');
  const script = html.split('<script>')[1].split('</script>')[0]
    .replace(/\{\{[\s\S]*?\}\}/g, 'localized');
  vm.runInContext(script + '\nglobalThis.modal = ' + name + ';', context);
  const modal = context.modal;
  function show() {
    modal.show({ assignable: [{ inboundId: 1, protocol: 'wg-c' }] });
    modal.selected = [1];
    modal.days = 7;
    if (!single) {
      modal.quantity = 2;
      modal.emailMethod = kind === 'fixed' ? 4 : 0;
      modal.firstNum = 1;
      modal.lastNum = 2;
      modal.emailPrefix = 'batch';
    }
  }
  show();
  return {
    modal, posts, releases, show, advance() { now += 60000; },
    edit() { if (single) modal.client.comment = 'corrected'; else modal.comment = 'corrected'; },
    restore() { if (single) modal.client.comment = ''; else modal.comment = ''; },
    randomCount() { return sequence; },
  };
}

async function retry(kind, first) {
  const f = fixture(kind, [first, success]);
  await f.modal.ok();
  assert.equal(f.posts.length, 1);
  assert.ok(f.modal.pendingAdd, 'unconfirmed operation must remain available');
  if (first !== pending) assert.equal(f.modal.pendingAdd.uncertain, true);
  assert.equal(f.modal.visible, true);
  assert.ok(f.modal.addRetryNotice);
  const randomCount = f.randomCount();
  f.advance();
  f.edit();
  await f.modal.ok();
  assert.equal(f.posts.length, 1, 'editing a saved/unknown operation must not submit');
  assert.match(f.modal.addRetryNotice, /Restore the original form/);
  f.restore();
  await f.modal.ok();
  assert.equal(f.posts.length, 2);
  assert.deepEqual(f.posts[1], f.posts[0], 'retry must preserve the complete posted body');
  assert.equal(f.randomCount(), randomCount, 'retry must not mint another identity');
  assert.equal(f.modal.pendingAdd, null);
  assert.equal(f.modal.visible, false);
  assert.equal(f.modal.confirmLoading, false);
}

async function correctedRejection(kind, first) {
  const f = fixture(kind, [first, success]);
  await f.modal.ok();
  assert.equal(f.modal.pendingAdd, null, 'definite pre-persist rejection must unlock input');
  assert.equal(f.modal.addRetryNotice, '');
  f.edit();
  f.advance();
  await f.modal.ok();
  assert.equal(f.posts.length, 2);
  const entry = JSON.parse(f.posts[1].body.settings).clients[0];
  assert.equal(entry.comment, 'corrected');
  assert.notDeepEqual(f.posts[1], f.posts[0]);
}

(async () => {
  let checks = 0;
  for (const kind of ['single', 'random', 'fixed']) {
    // Use real Msg/HttpUtil conversion, including dropped, empty and malformed
    // replies that must not look like definite pre-persist validation failures.
    for (const first of [
      pending, 'dropped', null, undefined, 'bad gateway', {},
      { success: 'false' }, { success: 1 },
    ]) {
      await retry(kind, first);
      checks++;
    }
    for (const first of [
      { success: false, obj: { persisted: false }, msg: 'invalid input' },
      { success: false, obj: null, msg: 'legacy validation failed' },
    ]) {
      await correctedRejection(kind, first);
      checks++;
    }
    const reset = fixture(kind, [pending, success]);
    await reset.modal.ok();
    reset.modal.close();
    reset.show();
    assert.equal(reset.modal.pendingAdd, null);
    assert.equal(reset.modal.addRetryNotice, '');
    reset.advance();
    await reset.modal.ok();
    assert.notDeepEqual(reset.posts[1], reset.posts[0], 'a new form must start a fresh operation');
    checks++;

    const double = fixture(kind, ['hold']);
    const firstClick = double.modal.ok();
    await double.modal.ok();
    assert.equal(double.posts.length, 1, 'an in-flight click must not send a second request');
    double.releases[0]();
    await firstClick;
    checks++;

    const reopened = fixture(kind, ['hold']);
    const oldRequest = reopened.modal.ok();
    reopened.modal.close();
    reopened.show();
    reopened.releases[0]();
    await oldRequest;
    assert.equal(reopened.modal.visible, true, 'an old response must not close a new form');
    assert.equal(reopened.modal.pendingAdd, null);
    assert.equal(reopened.modal.confirmLoading, false);
    checks++;

    // A later generic denial cannot erase an already confirmed stored account.
    const saved = fixture(kind, [pending, { success: false, obj: null }, success]);
    await saved.modal.ok();
    await saved.modal.ok();
    assert.ok(saved.modal.pendingAdd);
    saved.edit();
    await saved.modal.ok();
    assert.equal(saved.posts.length, 2);
    saved.restore();
    await saved.modal.ok();
    assert.deepEqual(saved.posts[2], saved.posts[0]);
    checks++;

    // A generic server denial cannot resolve a prior transport-unknown result.
    const unknown = fixture(kind, ['dropped', { success: false, obj: null }, success]);
    await unknown.modal.ok();
    assert.equal(unknown.modal.pendingAdd.saved, false);
    assert.equal(unknown.modal.pendingAdd.uncertain, true);
    const minted = unknown.randomCount();
    unknown.advance();
    await unknown.modal.ok();
    assert.ok(unknown.modal.pendingAdd, 'generic denial cannot disprove an earlier commit');
    unknown.edit();
    await unknown.modal.ok();
    assert.equal(unknown.posts.length, 2, 'unknown operation must not become a new batch');
    unknown.restore();
    await unknown.modal.ok();
    assert.deepEqual(unknown.posts[2], unknown.posts[0]);
    assert.equal(unknown.randomCount(), minted);
    checks++;

    // An explicit persisted:false acknowledgement is authoritative when the
    // request was unknown, rather than already confirmed saved.
    const notSaved = fixture(kind, ['dropped', { success: false, obj: { persisted: false } }, success]);
    await notSaved.modal.ok();
    await notSaved.modal.ok();
    assert.equal(notSaved.modal.pendingAdd, null);
    notSaved.edit();
    notSaved.advance();
    await notSaved.modal.ok();
    assert.equal(notSaved.posts.length, 3);
    assert.equal(JSON.parse(notSaved.posts[2].body.settings).clients[0].comment, 'corrected');
    assert.notDeepEqual(notSaved.posts[2], notSaved.posts[0]);
    checks++;
  }
  // The add may succeed before a separate membership ad-tag write fails. A
  // subsequent generic permission denial must not unlock that known saved add.
  const adtag = fixture('single', [
    success,
    { success: false, obj: null, msg: 'ad tag rejected' },
    { success: false, obj: null, msg: 'permission denied' },
    success, success,
  ]);
  adtag.modal.assignable = [
    { inboundId: 1, protocol: 'vless' }, { inboundId: 2, protocol: 'mtproto' },
  ];
  adtag.modal.selected = [1, 2];
  await adtag.modal.ok();
  assert.equal(adtag.posts.length, 2);
  assert.equal(adtag.posts[0].url, '/panel/api/inbounds/addClient');
  assert.match(adtag.posts[1].url, /\/updateClient\//);
  assert.ok(adtag.modal.pendingAdd.saved, 'a confirmed add remains saved when ad-tag update fails');
  assert.equal(adtag.modal.visible, true);
  adtag.advance();
  await adtag.modal.ok();
  assert.equal(adtag.posts.length, 3);
  assert.deepEqual(adtag.posts[2], adtag.posts[0]);
  assert.ok(adtag.modal.pendingAdd.saved, 'later permission denial must not forget the saved add');
  adtag.edit();
  await adtag.modal.ok();
  assert.equal(adtag.posts.length, 3, 'edited form must not create another account');
  assert.match(adtag.modal.addRetryNotice, /Restore the original form/);
  adtag.restore();
  await adtag.modal.ok();
  assert.deepEqual(adtag.posts[3], adtag.posts[0]);
  assert.match(adtag.posts[4].url, /\/updateClient\//);
  assert.equal(adtag.modal.pendingAdd, null);
  assert.equal(adtag.modal.visible, false);
  checks++;

  const edit = fixture('single', [success]);
  const expiry = 1700600000000;
  edit.modal.show({
    row: { email: 'existing-account', enable: true, expiryTime: expiry,
      memberships: [{ inboundId: 1, protocol: 'wg-c', clientId: 'existing-account' }] },
    storedBy: { 1: { email: 'existing-account', id: 'existing-account' } },
    assignable: [{ inboundId: 1, protocol: 'wg-c' }],
  });
  await edit.modal.ok();
  assert.match(edit.posts[0].url, /\/updateClient\/existing-account$/);
  assert.equal(JSON.parse(edit.posts[0].body.settings).clients[0].expiryTime, expiry);
  assert.equal(edit.modal.pendingAdd, null);
  checks++;
  console.log(JSON.stringify({ checks }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
"""


class LegacyModalRetryTest(unittest.TestCase):
    def test_actual_modal_create_retries(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js is required for modal retry regression tests")
        result = subprocess.run(
            [node, "-e", SCRIPT, str(SOURCE)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"checks":50', result.stdout)


if __name__ == "__main__":
    unittest.main()
