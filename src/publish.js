'use strict';

// 发布共享逻辑：单包发布（/api/packages/:id/publish）与联展批次发布
// （/api/batch-publish/preview|confirm）共用同一套“读取 → 指纹 → 重算 → 封存”。
//
// 关键约束（两种入口一致）：
//   - 只处理状态为 draft（待发布）的包；
//   - 发布在同一事务内重读清单/行程/授权依据并重算，任一包失格即整体拒绝；
//   - 成功时在同一事务写入不可变发布快照 + 签名发布凭证，再置为 published；
//   - 不合格不产生成功快照/凭证（单包发布另保留既有“失败留痕”行为，见 server.js）。

const crypto = require('crypto');
const { verifyStoredPackage, loadStops } = require('./verify');
const { buildAttestation } = require('./attest');
const { nowIso } = require('./db');

// ---------- 指纹 ----------
function sha256(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// 清单指纹：入展素材 id 升序的确定性哈希
function listFingerprint(sortedMaterialIds) {
  return sha256({ materialIds: [...sortedMaterialIds].sort((a, b) => a - b) });
}

// 行程指纹：单站取包顶层媒介/地区/展期；多站取按 position 排序的完整站次
function itineraryFingerprint(pkg, stopRows) {
  if (stopRows.length >= 2) {
    return sha256({
      multiStop: true,
      stops: stopRows.map((s) => ({
        name: s.name,
        medium: s.medium,
        region: s.region,
        useFrom: s.useFrom ?? s.use_from,
        useTo: s.useTo ?? s.use_to,
      })),
    });
  }
  return sha256({
    multiStop: false,
    medium: pkg.medium,
    region: pkg.region,
    useFrom: pkg.use_from,
    useTo: pkg.use_to,
  });
}

// 载入包当前清单（按 position、material_id 排序）
function loadItems(db, packageId) {
  return db
    .prepare('SELECT material_id FROM package_items WHERE package_id=? ORDER BY position, material_id')
    .all(packageId)
    .map((r) => r.material_id);
}

// 包的发布前视图（调用方应在事务内调用，保证多个包看到同一时刻数据）
function loadPublishView(db, packageId) {
  const pkg = db.prepare('SELECT * FROM packages WHERE id=?').get(packageId);
  if (!pkg) return null;
  const items = loadItems(db, packageId);
  const stopRows = loadStops(db, packageId);
  return {
    pkg,
    items,
    stopRows,
    multiStop: stopRows.length >= 2,
    listFingerprint: listFingerprint(items),
    itineraryFingerprint: itineraryFingerprint(pkg, stopRows),
  };
}

// 按当前授权及来源关系重算单站或多站包
function recompute(db, view) {
  return verifyStoredPackage(db, view.pkg, view.items, view.stopRows);
}

// 在【已开启的事务】内封存一个已重算合格的包：
// 不可变发布快照 + 同事务签名凭证 + 置为 published。
// 调用方必须保证 result.eligible === true（由重算得出）。
function sealPublishedPackage(db, { view, result, sealContext = 'publish' }) {
  const { pkg } = view;
  const createdAt = nowIso();
  const payloadText = JSON.stringify(result);
  const snapshotId = db
    .prepare(
      `INSERT INTO verification_snapshots(package_id, kind, basis_version, eligible, payload, created_at)
       VALUES (?,?,?,?,?,?)`
    )
    .run(pkg.id, 'publish', result.basisVersion, 1, payloadText, createdAt)
    .lastInsertRowid;

  const envelope = buildAttestation(db, {
    result,
    packageId: pkg.id,
    packageName: pkg.name,
    snapshotId,
    snapshotCreatedAt: createdAt,
    snapshotPayloadText: payloadText,
    sealContext,
  });
  db.prepare(
    `INSERT INTO publish_attestations(package_id, verification_snapshot_id, signer_kid, seal_context, envelope, created_at)
     VALUES (?,?,?,?,?,?)`
  ).run(pkg.id, snapshotId, envelope.signature.kid, sealContext, JSON.stringify(envelope), createdAt);

  db.prepare("UPDATE packages SET status='published', published_at=?, updated_at=? WHERE id=?")
    .run(createdAt, createdAt, pkg.id);

  const attestationId = db
    .prepare('SELECT id FROM publish_attestations WHERE verification_snapshot_id=?')
    .pluck().get(snapshotId);
  return { snapshotId, attestationId, envelope, createdAt, result };
}

module.exports = {
  sha256,
  listFingerprint,
  itineraryFingerprint,
  loadItems,
  loadPublishView,
  recompute,
  sealPublishedPackage,
};
