'use strict';

// 联展批次发布：预览（只读） / 确认（单事务原子发布 2～20 个待发布包）。
//
// 策展人可选取 2～20 个【待发布】展览包组成联展批次：
//   预览：按包展示单站或多站逐站核验结果、共同依据版本与各包清单/行程指纹；
//         只要有包失格（不存在 / 非待发布 / 重算不合格），列出缺口且不下发确认凭据；
//         预览只读，不写入任何数据、不产生快照或凭证。
//   确认：携带预览凭据，服务端在【同一事务】内核对包集合、待发布状态、依据版本、
//         各包清单与行程指纹，并按当前授权及来源关系重算全部包。全部合格时，每包
//         封存不可变发布快照与签名凭证后一起转为已发布；任一不符整批拒绝，
//         不产生快照、凭证或部分发布（单包发布的失败留痕行为仅属单包入口）。

const crypto = require('crypto');
const { basisVersion } = require('./verify');
const keyring = require('./attest-keys');
const {
  loadPublishView,
  recompute,
  sealPublishedPackage,
} = require('./publish');

class BatchError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const MIN_PACKAGES = 2;
const MAX_PACKAGES = 20;
const TOKEN_KIND = 'batch-publish-confirm-v1';

// ---------- 入参：包集合（2～20 个正整数，去重后升序；顺序不影响批次身份） ----------
function parsePackageIds(rawBody) {
  const body = rawBody && typeof rawBody === 'object' ? rawBody : {};
  const raw = body.packageIds;
  if (!Array.isArray(raw)) {
    throw new BatchError(400, '缺少 packageIds（数组；联展批次须选取 2～20 个待发布展览包）',
      { code: 'INVALID_BATCH' });
  }
  const bad = [];
  const ids = [];
  raw.forEach((v, i) => {
    const n = Number(v);
    if (!Number.isInteger(n) || n <= 0) bad.push({ index: i, value: v });
    else if (!ids.includes(n)) ids.push(n);
  });
  if (bad.length) {
    throw new BatchError(400,
      `联展批次包编号必须全部为正整数（${bad.length} 个不合法），已整批拒绝`,
      { code: 'INVALID_BATCH', errors: bad });
  }
  if (ids.length < MIN_PACKAGES) {
    throw new BatchError(400,
      `联展批次至少选取 ${MIN_PACKAGES} 个展览包（当前去重后 ${ids.length} 个）`,
      { code: 'INVALID_BATCH', minPackages: MIN_PACKAGES, maxPackages: MAX_PACKAGES });
  }
  if (ids.length > MAX_PACKAGES) {
    throw new BatchError(400,
      `联展批次至多选取 ${MAX_PACKAGES} 个展览包（当前去重后 ${ids.length} 个）`,
      { code: 'INVALID_BATCH', minPackages: MIN_PACKAGES, maxPackages: MAX_PACKAGES });
  }
  return ids.sort((a, b) => a - b);
}

// ---------- 逐站摘要（单站/多站统一形态，便于页面与 API 消费） ----------
function stopSummariesOf(result, pkg, multiStop) {
  if (multiStop) {
    return (result.stops || []).map((s) => ({
      position: s.position,
      name: s.name,
      medium: s.medium,
      region: s.region,
      useFrom: s.useFrom,
      useTo: s.useTo,
      eligible: s.eligible,
      nodeCount: s.stats.nodeCount,
      failingNodeCount: s.stats.failingCount,
      failingNodes: s.failingNodes,
    }));
  }
  return [{
    position: 0,
    name: pkg.name,
    medium: pkg.medium,
    region: pkg.region,
    useFrom: pkg.use_from,
    useTo: pkg.use_to,
    eligible: result.eligible,
    nodeCount: result.stats.nodeCount,
    failingNodeCount: result.stats.failingCount,
    failingNodes: result.failingNodes,
  }];
}

// ---------- 预览凭据 ----------
function tokenEntries(packages) {
  return packages.map((p) => ({
    packageId: p.packageId,
    listFingerprint: p.listFingerprint,
    itineraryFingerprint: p.itineraryFingerprint,
  }));
}

function signToken(basis, packages) {
  const payload = {
    kind: TOKEN_KIND,
    basisVersion: basis,
    packageIds: packages.map((p) => p.packageId),
    packages: tokenEntries(packages),
    createdAt: new Date().toISOString(),
  };
  const digest = crypto.createHash('sha256').update(keyring.canonicalJSON(payload), 'utf8').digest('hex');
  return { ...payload, digest };
}

// 结构校验 + 防篡改校验；返回规范化 token。任何不符均为凭据不符（409）。
function parseConfirmToken(rawBody) {
  const body = rawBody && typeof rawBody === 'object' ? rawBody : {};
  const token = body.confirmToken ?? body.token;
  if (!token || typeof token !== 'object') {
    throw new BatchError(400, '缺少确认凭据 confirmToken，请先调用联展批次预览',
      { code: 'TOKEN_REQUIRED' });
  }
  const { kind, basisVersion: clientBasis, packageIds, packages, createdAt, digest } = token;
  const entriesValid = Array.isArray(packages)
    && packages.every((e) => e && Number.isInteger(Number(e.packageId))
      && typeof e.listFingerprint === 'string'
      && typeof e.itineraryFingerprint === 'string');
  if (kind !== TOKEN_KIND || typeof digest !== 'string'
    || !Number.isInteger(Number(clientBasis))
    || !Array.isArray(packageIds) || packageIds.length < MIN_PACKAGES || packageIds.length > MAX_PACKAGES
    || !entriesValid || packages.length !== packageIds.length
    || typeof createdAt !== 'string') {
    throw new BatchError(409, '联展批次确认凭据内容不完整或已损坏，请重新预览',
      { code: 'TOKEN_MISMATCH' });
  }
  const payload = { kind, basisVersion: Number(clientBasis), packageIds: packageIds.map(Number),
    packages: packages.map((e) => ({
      packageId: Number(e.packageId),
      listFingerprint: e.listFingerprint,
      itineraryFingerprint: e.itineraryFingerprint,
    })),
    createdAt };
  // 包集合须为正整数、去重且与条目一一对应
  const ids = payload.packageIds;
  if (ids.some((id) => id <= 0) || new Set(ids).size !== ids.length
    || payload.packages.some((e, i) => e.packageId !== ids[i])) {
    throw new BatchError(409, '联展批次确认凭据中的包集合无效，请重新预览',
      { code: 'TOKEN_MISMATCH' });
  }
  const expectDigest = crypto.createHash('sha256')
    .update(keyring.canonicalJSON(payload), 'utf8').digest('hex');
  if (expectDigest !== digest) {
    throw new BatchError(409, '联展批次确认凭据校验失败（可能被篡改或来自旧预览），请重新预览',
      { code: 'TOKEN_MISMATCH' });
  }
  return payload;
}

// ---------- 主入口：预览（只读，不写入任何数据） ----------
function previewBatchPublish(db, rawBody) {
  const ids = parsePackageIds(rawBody);

  const run = db.transaction(() => {
    const basis = basisVersion(db);
    const packages = ids.map((id) => {
      const view = loadPublishView(db, id);
      if (!view) {
        return {
          packageId: id, found: false, name: null, status: null,
          multiStop: false, stopCount: 0, itemCount: 0,
          eligible: false,
          blockers: [{ code: 'PACKAGE_NOT_FOUND', message: `展览包 #${id} 不存在` }],
        };
      }
      const { pkg } = view;
      const result = recompute(db, view);
      const blockers = [];
      if (pkg.status !== 'draft') {
        blockers.push({
          code: 'NOT_DRAFT',
          status: pkg.status,
          message: `包当前状态为 ${pkg.status}，只有待发布（draft）包可以参与联展批次发布`,
        });
      }
      if (!result.eligible) {
        blockers.push({
          code: 'RECOMPUTE_DISQUALIFIED',
          message: '按当前授权及来源关系重算未通过（单站/多站逐站核验存在缺口）',
        });
      }
      return {
        packageId: id,
        found: true,
        name: pkg.name,
        status: pkg.status,
        multiStop: view.multiStop,
        stopCount: view.multiStop ? view.stopRows.length : 1,
        itemCount: view.items.length,
        eligible: blockers.length === 0,
        blockers,
        listFingerprint: view.listFingerprint,
        itineraryFingerprint: view.itineraryFingerprint,
        stops: stopSummariesOf(result, pkg, view.multiStop),
        result,
      };
    });

    const missing = packages.filter((p) => !p.found).map((p) => p.packageId);
    const blocked = packages.filter((p) => p.found && !p.eligible);
    const eligiblePackages = packages.filter((p) => p.eligible);
    const allEligible = missing.length === 0 && blocked.length === 0;

    const out = {
      generatedAt: new Date().toISOString(),
      mutated: false,
      basisVersion: basis,
      packageCount: packages.length,
      eligibleCount: eligiblePackages.length,
      blockedCount: blocked.length + missing.length,
      missingPackageIds: missing,
      eligible: allEligible,
      packages,
    };
    // 全部合格（均存在、待发布、重算合格）才下发确认凭据
    if (allEligible) out.confirmToken = signToken(basis, eligiblePackages);
    return out;
  });

  return run();
}

// ---------- 主入口：确认（单事务；任一不符整批拒绝，不产生任何部分发布） ----------
function confirmBatchPublish(db, rawBody) {
  const token = parseConfirmToken(rawBody);

  const run = db.transaction(() => {
    // 1) 共同依据版本：预览后授权/来源关系被任何增删改即整体拒绝
    const currentBasis = basisVersion(db);
    if (token.basisVersion !== currentBasis) {
      throw new BatchError(409,
        `核验依据已变化：预览时版本 ${token.basisVersion}，当前版本 ${currentBasis}，授权或来源关系在此期间被修改。整批拒绝，请重新预览。`,
        { code: 'STALE_BASIS', clientBasis: token.basisVersion, currentBasis });
    }

    const fpById = new Map(token.packages.map((e) => [e.packageId, e]));
    const missing = [];
    const notDraft = [];
    const changed = [];
    const disqualified = [];
    const views = new Map();

    // 2) 逐包核对：存在 → 待发布 → 清单/行程指纹 → 按当前数据重算
    for (const id of token.packageIds) {
      const view = loadPublishView(db, id);
      if (!view) {
        missing.push({ packageId: id, message: `展览包 #${id} 不存在` });
        continue;
      }
      views.set(id, view);
      if (view.pkg.status !== 'draft') {
        notDraft.push({ packageId: id, status: view.pkg.status,
          message: `包 #${id} 当前状态为 ${view.pkg.status}，不再是待发布` });
      }
      const fp = fpById.get(id);
      const changes = [];
      if (view.listFingerprint !== fp.listFingerprint) changes.push('LIST_CHANGED');
      if (view.itineraryFingerprint !== fp.itineraryFingerprint) changes.push('ITINERARY_CHANGED');
      if (changes.length) {
        changed.push({ packageId: id, changes,
          currentListFingerprint: view.listFingerprint,
          currentItineraryFingerprint: view.itineraryFingerprint,
          message: `包 #${id} 的清单或行程在预览后被修改（${changes.join('、')}）` });
      }
      // 无论状态是否变化都重算：用于一次性给出全部失格缺口
      const result = recompute(db, view);
      if (!result.eligible) {
        disqualified.push({
          packageId: id, name: view.pkg.name,
          multiStop: view.multiStop,
          stops: stopSummariesOf(result, view.pkg, view.multiStop),
          result,
        });
      }
    }

    // 拒绝优先级：包不存在 → 状态变化 → 清单/行程变化 → 重算失格
    if (missing.length) {
      throw new BatchError(404,
        `联展批次中的 ${missing.length} 个包不存在，整批拒绝（未产生快照、凭证或发布）`,
        { code: 'BATCH_PACKAGE_NOT_FOUND', missing });
    }
    if (notDraft.length) {
      throw new BatchError(409,
        `联展批次中的 ${notDraft.length} 个包已不是待发布状态，整批拒绝`,
        { code: 'BATCH_NOT_DRAFT', packages: notDraft });
    }
    if (changed.length) {
      throw new BatchError(409,
        `联展批次中的 ${changed.length} 个包在预览后清单或行程发生变化，整批拒绝，请重新预览`,
        { code: 'BATCH_PACKAGE_CHANGED', packages: changed });
    }
    if (disqualified.length) {
      throw new BatchError(422,
        `联展批次中的 ${disqualified.length} 个包按当前授权及来源关系重算失格，整批拒绝（未产生快照、凭证或部分发布）`,
        { code: 'BATCH_RECOMPUTE_DISQUALIFIED', packages: disqualified });
    }

    // 3) 全部合格：同一事务内逐包封存不可变快照 + 签名凭证，再一起转为已发布
    const sealed = [];
    for (const id of token.packageIds) {
      const view = views.get(id);
      const result = recompute(db, view); // 封存前最后一次权威重算（与上面同一数据快照）
      if (!result.eligible) {
        throw new BatchError(422, `包 #${id} 封存前重算失格，整批拒绝`,
          { code: 'BATCH_RECOMPUTE_DISQUALIFIED' });
      }
      sealed.push({ packageId: id, ...sealPublishedPackage(db, { view, result, sealContext: 'publish' }) });
    }

    return {
      basisVersion: currentBasis,
      packageCount: sealed.length,
      packages: sealed.map((s) => ({
        packageId: s.packageId,
        snapshotId: s.snapshotId,
        attestationId: s.attestationId,
        attestation: s.envelope,
        result: s.result,
      })),
    };
  });

  return run();
}

module.exports = {
  BatchError,
  previewBatchPublish,
  confirmBatchPublish,
  MIN_PACKAGES,
  MAX_PACKAGES,
};
