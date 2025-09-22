import { Context, Handler, PRIV, ForbiddenError, TokenModel, UserModel } from 'hydrooj';

/**
 * IP Control 插件（重写版）
 * 功能：
 * 1. 比赛开关：contest.ipControlEnabled
 * 2. 比赛开始前 1 小时阻止已报名用户登录（并清除其 token）
 * 3. 比赛进行中首次登录绑定 IP+UA，后续变更拒绝
 * 4. 管理页面：开启/关闭、导入 UID 参赛、清除锁
 * 5. 仅影响已报名且开启了 IP 控制的未结束比赛
 */

// ---------------- 内部状态 ----------------
let docModel: any; // document model
let ipLockColl: any; // 记录 (contestDocId, uid) -> { ip, ua }
let db: any; // 原始数据库实例 (ctx.db)
let indexesEnsured = false; // 索引一次性创建

// ---------------- 类型声明 ----------------
interface IpLockRecord {
  _id: string; // `${contestDocId}:${uid}`
  contestId: any; // contest docId (文档内部 id，不一定是字符串)
  uid: number;
  ip: string;
  ua: string;
  createdAt: Date;
  updatedAt: Date;
}

declare module 'hydrooj' {
  interface Collections { ipcontrol_login: IpLockRecord; }
}

// ---------------- 日志封装（始终输出） ----------------
const log = (...a: any[]) => console.log('[IPControl]', ...a);
const warn = (...a: any[]) => console.warn('[IPControl][WARN]', ...a);
const err = (...a: any[]) => console.error('[IPControl][ERR]', ...a);

// ---------------- 工具函数 ----------------
function normalizeDomainId(d: any): string { return typeof d === 'string' ? d : (d?.domainId || 'system'); }
function firstIp(raw?: string): string { if (!raw) return ''; const part = raw.split(',')[0].trim(); return part.includes(':') ? part.split(':')[0] : part; }

// ================== 采用生产已验证的比赛获取策略 ==================
// 与 CAUCOJUserBind 保持一致：
// 1) document.findOne({_id: contestId, docType:30})
// 2) 如果失败，加载所有 docType:30，字符串匹配 _id
// 不再使用 docModel.get / 其他集合回退，确保行为一致性。
async function fetchContest(_domainIdInput: string | any, contestId: any) {
  if (!db) return null;
  const documentColl = db.collection('document');
  let contest: any = null;
  try {
    contest = await documentColl.findOne({ _id: contestId, docType: 30 });
    if (contest) {
      log('fetchContest direct match', { _id: contest._id?.toString?.(), docId: contest.docId });
      return contest;
    }
  } catch (e) {
    warn('fetchContest direct query error', e);
  }
  try {
    const all = await documentColl.find({ docType: 30 }).toArray();
    contest = all.find(c => c._id?.toString?.() === contestId?.toString?.());
    if (contest) {
      log('fetchContest fallback list match', { _id: contest._id?.toString?.(), docId: contest.docId });
      return contest;
    }
    warn('fetchContest not found (docType=30)', { contestId });
  } catch (e) {
    err('fetchContest fallback error', e);
  }
  return null;
}

async function listActive(domainId: string) {
  if (!db) return [];
  const documentColl = db.collection('document');
  const now = new Date();
  try {
    // 只筛选已开启 ipControlEnabled 且未结束的比赛 (docType=30)
    const list = await documentColl.find({ docType: 30, ipControlEnabled: true, endAt: { $gt: now } }).toArray();
    return list;
  } catch (e) { err('listActive error', e); return []; }
}

async function shouldBlockLogin(domainId: string, uid: number) {
  const contests = await listActive(domainId);
  if (!contests.length) return { block: false };
  const docIds = contests.map(c => c.docId).filter(id => id !== undefined);
  let attended: any[] = [];
  if (docModel && docIds.length) {
    try {
      attended = await docModel.getMultiStatus(domainId, docModel.TYPE_CONTEST, { uid, docId: { $in: docIds }, attend: 1 }).project({ docId: 1 }).toArray();
    } catch (e) { err('getMultiStatus error', e); }
  }
  if (!attended.length) return { block: false };
  const now = Date.now();
  for (const c of contests) {
    const begin = new Date(c.beginAt).getTime();
    if (now < begin && now >= begin - 3600_000) {
      if (attended.find(a => a.docId?.toString?.() === c.docId?.toString?.())) {
        return { block: true, reason: '比赛开始前一小时禁止登录（IP控制）' };
      }
    }
  }
  return { block: false };
}

async function verifyDuringContest(domainId: string, uid: number, ip: string, ua: string) {
  const contests = await listActive(domainId);
  if (!contests.length) return;
  const docIds = contests.map(c => c.docId).filter(id => id !== undefined);
  let attended: any[] = [];
  if (docModel && docIds.length) {
    try { attended = await docModel.getMultiStatus(domainId, docModel.TYPE_CONTEST, { uid, docId: { $in: docIds }, attend: 1 }).project({ docId: 1 }).toArray(); } catch (e) { err('getMultiStatus error', e); }
  }
  if (!attended.length) return;
  const now = Date.now();
  for (const c of contests) {
    const begin = new Date(c.beginAt).getTime();
    const end = new Date(c.endAt).getTime();
    if (now >= begin && now <= end) {
      if (!attended.find(a => a.docId?.toString?.() === c.docId?.toString?.())) continue;
      const key = `${c.docId}:${uid}`;
      let rec: IpLockRecord | null = await ipLockColl.findOne({ _id: key });
      if (!rec) {
        rec = { _id: key, contestId: c.docId, uid, ip, ua, createdAt: new Date(), updatedAt: new Date() };
        await ipLockColl.insertOne(rec);
        log('bind first login', { contest: c.docId?.toString?.(), uid, ip, ua });
      } else if (rec.ip !== ip || rec.ua !== ua) {
        log('reject ip/ua change', { contest: c.docId?.toString?.(), uid, oldIp: rec.ip, newIp: ip, oldUa: rec.ua, newUa: ua });
        throw new ForbiddenError('IP/UA 与首次登录不一致，比赛已启用 IP 控制');
      }
    }
  }
}

// ---------------- 路由 Handler ----------------
class ManageHandler extends Handler {
  async get(domainIdParam: string) {
    this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
    const { contestId } = this.request.params;
    const contest = await fetchContest(domainIdParam, contestId);
    if (!contest) throw new ForbiddenError('比赛不存在');
    let imported = 0;
    if (docModel && contest.docId !== undefined) {
      try { imported = await docModel.countStatus(domainIdParam, docModel.TYPE_CONTEST, { docId: contest.docId, attend: 1 }); } catch { /* ignore */ }
    }
    const beginAtStr = contest.beginAt ? new Date(contest.beginAt).toISOString().replace('T',' ').substring(0,19) : '';
    const endAtStr = contest.endAt ? new Date(contest.endAt).toISOString().replace('T',' ').substring(0,19) : '';
    this.response.template = 'ipcontrol_contest_manage.html';
    this.response.body = { contest, imported, beginAtStr, endAtStr };
  }
  async post(domainIdParam: string) {
    this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
    const { contestId } = this.request.params;
    const contest = await fetchContest(domainIdParam, contestId);
    if (!contest) throw new ForbiddenError('比赛不存在');
    const { action } = this.request.body;
    if (action === 'toggle') {
      const enable = this.request.body.enabled === 'true';
      if (docModel && contest.docId !== undefined) {
        await docModel.set(domainIdParam, docModel.TYPE_CONTEST, contest.docId, { ipControlEnabled: enable } as any);
      } else {
        // 直接更新底层 document 集合（不推荐，但保持行为）
        try { await db.collection('document').updateOne({ _id: contest._id }, { $set: { ipControlEnabled: enable } }); } catch (e) { err('direct update ipControlEnabled failed', e); }
      }
      log('toggle', { contest: contest.docId, enable });
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    if (action === 'import_uids') {
      const text: string = this.request.body.uidsText || '';
      const list: number[] = [];
      text.split(/[\s,;]+/).forEach(t => { if (/^\d+$/.test(t)) list.push(+t); });
      if (docModel && contest.docId !== undefined) {
        for (const uid of list) {
          await docModel.setStatus(domainIdParam, docModel.TYPE_CONTEST, contest.docId, uid, { attend: 1, subscribe: 1 } as any);
        }
      }
      log('import uids', { contest: contest.docId, count: list.length });
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    if (action === 'clear_locks') {
      await ipLockColl.deleteMany({ contestId: contest.docId });
      log('clear locks', { contest: contest.docId });
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    this.response.redirect = `/contest/${contestId}/ipcontrol`;
  }
}

// ---------------- 入口 ----------------
export async function apply(ctx: Context) {
  // 初始化 model & collection
  if (!docModel) docModel = (global as any).Hydro?.model?.document || (global as any).Hydro?.model?.doc || (global as any).Hydro?.model?.Document;
  if (!ipLockColl) { ipLockColl = ctx.db.collection('ipcontrol_login'); log('ipLock collection ready'); }
  if (!db) db = ctx.db;
  if (!indexesEnsured) {
    try {
      await ctx.db.ensureIndexes(
        ipLockColl,
        { key: { contestId: 1, uid: 1 }, name: 'contest_user' },
        { key: { createdAt: 1 }, name: 'createdAt' },
      );
      indexesEnsured = true;
    } catch (e) { err('ensureIndexes failed', e); }
  }
  log('plugin initialized');

  // 管理路由
  ctx.Route('ipcontrol_contest_manage', '/contest/:contestId/ipcontrol', ManageHandler, PRIV.PRIV_EDIT_SYSTEM);
  log('route registered /contest/:contestId/ipcontrol');

  // 登录前：阻止窗口内登录
  ctx.on('handler/before/UserLogin#post', async (h: any) => {
    const uname = h.args.uname;
    let udoc = await UserModel.getByEmail(h.args.domainId, uname) || await UserModel.getByUname(h.args.domainId, uname);
    if (!udoc) return;
    const domainId = h.args.domainId || 'system';
    try {
      const { block, reason } = await shouldBlockLogin(domainId, udoc._id);
      if (block) {
        await TokenModel.delByUid(udoc._id);
        log('block pre-contest login', { uid: udoc._id, reason });
        throw new ForbiddenError(reason || '登录被 IP 控制策略阻止');
      }
    } catch (e) { err('before login hook error', e); throw e; }
  });

  // 登录后：锁定 / 校验 IP+UA
  ctx.on('handler/after/UserLogin#post', async (h: any) => {
    const uid = h.user?._id; if (!uid) return;
    const domainId = h.args.domainId || 'system';
    const ip = firstIp(h.request.ip || h.request.headers['x-forwarded-for']);
    const ua = h.request.headers['user-agent'] || '';
    try { await verifyDuringContest(domainId, uid, ip, ua); } catch (e) { if (!(e instanceof ForbiddenError)) err('after login verify error', e); throw e; }
  });
}
