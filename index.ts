import { Context, Handler, PRIV, ForbiddenError, TokenModel, UserModel } from 'hydrooj';

// 延迟初始化引用
let documentModel: any; // 在 apply 中赋值
let ipLockColl: any;    // 在 apply 中赋值
let db: any;            // 保存 ctx.db 引用用于回退原始查询
let ipLockIndexesEnsured = false;

// 简单日志（通过环境变量 IPCONTROL_LOG 启用）
const IPC_LOG_ENABLED = process.env.IPCONTROL_LOG === '1';
function iplog(...args: any[]) { if (IPC_LOG_ENABLED) console.log('[IPControl]', ...args); }

// 扩展 hydrooj 集合类型
declare module 'hydrooj' {
  interface Collections {
    ipcontrol_login: IpLockDoc;
  }
}

// ipLockColl 将在 apply(ctx) 中通过 ctx.db.collection 获取

interface IpLockDoc {
  _id?: string;          // contestId + ':' + uid
  contestId: any;        // contest docId
  uid: number;           // 用户 ID
  ip: string;            // 记录的首登 IP
  ua: string;            // 记录的首登 UA
  createdAt: Date;
  updatedAt: Date;
}

// 工具函数
// 去掉对 mongodb 包的直接依赖，Hydro 环境未必为插件单独提供该模块。
// 如果后续需要真正的 ObjectId，可考虑 (global as any).Hydro.db?.bson?.ObjectId 动态获取。
function tryCastObjectId(id: any) {
  if (typeof id === 'string' && /^[0-9a-fA-F]{24}$/.test(id)) {
    console.log('[IPControl] treat id as hex ObjectId string (no cast)', id);
    return id; // 直接返回字符串，交给底层 model 自行处理
  }
  return id;
}

async function getContest(domainId: string, contestId: any) {
  if (!documentModel) {
    console.log('[IPControl] getContest: documentModel not ready');
    return null;
  }
  const normalizeDomainId = (d: any) => (typeof d === 'string' ? d : (d?.domainId || 'system'));
  const domainIdStr = normalizeDomainId(domainId as any);
  const original = contestId;
  const casted = tryCastObjectId(contestId);
  console.log('[IPControl] getContest start', { domainIdParam: domainId, domainIdStr, original: String(original), casted: casted?.toString?.() });
  let found = await documentModel.get(domainIdStr, documentModel.TYPE_CONTEST, casted);
  if (!found && casted !== original) {
    console.log('[IPControl] retry with original id (cast differed)');
    found = await documentModel.get(domainIdStr, documentModel.TYPE_CONTEST, original);
  }
  // 回退 1：直接在 document 集合按 _id 查找 (hex 24)
  if (!found && typeof original === 'string' && /^[0-9a-fA-F]{24}$/.test(original) && db) {
    try {
      const OID = (global as any).Hydro?.db?.bson?.ObjectId;
      const oidVal = OID ? new OID(original) : original;
      const raw = await db.collection('document').findOne({ _id: oidVal, type: documentModel.TYPE_CONTEST });
      if (raw) {
        console.log('[IPControl] fallback raw _id match found');
        found = raw;
      } else {
        console.log('[IPControl] fallback raw _id match not found');
      }
    } catch (e) {
      console.log('[IPControl] fallback raw _id query error', e);
    }
  }
  // 回退 2：若 id 是纯数字，尝试数字 docId
  if (!found && typeof original === 'string' && /^\d+$/.test(original)) {
    const numId = Number(original);
    try {
      console.log('[IPControl] retry numeric docId', numId);
      found = await documentModel.get(domainIdStr, documentModel.TYPE_CONTEST, numId);
    } catch (e) {
      console.log('[IPControl] numeric docId query error', e);
    }
  }
  if (!found) console.log('[IPControl] getContest not found', { domainIdStr, contestId: String(casted) });
  else console.log('[IPControl] getContest success', { domainIdStr, _id: found._id?.toString?.(), docId: found.docId?.toString?.(), title: found.title, beginAt: found.beginAt, endAt: found.endAt, ipControlEnabled: found.ipControlEnabled });
  return found;
}

async function listActiveIpControlContests(domainId: string) {
  if (!documentModel) return [];
  const now = new Date();
  return await documentModel.getMulti(
    domainId,
    documentModel.TYPE_CONTEST,
    { ipControlEnabled: true, endAt: { $gt: now } },
  ).toArray();
}

// 解析请求 IP
function normIp(raw?: string): string {
  if (!raw) return '';
  // 可能是 x-forwarded-for 多个逗号
  const first = raw.split(',')[0].trim();
  return first.includes(':') ? first.split(':')[0] : first; // 去掉端口
}

// 登录限制逻辑
async function shouldBlockLogin(domainId: string, uid: number): Promise<{ block: boolean; reason?: string }> {
  if (!documentModel) return { block: false };
  const contests = await listActiveIpControlContests(domainId);
  if (!contests.length) return { block: false };
  const now = Date.now();
  const contestIds = contests.map(c => c.docId);
  const attended = await documentModel.getMultiStatus(domainId, documentModel.TYPE_CONTEST, { uid, docId: { $in: contestIds }, attend: 1 }).project({ docId: 1 }).toArray();
  if (!attended.length) return { block: false };
  for (const c of contests) {
  const begin = new Date(c.beginAt).getTime();
    if (now < begin && now >= begin - 60 * 60 * 1000) {
  const a = attended.find(x => x.docId.toString() === c.docId.toString());
      if (a) return { block: true, reason: '比赛开始前一小时禁止登录（IP控制）' };
    }
  }
  return { block: false };
}

// 比赛期间 IP/UA 校验
async function verifyContestIpUa(domainId: string, uid: number, ip: string, ua: string) {
  if (!documentModel) return;
  const contests = await listActiveIpControlContests(domainId);
  if (!contests.length) return;
  const now = Date.now();
  const contestIds = contests.map(c => c.docId);
  const attended = await documentModel.getMultiStatus(domainId, documentModel.TYPE_CONTEST, { uid, docId: { $in: contestIds }, attend: 1 }).project({ docId: 1 }).toArray();
  if (!attended.length) return;
  for (const c of contests) {
  const begin = new Date(c.beginAt).getTime();
  const end = new Date(c.endAt).getTime();
    if (now >= begin && now <= end) {
  const isAttend = attended.find(x => x.docId.toString() === c.docId.toString());
      if (!isAttend) continue;
  const key = `${c.docId}:${uid}`;
      let lock = await ipLockColl.findOne({ _id: key }) as IpLockDoc | null;
      if (!lock) {
        lock = { _id: key, contestId: c.docId, uid, ip, ua, createdAt: new Date(), updatedAt: new Date() };
        await ipLockColl.insertOne(lock);
        iplog('Bind', { contest: c.docId.toString(), uid, ip, ua });
      } else if (lock.ip !== ip || lock.ua !== ua) {
        iplog('Reject change', { contest: c.docId.toString(), uid, oldIp: lock.ip, newIp: ip, oldUa: lock.ua, newUa: ua });
        throw new ForbiddenError('IP/UA 与首次登录不一致，已启用比赛 IP 控制');
      }
    }
  }
}

// 管理界面
class IpControlContestHandler extends Handler {
  async get(domainId: string) {
    this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
    const { contestId } = this.request.params;
  console.log('[IPControl] Route GET /ipcontrol params', { contestId, domainId });
  const contest = await getContest(domainId, contestId);
    if (!contest) throw new ForbiddenError('比赛不存在');
    const imported = await documentModel.countStatus(domainId, documentModel.TYPE_CONTEST, { docId: contest.docId, attend: 1 });
    this.response.template = 'ipcontrol_contest_manage.html';
    this.response.body = { contest, imported };
  }
  async post(domainId: string) {
    this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
    const { contestId } = this.request.params;
  console.log('[IPControl] Route POST /ipcontrol params', { contestId, domainId, body: this.request.body });
  const contest = await getContest(domainId, contestId);
    if (!contest) throw new ForbiddenError('比赛不存在');
    const { action, enabled, uidsText } = this.request.body;
    if (action === 'toggle') {
      await documentModel.set(domainId, documentModel.TYPE_CONTEST, contest.docId, { ipControlEnabled: enabled === 'true' } as any);
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    if (action === 'clear_locks') {
      await ipLockColl.deleteMany({ contestId: contest.docId });
      iplog('Cleared locks for contest', contest.docId.toString());
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    if (action === 'import_uids') {
      const list: number[] = [];
      (uidsText || '').split(/[\s,;]+/).forEach((t: string) => { if (/^\d+$/.test(t)) list.push(+t); });
      for (const uid of list) {
        await documentModel.setStatus(domainId, documentModel.TYPE_CONTEST, contest.docId, uid, { attend: 1, subscribe: 1 } as any);
      }
      iplog('Import attend list', { contest: contest.docId.toString(), count: list.length });
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    this.response.redirect = `/contest/${contestId}/ipcontrol`;
  }
}

export async function apply(ctx: Context) {
  // 初始化依赖的 model / collection
  if (!documentModel) documentModel = (global as any).Hydro?.model?.document || (global as any).Hydro?.model?.doc || (global as any).Hydro?.model?.Document;
  if (!documentModel) {
    console.error('[IPControl] document model not found, plugin disabled');
    return; // 直接退出，避免后续调用 undefined
  }
  if (!ipLockColl) {
    ipLockColl = ctx.db.collection('ipcontrol_login');
  console.log('[IPControl] ipLock collection ready');
  }
  if (!db) db = ctx.db;
  if (!ipLockIndexesEnsured) {
    try {
      await ctx.db.ensureIndexes(
        ipLockColl,
        { key: { contestId: 1, uid: 1 }, name: 'contest_user' },
        { key: { createdAt: 1 }, name: 'createdAt' },
      );
      ipLockIndexesEnsured = true;
    } catch (e) {
      console.error('[IPControl] ensure index failed', e);
    }
  }
  iplog('Plugin initialized');
  ctx.Route('ipcontrol_contest_manage', '/contest/:contestId/ipcontrol', IpControlContestHandler, PRIV.PRIV_EDIT_SYSTEM);
  console.log('[IPControl] Route registered: /contest/:contestId/ipcontrol');
  ctx.on('handler/before/UserLogin#post', async (that: any) => {
    const unameOrEmail = that.args.uname;
  let udoc = await UserModel.getByEmail(that.args.domainId, unameOrEmail) || await UserModel.getByUname(that.args.domainId, unameOrEmail);
  if (!udoc) return;
    const domainId = that.args.domainId || 'system';
    const { block, reason } = await shouldBlockLogin(domainId, udoc._id);
    if (block) {
      await TokenModel.delByUid(udoc._id); // 删除所有 token
      iplog('Block login (pre-contest window)', { uid: udoc._id, reason });
      throw new ForbiddenError(reason || '登录被 IP 控制策略阻止');
    }
  });
  ctx.on('handler/after/UserLogin#post', async (that: any) => {
    const uid = that.user?._id;
    if (!uid) return;
    const ip = normIp(that.request.ip || that.request.headers['x-forwarded-for']);
    const ua = that.request.headers['user-agent'] || '';
    const domainId = that.args.domainId || 'system';
    try {
      await verifyContestIpUa(domainId, uid, ip, ua);
    } catch (e) {
      // 若抛出 ForbiddenError 让框架处理
      if (!(e instanceof ForbiddenError)) console.error('[IPControl] verify error', e);
      throw e;
    }
  });
}
