import { Context, Handler, PRIV, ForbiddenError, TokenModel, UserModel } from 'hydrooj';
// document 未从根导出，仍用 global 访问
const document = (global as any).Hydro.model.document;

// 扩展 hydrooj 集合类型
declare module 'hydrooj' {
  interface Collections {
    ipcontrol_login: IpLockDoc;
  }
}

// 记录首登 IP/UA 的集合 (直接使用底层 db 以免污染核心集合)
const ipLockColl = (global as any).Hydro.db.collection('ipcontrol_login');

interface IpLockDoc {
  _id?: string; // contestId + ':' + uid
  contestId: any;
  uid: number;
  ip: string;
  ua: string;
  createdAt: Date;
  updatedAt: Date;
}

// 工具函数
async function getContest(domainId: string, contestId: any) {
  return await document.get(domainId, document.TYPE_CONTEST, contestId);
}

async function listActiveIpControlContests(domainId: string) {
  const now = new Date();
  return await document.getMulti(domainId, document.TYPE_CONTEST, { ipControlEnabled: true, endAt: { $gt: now } }).toArray();
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
  const contests = await listActiveIpControlContests(domainId);
  if (!contests.length) return { block: false };
  const now = Date.now();
  const contestIds = contests.map(c => c.docId);
  const attended = await document.getMultiStatus(domainId, document.TYPE_CONTEST, { uid, docId: { $in: contestIds }, attend: 1 }).project({ docId: 1 }).toArray();
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
  const contests = await listActiveIpControlContests(domainId);
  if (!contests.length) return;
  const now = Date.now();
  const contestIds = contests.map(c => c.docId);
  const attended = await document.getMultiStatus(domainId, document.TYPE_CONTEST, { uid, docId: { $in: contestIds }, attend: 1 }).project({ docId: 1 }).toArray();
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
      } else if (lock.ip !== ip || lock.ua !== ua) {
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
  const contest = await getContest(domainId, contestId);
    if (!contest) throw new ForbiddenError('比赛不存在');
  const imported = await document.countStatus(domainId, document.TYPE_CONTEST, { docId: contest.docId, attend: 1 });
    this.response.template = 'ipcontrol_contest_manage.html';
    this.response.body = { contest, imported };
  }
  async post(domainId: string) {
    this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
    const { contestId } = this.request.params;
  const contest = await getContest(domainId, contestId);
    if (!contest) throw new ForbiddenError('比赛不存在');
    const { action, enabled, uidsText } = this.request.body;
    if (action === 'toggle') {
  await document.set(domainId, document.TYPE_CONTEST, contest.docId, { ipControlEnabled: enabled === 'true' } as any);
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    if (action === 'import_uids') {
      const list: number[] = [];
      (uidsText || '').split(/[\s,;]+/).forEach((t: string) => { if (/^\d+$/.test(t)) list.push(+t); });
      for (const uid of list) {
        await document.setStatus(domainId, document.TYPE_CONTEST, contest.docId, uid, { attend: 1, subscribe: 1 } as any);
      }
      this.response.redirect = `/contest/${contestId}/ipcontrol`;
      return;
    }
    this.response.redirect = `/contest/${contestId}/ipcontrol`;
  }
}

export function apply(ctx: Context) {
  ctx.Route('ipcontrol_contest_manage', '/contest/:contestId/ipcontrol', IpControlContestHandler, PRIV.PRIV_EDIT_SYSTEM);
  ctx.on('handler/before/UserLogin#post', async (that: any) => {
    const unameOrEmail = that.args.uname;
    const UserModel = (global as any).Hydro.model.user;
    let udoc = await UserModel.getByEmail(that.args.domainId, unameOrEmail);
    if (!udoc) udoc = await UserModel.getByUname(that.args.domainId, unameOrEmail);
    if (!udoc) return;
  const { block, reason } = await shouldBlockLogin(that.args.domainId, udoc._id);
    if (block) {
  await TokenModel.delByUid(udoc._id); // 删除所有 token
      throw new ForbiddenError(reason || '登录被 IP 控制策略阻止');
    }
  });
  ctx.on('handler/after/UserLogin#post', async (that: any) => {
    const uid = that.user?._id;
    if (!uid) return;
    const ip = normIp(that.request.ip || that.request.headers['x-forwarded-for']);
    const ua = that.request.headers['user-agent'] || '';
  await verifyContestIpUa(that.args.domainId, uid, ip, ua);
  });
}
