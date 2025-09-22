import {
    db, Context, UserModel, Handler, NotFoundError, ForbiddenError, 
    PRIV, Types, param, ValidationError, DocumentModel
} from 'hydrooj';

// 集合定义
const ipControlSettingsColl = db.collection('ip_control_settings');
const ipControlRecordsColl = db.collection('ip_control_records');
const contestParticipantsColl = db.collection('contest_participants');

// 接口定义
interface IPControlSetting {
    _id?: any;
    contestId: any; // 比赛ID
    enabled: boolean; // 是否启用IP控制
    preContestLockMinutes: number; // 比赛开始前多少分钟锁定登录
    strictMode: boolean; // 严格模式：IP和UA都必须一致
    allowedIPs?: string[]; // 允许的IP范围（可选）
    createdAt: Date;
    createdBy: number;
    updatedAt: Date;
}

interface IPControlRecord {
    _id?: any;
    uid: number; // 用户ID
    contestId: any; // 比赛ID
    firstLoginIP: string; // 首次登录IP
    firstLoginUA: string; // 首次登录UA
    firstLoginAt: Date; // 首次登录时间
    loginCount: number; // 登录次数
    lastLoginAt: Date; // 最后登录时间
    violations: Array<{
        ip: string;
        ua: string;
        timestamp: Date;
        blocked: boolean;
    }>; // 违规记录
}

interface ContestParticipant {
    _id?: any;
    contestId: any; // 比赛ID
    uid: number; // 用户ID
    forced: boolean; // 是否强制参赛
    addedAt: Date; // 添加时间
    addedBy: number; // 添加者
}

declare module 'hydrooj' {
    interface Model {
        ipControl: typeof ipControlModel;
    }
    interface Collections {
        ip_control_settings: IPControlSetting;
        ip_control_records: IPControlRecord;
        contest_participants: ContestParticipant;
    }
}

// IP控制数据模型
const ipControlModel = {
    // 创建或更新比赛IP控制设置
    async setContestIPControl(contestId: any, settings: {
        enabled: boolean;
        preContestLockMinutes: number;
        strictMode: boolean;
        allowedIPs?: string[];
    }, operatorId: number): Promise<void> {
        const setting: IPControlSetting = {
            contestId,
            enabled: settings.enabled,
            preContestLockMinutes: settings.preContestLockMinutes || 60,
            strictMode: settings.strictMode || true,
            allowedIPs: settings.allowedIPs || [],
            createdAt: new Date(),
            createdBy: operatorId,
            updatedAt: new Date()
        };

        await ipControlSettingsColl.replaceOne(
            { contestId },
            setting,
            { upsert: true }
        );
    },

    // 获取比赛IP控制设置
    async getContestIPControl(contestId: any): Promise<IPControlSetting | null> {
        return await ipControlSettingsColl.findOne({ contestId });
    },

    // 检查用户是否参加了需要IP控制的比赛
    async getUserIPControlContests(uid: number): Promise<IPControlSetting[]> {
        // 获取用户参加的所有比赛
        const userContests = await db.collection('document.status').find({
            uid,
            docType: 30, // 比赛类型
            attend: 1
        }).toArray();

        if (userContests.length === 0) {
            return [];
        }

        const contestIds = userContests.map(contest => contest.docId);
        
        // 获取这些比赛中启用了IP控制的
        const ipControlContests = await ipControlSettingsColl.find({
            contestId: { $in: contestIds },
            enabled: true
        }).toArray();

        return ipControlContests;
    },

    // 检查比赛是否在锁定时间内
    async isContestInLockPeriod(contestId: any): Promise<boolean> {
        const documentColl = db.collection('document');
        let contest: any = null;
        
        // 尝试多种查询方式
        try {
            // 方式1: 直接查询
            contest = await documentColl.findOne({
                _id: contestId,
                docType: 30 // 比赛文档类型
            });
        } catch (error) {
            // 查询失败，继续尝试其他方式
        }
        
        // 方式2: 如果直接查询失败，尝试字符串匹配
        if (!contest) {
            try {
                const allContests = await documentColl.find({ docType: 30 }).toArray();
                
                // 尝试字符串匹配
                contest = allContests.find(c => {
                    return c._id.toString() === contestId.toString();
                }) || null;
            } catch (error) {
                // 查询失败
            }
        }

        if (!contest) {
            return false;
        }

        const setting = await this.getContestIPControl(contestId);
        if (!setting || !setting.enabled) {
            return false;
        }

        const now = new Date();
        const contestStart = new Date(contest.beginAt);
        const lockStart = new Date(contestStart.getTime() - setting.preContestLockMinutes * 60 * 1000);

        return now >= lockStart && now < contestStart;
    },

    // 检查用户是否应该被阻止登录
    async shouldBlockUserLogin(uid: number): Promise<{ blocked: boolean; reason?: string }> {
        const ipControlContests = await this.getUserIPControlContests(uid);
        
        if (ipControlContests.length === 0) {
            return { blocked: false };
        }

        // 检查是否有比赛在锁定期内
        for (const setting of ipControlContests) {
            const inLockPeriod = await this.isContestInLockPeriod(setting.contestId);
            if (inLockPeriod) {
                return { 
                    blocked: true, 
                    reason: '您参加的比赛即将开始，现在禁止登录。请在比赛开始后重新登录。' 
                };
            }
        }

        return { blocked: false };
    },

    // 记录用户登录IP和UA
    async recordUserLogin(uid: number, ip: string, ua: string): Promise<void> {
        const ipControlContests = await this.getUserIPControlContests(uid);
        
        if (ipControlContests.length === 0) {
            return;
        }

        for (const setting of ipControlContests) {
            // 检查比赛是否已开始但未结束
            const documentColl = db.collection('document');
            let contest: any = null;
            
            // 尝试多种查询方式查找比赛
            try {
                // 方式1: 直接查询
                contest = await documentColl.findOne({
                    _id: setting.contestId,
                    docType: 30 // 比赛文档类型
                });
            } catch (error) {
                // 查询失败，继续尝试其他方式
            }
            
            // 方式2: 如果直接查询失败，尝试字符串匹配
            if (!contest) {
                try {
                    const allContests = await documentColl.find({ docType: 30 }).toArray();
                    
                    // 尝试字符串匹配
                    contest = allContests.find(c => {
                        return c._id.toString() === setting.contestId.toString();
                    }) || null;
                } catch (error) {
                    // 查询失败
                }
            }

            if (!contest) continue;

            const now = new Date();
            const contestStart = new Date(contest.beginAt);
            const contestEnd = new Date(contest.endAt);

            // 只在比赛进行期间记录
            if (now >= contestStart && now <= contestEnd) {
                const existingRecord = await ipControlRecordsColl.findOne({
                    uid,
                    contestId: setting.contestId
                });

                if (existingRecord) {
                    // 更新现有记录
                    await ipControlRecordsColl.updateOne(
                        { _id: existingRecord._id },
                        {
                            $set: {
                                lastLoginAt: now
                            },
                            $inc: {
                                loginCount: 1
                            }
                        }
                    );
                } else {
                    // 创建新记录
                    await ipControlRecordsColl.insertOne({
                        uid,
                        contestId: setting.contestId,
                        firstLoginIP: ip,
                        firstLoginUA: ua,
                        firstLoginAt: now,
                        loginCount: 1,
                        lastLoginAt: now,
                        violations: []
                    });
                }
            }
        }
    },

    // 检查登录IP/UA是否与首次登录一致
    async checkLoginConsistency(uid: number, ip: string, ua: string): Promise<{ allowed: boolean; reason?: string }> {
        const ipControlContests = await this.getUserIPControlContests(uid);
        
        if (ipControlContests.length === 0) {
            return { allowed: true };
        }

        for (const setting of ipControlContests) {
            // 检查比赛是否进行中
            const documentColl = db.collection('document');
            let contest: any = null;
            
            // 尝试多种查询方式查找比赛
            try {
                // 方式1: 直接查询
                contest = await documentColl.findOne({
                    _id: setting.contestId,
                    docType: 30 // 比赛文档类型
                });
            } catch (error) {
                // 查询失败，继续尝试其他方式
            }
            
            // 方式2: 如果直接查询失败，尝试字符串匹配
            if (!contest) {
                try {
                    const allContests = await documentColl.find({ docType: 30 }).toArray();
                    
                    // 尝试字符串匹配
                    contest = allContests.find(c => {
                        return c._id.toString() === setting.contestId.toString();
                    }) || null;
                } catch (error) {
                    // 查询失败
                }
            }

            if (!contest) continue;

            const now = new Date();
            const contestStart = new Date(contest.beginAt);
            const contestEnd = new Date(contest.endAt);

            // 只在比赛进行期间检查
            if (now >= contestStart && now <= contestEnd) {
                const record = await ipControlRecordsColl.findOne({
                    uid,
                    contestId: setting.contestId
                });

                if (record) {
                    const ipMatches = record.firstLoginIP === ip;
                    const uaMatches = record.firstLoginUA === ua;

                    if (setting.strictMode) {
                        // 严格模式：IP和UA都必须一致
                        if (!ipMatches || !uaMatches) {
                            // 记录违规
                            await ipControlRecordsColl.updateOne(
                                { _id: record._id },
                                {
                                    $push: {
                                        violations: {
                                            ip,
                                            ua,
                                            timestamp: now,
                                            blocked: true
                                        }
                                    }
                                }
                            );

                            return {
                                allowed: false,
                                reason: `检测到您的登录环境发生变化，为保证比赛公平性，禁止登录。首次登录IP: ${record.firstLoginIP}，当前IP: ${ip}`
                            };
                        }
                    } else {
                        // 宽松模式：只检查IP
                        if (!ipMatches) {
                            // 记录违规
                            await ipControlRecordsColl.updateOne(
                                { _id: record._id },
                                {
                                    $push: {
                                        violations: {
                                            ip,
                                            ua,
                                            timestamp: now,
                                            blocked: true
                                        }
                                    }
                                }
                            );

                            return {
                                allowed: false,
                                reason: `检测到您的IP地址发生变化，为保证比赛公平性，禁止登录。首次登录IP: ${record.firstLoginIP}，当前IP: ${ip}`
                            };
                        }
                    }
                }
            }
        }

        return { allowed: true };
    },

    // 强制用户参加比赛
    async forceUserToContest(contestId: any, uids: number[], operatorId: number): Promise<{ success: number; failed: number[] }> {
        let success = 0;
        const failed: number[] = [];

        for (const uid of uids) {
            try {
                // 检查用户是否存在
                const user = await UserModel.getById('system', uid);
                if (!user) {
                    failed.push(uid);
                    continue;
                }

                // 检查是否已经参加
                const existingStatus = await db.collection('document.status').findOne({
                    docType: 30,
                    uid,
                    docId: contestId
                });

                if (!existingStatus) {
                    // 创建参赛状态
                    await db.collection('document.status').insertOne({
                        docType: 30,
                        uid,
                        domainId: 'system',
                        docId: contestId,
                        attend: 1,
                        subscribe: 1
                    });

                    // 更新比赛参与人数
                    await db.collection('document').updateOne(
                        { _id: contestId, docType: 30 },
                        { $inc: { attend: 1 } }
                    );
                } else if (existingStatus.attend !== 1) {
                    // 更新现有状态
                    await db.collection('document.status').updateOne(
                        { _id: existingStatus._id },
                        { $set: { attend: 1, subscribe: 1 } }
                    );

                    // 更新比赛参与人数（如果之前没有参加）
                    await db.collection('document').updateOne(
                        { _id: contestId, docType: 30 },
                        { $inc: { attend: 1 } }
                    );
                }

                // 记录强制参赛信息
                await contestParticipantsColl.replaceOne(
                    { contestId, uid },
                    {
                        contestId,
                        uid,
                        forced: true,
                        addedAt: new Date(),
                        addedBy: operatorId
                    },
                    { upsert: true }
                );

                success++;
            } catch (error) {
                failed.push(uid);
            }
        }

        return { success, failed };
    },

    // 获取比赛的强制参赛用户列表
    async getForcedParticipants(contestId: any): Promise<any[]> {
        const participants = await contestParticipantsColl.find({
            contestId,
            forced: true
        }).toArray();

        const result: any[] = [];
        for (const participant of participants) {
            const user = await UserModel.getById('system', participant.uid);
            if (user) {
                result.push({
                    uid: participant.uid,
                    uname: user.uname,
                    addedAt: participant.addedAt,
                    addedBy: participant.addedBy
                });
            }
        }

        return result;
    },

    // 移除强制参赛用户
    async removeForcedParticipant(contestId: any, uid: number): Promise<void> {
        // 移除强制参赛记录
        await contestParticipantsColl.deleteOne({
            contestId,
            uid,
            forced: true
        });

        // 移除参赛状态
        const statusResult = await db.collection('document.status').deleteOne({
            docType: 30,
            uid,
            docId: contestId
        });

        // 如果成功移除状态，更新比赛参与人数
        if (statusResult.deletedCount > 0) {
            await db.collection('document').updateOne(
                { _id: contestId, docType: 30 },
                { $inc: { attend: -1 } }
            );
        }
    },

    // 获取IP控制违规记录
    async getViolationRecords(contestId?: any, page: number = 1, limit: number = 20): Promise<{
        records: any[];
        total: number;
        pageCount: number;
    }> {
        const skip = (page - 1) * limit;
        let query: any = {};

        if (contestId) {
            query.contestId = contestId;
        }

        // 只查询有违规记录的
        query['violations.0'] = { $exists: true };

        const total = await ipControlRecordsColl.countDocuments(query);
        const records = await ipControlRecordsColl.find(query)
            .sort({ lastLoginAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();

        // 补充用户信息和比赛信息
        for (const record of records) {
            const user = await UserModel.getById('system', record.uid);
            (record as any).user = user ? { _id: user._id, uname: user.uname } : null;

            const contest = await db.collection('document').findOne({
                _id: record.contestId,
                docType: 30
            });
            (record as any).contest = contest ? { _id: contest._id, title: contest.title } : null;
        }

        return {
            records,
            total,
            pageCount: Math.ceil(total / limit)
        };
    },

    // 清除用户登录Token（强制下线）
    async clearUserTokens(uid: number): Promise<void> {
        await db.collection('token').deleteMany({ 
            uid, 
            tokenType: 0  // 登录token类型
        });
    },

    // 获取所有启用IP控制的比赛
    async getIPControlContests(): Promise<any[]> {
        const settings = await ipControlSettingsColl.find({ enabled: true }).toArray();
        const result: any[] = [];

        for (const setting of settings) {
            const documentColl = db.collection('document');
            let contest: any = null;
            
            // 尝试多种查询方式查找比赛
            try {
                // 方式1: 直接查询
                contest = await documentColl.findOne({
                    _id: setting.contestId,
                    docType: 30 // 比赛文档类型
                });
            } catch (error) {
                // 查询失败，继续尝试其他方式
            }
            
            // 方式2: 如果直接查询失败，尝试字符串匹配
            if (!contest) {
                try {
                    const allContests = await documentColl.find({ docType: 30 }).toArray();
                    
                    // 尝试字符串匹配
                    contest = allContests.find(c => {
                        return c._id.toString() === setting.contestId.toString();
                    }) || null;
                } catch (error) {
                    // 查询失败
                }
            }

            if (contest) {
                result.push({
                    contestId: setting.contestId,
                    title: contest.title,
                    beginAt: contest.beginAt,
                    endAt: contest.endAt,
                    setting
                });
            }
        }

        return result;
    }
};

global.Hydro.model.ipControl = ipControlModel;

// IP控制管理主页
class IPControlMainHandler extends Handler {
    async get() {
        this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
        
        // 获取所有启用IP控制的比赛
        const ipControlContests = await ipControlModel.getIPControlContests();
        
        // 获取最近的违规记录
        const { records: recentViolations } = await ipControlModel.getViolationRecords(undefined, 1, 10);
        
        this.response.template = 'ip_control_main.html';
        this.response.body = {
            ipControlContests,
            recentViolations
        };
    }
}

// 比赛IP控制设置
class ContestIPControlHandler extends Handler {
    async get() {
        this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
        const { contestId } = this.request.params;
        
        if (!contestId) {
            throw new NotFoundError('比赛ID无效');
        }

        // 获取比赛信息
        const documentColl = db.collection('document');
        let contest: any = null;
        
        // 尝试多种查询方式查找比赛
        try {
            // 方式1: 直接查询
            contest = await documentColl.findOne({
                _id: contestId,
                docType: 30 // 比赛文档类型
            });
        } catch (error) {
            // 查询失败，继续尝试其他方式
        }
        
        // 方式2: 如果直接查询失败，尝试字符串匹配
        if (!contest) {
            try {
                const allContests = await documentColl.find({ docType: 30 }).toArray();
                
                // 尝试字符串匹配
                contest = allContests.find(c => {
                    return c._id.toString() === contestId.toString();
                }) || null;
            } catch (error) {
                // 查询失败
            }
        }

        if (!contest) {
            throw new NotFoundError('比赛不存在');
        }

        // 获取IP控制设置
        const setting = await ipControlModel.getContestIPControl(contestId);

        // 获取强制参赛用户列表
        const forcedParticipants = await ipControlModel.getForcedParticipants(contestId);

        // 检查是否有成功消息
        const { success, message } = this.request.query;

        this.response.template = 'contest_ip_control.html';
        this.response.body = {
            contest,
            setting: setting || {
                enabled: false,
                preContestLockMinutes: 60,
                strictMode: true,
                allowedIPs: []
            },
            forcedParticipants,
            success: success === '1',
            message: message ? decodeURIComponent(message as string) : null
        };
    }

    async post() {
        this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
        const { contestId } = this.request.params;
        const { 
            action, 
            enabled, 
            preContestLockMinutes, 
            strictMode, 
            allowedIPs,
            uidsText,
            uidToRemove
        } = this.request.body;

        if (!contestId) {
            throw new NotFoundError('比赛ID无效');
        }

        try {
            if (action === 'save_settings') {
                // 保存IP控制设置
                const settings = {
                    enabled: enabled === 'true',
                    preContestLockMinutes: parseInt(preContestLockMinutes) || 60,
                    strictMode: strictMode === 'true',
                    allowedIPs: allowedIPs ? allowedIPs.split('\n').map((ip: string) => ip.trim()).filter(Boolean) : []
                };

                await ipControlModel.setContestIPControl(contestId, settings, this.user._id);

                this.response.redirect = `/contest/${contestId}/ip-control?success=1&message=${encodeURIComponent('IP控制设置已保存')}`;
                
            } else if (action === 'add_participants') {
                // 添加强制参赛用户
                if (!uidsText || !uidsText.trim()) {
                    throw new Error('请输入用户ID列表');
                }

                const uids: number[] = [];
                const lines = uidsText.trim().split('\n');
                
                for (const line of lines) {
                    const uid = parseInt(line.trim());
                    if (!isNaN(uid) && uid > 0) {
                        uids.push(uid);
                    }
                }

                if (uids.length === 0) {
                    throw new Error('没有有效的用户ID');
                }

                const result = await ipControlModel.forceUserToContest(contestId, uids, this.user._id);

                let message = `成功添加 ${result.success} 个用户`;
                if (result.failed.length > 0) {
                    message += `，失败 ${result.failed.length} 个：${result.failed.join(', ')}`;
                }

                this.response.redirect = `/contest/${contestId}/ip-control?success=1&message=${encodeURIComponent(message)}`;
                
            } else if (action === 'remove_participant') {
                // 移除强制参赛用户
                if (!uidToRemove) {
                    throw new Error('请指定要移除的用户ID');
                }

                const uid = parseInt(uidToRemove);
                if (isNaN(uid)) {
                    throw new Error('用户ID无效');
                }

                await ipControlModel.removeForcedParticipant(contestId, uid);

                this.response.redirect = `/contest/${contestId}/ip-control?success=1&message=${encodeURIComponent('用户已移除')}`;
            }

        } catch (error: any) {
            const documentColl = db.collection('document');
            let contest: any = null;
            
            // 尝试多种查询方式查找比赛
            try {
                // 方式1: 直接查询
                contest = await documentColl.findOne({
                    _id: contestId,
                    docType: 30 // 比赛文档类型
                });
            } catch (err) {
                // 查询失败，继续尝试其他方式
            }
            
            // 方式2: 如果直接查询失败，尝试字符串匹配
            if (!contest) {
                try {
                    const allContests = await documentColl.find({ docType: 30 }).toArray();
                    
                    // 尝试字符串匹配
                    contest = allContests.find(c => {
                        return c._id.toString() === contestId.toString();
                    }) || null;
                } catch (err) {
                    // 查询失败
                }
            }

            const setting = await ipControlModel.getContestIPControl(contestId);
            const forcedParticipants = await ipControlModel.getForcedParticipants(contestId);

            this.response.template = 'contest_ip_control.html';
            this.response.body = {
                contest,
                setting: setting || {
                    enabled: false,
                    preContestLockMinutes: 60,
                    strictMode: true,
                    allowedIPs: []
                },
                forcedParticipants,
                error: error.message,
                formData: this.request.body
            };
        }
    }
}

// 违规记录查看
class ViolationRecordsHandler extends Handler {
    async get() {
        this.checkPriv(PRIV.PRIV_EDIT_SYSTEM);
        
        const page = +(this.request.query.page || '1');
        const contestId = this.request.query.contestId as string;
        
        const { records, total, pageCount } = await ipControlModel.getViolationRecords(
            contestId, page, 20
        );

        // 获取所有启用IP控制的比赛（用于筛选）
        const ipControlContests = await ipControlModel.getIPControlContests();

        this.response.template = 'violation_records.html';
        this.response.body = {
            records,
            total,
            pageCount,
            page,
            selectedContestId: contestId,
            ipControlContests
        };
    }
}

// 注册路由和事件监听器
export function apply(ctx: Context) {
    // 注册模型
    global.Hydro.model.ipControl = ipControlModel;

    // 注册路由
    ctx.Route('ip_control_main', '/ip-control', IPControlMainHandler, PRIV.PRIV_EDIT_SYSTEM);
    ctx.Route('contest_ip_control', '/contest/:contestId/ip-control', ContestIPControlHandler, PRIV.PRIV_EDIT_SYSTEM);
    ctx.Route('violation_records', '/ip-control/violations', ViolationRecordsHandler, PRIV.PRIV_EDIT_SYSTEM);

    // 监听用户登录前事件 - 检查是否在锁定期
    ctx.on('handler/before/UserLogin#post', async (that) => {
        const { uname } = that.args;
        
        // 获取用户信息
        let udoc = await UserModel.getByEmail(that.args.domainId, uname);
        if (!udoc) {
            const user = await UserModel.getByUname(that.args.domainId, uname);
            if (user) udoc = user;
        }
        
        if (udoc) {
            // 检查是否应该阻止登录
            const { blocked, reason } = await ipControlModel.shouldBlockUserLogin(udoc._id);
            if (blocked) {
                throw new ForbiddenError(reason || '登录被阻止');
            }
        }
    });

    // 监听用户登录后事件 - 记录IP和检查一致性
    ctx.on('handler/after/UserLogin#post', async (that) => {
        if (that.response.redirect && that.user) {
            const ip = that.request.ip;
            const ua = that.request.headers['user-agent'] || '';
            
            // 检查登录一致性
            const { allowed, reason } = await ipControlModel.checkLoginConsistency(
                that.user._id, ip, ua
            );
            
            if (!allowed) {
                // 清除登录Token，强制下线
                await ipControlModel.clearUserTokens(that.user._id);
                throw new ForbiddenError(reason || '登录环境检查失败');
            }
            
            // 记录登录信息
            await ipControlModel.recordUserLogin(that.user._id, ip, ua);
        }
    });

    // 监听比赛参加事件 - 检查IP控制参赛权限
    ctx.on('handler/before/ContestDetailHandler#postAttend', async (that) => {
        const { domainId, tid: contestId } = that.args;
        const userId = that.user._id;
        
        // 检查比赛是否启用了IP控制
        const setting = await ipControlModel.getContestIPControl(contestId);
        if (setting && setting.enabled) {
            // 如果启用了IP控制，检查用户是否在强制参赛列表中
            const forcedParticipant = await contestParticipantsColl.findOne({
                contestId,
                uid: userId,
                forced: true
            });
            
            if (!forcedParticipant) {
                throw new ForbiddenError('此比赛启用了IP控制，只有被管理员添加的用户才能参加');
            }
        }
    });

    // 定时任务：清理过期的登录状态
    setTimeout(async () => {
        setInterval(async () => {
            try {
                // 获取所有启用IP控制的比赛
                const ipControlContests = await ipControlModel.getIPControlContests();
                
                for (const { contestId, setting } of ipControlContests) {
                    const inLockPeriod = await ipControlModel.isContestInLockPeriod(contestId);
                    
                    if (inLockPeriod) {
                        // 在锁定期内，清除所有参赛用户的登录状态
                        const participants = await db.collection('document.status').find({
                            docType: 30,
                            docId: contestId,
                            attend: 1
                        }).toArray();
                        
                        for (const participant of participants) {
                            await ipControlModel.clearUserTokens(participant.uid);
                        }
                    }
                }
            } catch (error) {
                console.error('IP控制定时任务执行失败:', error);
            }
        }, 5 * 60 * 1000); // 每5分钟执行一次
    }, 10000); // 10秒后开始执行

    // 添加导航菜单
    ctx.inject(['ui'], (c) => {
        c.injectUI('Notification', 'IP控制', { type: 'info' });
    });
}
