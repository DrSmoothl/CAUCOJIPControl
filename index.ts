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
    type?: string; // 记录类型：'login' | 'violation'
    firstLoginIP?: string; // 首次登录IP
    firstLoginUA?: string; // 首次登录UA
    firstLoginAt?: Date; // 首次登录时间
    loginCount?: number; // 登录次数
    lastLoginAt?: Date; // 最后登录时间
    ip?: string; // 当前IP（用于违规记录）
    userAgent?: string; // 当前UA（用于违规记录）
    timestamp?: Date; // 时间戳（用于违规记录）
    details?: any; // 详细信息（用于违规记录）
    violations?: Array<{
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
    firstLoginIP?: string; // 首次登录IP
    firstLoginUA?: string; // 首次登录UA
    firstLoginAt?: Date; // 首次登录时间
    lastLoginAt?: Date; // 最后登录时间
    loginCount?: number; // 登录次数
    violationCount?: number; // 违规次数
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
        const contestIdStr = contestId.toString();
        console.log('[IPControl] getContestIPControl: 查询比赛IP控制设置, contestId:', contestId, 'contestIdStr:', contestIdStr);
        const setting = await ipControlSettingsColl.findOne({ contestId: contestIdStr });
        console.log('[IPControl] getContestIPControl: 找到设置:', setting ? '是' : '否', setting);
        return setting;
    },

    // 检查用户是否参加了需要IP控制的比赛
    async getUserIPControlContests(uid: number): Promise<IPControlSetting[]> {
        // 获取用户参加的所有比赛
        const userContests = await db.collection('document.status').find({
            uid,
            docType: 30, // 比赛类型
            attend: 1
        }).toArray();

        console.log(`[IPControl] getUserIPControlContests: 用户 ${uid} 参加的比赛:`, userContests.map(c => c.docId));

        if (userContests.length === 0) {
            return [];
        }

        const contestIds = userContests.map(contest => contest.docId.toString());
        console.log(`[IPControl] getUserIPControlContests: 转换后的contestIds:`, contestIds);
        
        // 获取这些比赛中启用了IP控制的
        const ipControlContests = await ipControlSettingsColl.find({
            contestId: { $in: contestIds },
            enabled: true
        }).toArray();

        console.log(`[IPControl] getUserIPControlContests: 启用IP控制的比赛:`, ipControlContests);

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

    // 记录用户违规行为
    async recordViolation(uid: number, contestId: any, ip: string, ua: string, details: any): Promise<void> {
        try {
            console.log('[IPControl] recordViolation: 记录违规行为, uid:', uid, 'contestId:', contestId, 'ip:', ip, 'details:', details);
            // 记录到违规记录集合
            await ipControlRecordsColl.insertOne({
                uid,
                contestId,
                type: 'violation',
                ip,
                userAgent: ua,
                timestamp: new Date(),
                details
            });
            console.log('[IPControl] recordViolation: 违规记录插入成功');

            // 更新参赛者的违规次数
            const updateResult = await contestParticipantsColl.updateOne(
                { contestId, uid },
                { 
                    $inc: { violationCount: 1 },
                    $push: { 
                        violations: {
                            ip,
                            ua,
                            timestamp: new Date(),
                            blocked: true
                        }
                    }
                },
                { upsert: true }
            );
            console.log('[IPControl] recordViolation: 参赛者违规次数更新结果:', updateResult);

            console.log(`[IPControl] 记录用户 ${uid} 在比赛 ${contestId} 中的违规行为: ${details.reason}`);
        } catch (error) {
            console.error('[IPControl] recordViolation: 记录违规行为失败:', error);
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
                    addedAtFormatted: new Date(participant.addedAt).toLocaleString('zh-CN'),
                    addedBy: participant.addedBy
                });
            }
        }

        return result;
    },

    // 获取比赛的所有用户登录记录（供管理员查看）
    async getContestLoginRecords(contestId: any): Promise<any[]> {
        const records = await ipControlRecordsColl.find({
            contestId
        }).toArray();

        const result: any[] = [];
        for (const record of records) {
            const user = await UserModel.getById('system', record.uid);
            if (user) {
                result.push({
                    uid: record.uid,
                    uname: user.uname,
                    firstLoginIP: record.firstLoginIP,
                    firstLoginUA: record.firstLoginUA,
                    firstLoginAtFormatted: record.firstLoginAt ? new Date(record.firstLoginAt).toLocaleString('zh-CN') : '未知',
                    loginCount: record.loginCount || 0,
                    lastLoginAtFormatted: record.lastLoginAt ? new Date(record.lastLoginAt).toLocaleString('zh-CN') : '未知',
                    violationCount: record.violations ? record.violations.length : 0
                });
            }
        }

        return result;
    },

    // 删除用户的登录记录（允许换设备）
    async clearUserLoginRecord(contestId: any, uid: number): Promise<void> {
        await ipControlRecordsColl.deleteOne({
            contestId,
            uid
        });
    },

    // 批量删除用户的登录记录
    async clearMultipleUserLoginRecords(contestId: any, uids: number[]): Promise<{ success: number; failed: number[] }> {
        let success = 0;
        const failed: number[] = [];

        for (const uid of uids) {
            try {
                const result = await ipControlRecordsColl.deleteOne({
                    contestId,
                    uid
                });
                if (result.deletedCount > 0) {
                    success++;
                } else {
                    failed.push(uid);
                }
            } catch (error) {
                failed.push(uid);
            }
        }

        return { success, failed };
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
            
            // 格式化时间数据
            (record as any).firstLoginAtFormatted = record.firstLoginAt ? new Date(record.firstLoginAt).toLocaleString('zh-CN') : '未知';
            (record as any).lastLoginAtFormatted = record.lastLoginAt ? new Date(record.lastLoginAt).toLocaleString('zh-CN') : '未知';
            
            // 格式化违规记录中的时间
            if (record.violations && record.violations.length > 0) {
                (record as any).violations = record.violations.map((violation: any) => ({
                    ...violation,
                    timestampFormatted: new Date(violation.timestamp).toLocaleString('zh-CN')
                }));
                (record as any).lastViolationFormatted = new Date(record.violations[record.violations.length - 1].timestamp).toLocaleString('zh-CN');
            }
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
                    beginAtFormatted: new Date(contest.beginAt).toLocaleString('zh-CN'),
                    endAt: contest.endAt,
                    endAtFormatted: new Date(contest.endAt).toLocaleString('zh-CN'),
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

        // 获取比赛的所有登录记录
        const loginRecords = await ipControlModel.getContestLoginRecords(contestId);

        // 格式化时间信息供模板使用
        const now = new Date();
        const timeInfo = {
            now: now.toLocaleString('zh-CN'),
            contestStart: new Date(contest.beginAt).toLocaleString('zh-CN'),
            contestEnd: new Date(contest.endAt).toLocaleString('zh-CN'),
            lockStart: setting ? new Date(contest.beginAt.getTime() - (setting.preContestLockMinutes || 60) * 60 * 1000).toLocaleString('zh-CN') : null,
            status: (() => {
                if (!setting || !setting.enabled) return 'disabled';
                const startTime = contest.beginAt.getTime();
                const endTime = contest.endAt.getTime();
                const lockStartTime = startTime - (setting.preContestLockMinutes || 60) * 60 * 1000;
                const currentTime = now.getTime();
                
                if (currentTime < lockStartTime) return 'normal';
                if (currentTime >= lockStartTime && currentTime < startTime) return 'locked';
                if (currentTime >= startTime && currentTime <= endTime) return 'running';
                return 'ended';
            })()
        };

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
            loginRecords,
            timeInfo,
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
            uidToRemove,
            clearUidsText,
            clearUidToRemove
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
                
            } else if (action === 'clear_login_records') {
                // 批量清除用户登录记录
                if (!clearUidsText || !clearUidsText.trim()) {
                    throw new Error('请输入用户ID列表');
                }

                const uids: number[] = [];
                const lines = clearUidsText.trim().split('\n');
                
                for (const line of lines) {
                    const uid = parseInt(line.trim());
                    if (!isNaN(uid) && uid > 0) {
                        uids.push(uid);
                    }
                }

                if (uids.length === 0) {
                    throw new Error('没有有效的用户ID');
                }

                const result = await ipControlModel.clearMultipleUserLoginRecords(contestId, uids);

                let message = `成功清除 ${result.success} 个用户的登录记录`;
                if (result.failed.length > 0) {
                    message += `，失败 ${result.failed.length} 个：${result.failed.join(', ')}`;
                }

                this.response.redirect = `/contest/${contestId}/ip-control?success=1&message=${encodeURIComponent(message)}`;
                
            } else if (action === 'clear_single_record') {
                // 清除单个用户登录记录
                if (!clearUidToRemove) {
                    throw new Error('请指定要清除记录的用户ID');
                }

                const uid = parseInt(clearUidToRemove);
                if (isNaN(uid)) {
                    throw new Error('用户ID无效');
                }

                await ipControlModel.clearUserLoginRecord(contestId, uid);

                this.response.redirect = `/contest/${contestId}/ip-control?success=1&message=${encodeURIComponent('用户登录记录已清除')}`;
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
            const loginRecords = await ipControlModel.getContestLoginRecords(contestId);

            // 格式化时间信息供模板使用
            const now = new Date();
            const timeInfo = contest ? {
                now: now.toLocaleString('zh-CN'),
                contestStart: new Date(contest.beginAt).toLocaleString('zh-CN'),
                contestEnd: new Date(contest.endAt).toLocaleString('zh-CN'),
                lockStart: setting ? new Date(contest.beginAt.getTime() - (setting.preContestLockMinutes || 60) * 60 * 1000).toLocaleString('zh-CN') : null,
                status: (() => {
                    if (!setting || !setting.enabled) return 'disabled';
                    const startTime = contest.beginAt.getTime();
                    const endTime = contest.endAt.getTime();
                    const lockStartTime = startTime - (setting.preContestLockMinutes || 60) * 60 * 1000;
                    const currentTime = now.getTime();
                    
                    if (currentTime < lockStartTime) return 'normal';
                    if (currentTime >= lockStartTime && currentTime < startTime) return 'locked';
                    if (currentTime >= startTime && currentTime <= endTime) return 'running';
                    return 'ended';
                })()
            } : null;

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
                loginRecords,
                timeInfo,
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
        const { uname, password } = that.args;
        
        console.log(`[IP控制] 用户 ${uname} 尝试登录, args:`, that.args);
        
        // 获取用户信息
        let udoc = await UserModel.getByEmail(that.args.domainId, uname);
        if (!udoc) {
            const user = await UserModel.getByUname(that.args.domainId, uname);
            if (user) udoc = user;
        }
        
        if (udoc) {
            console.log(`[IP控制] 找到用户信息: ${udoc._id}, uname: ${udoc.uname}, email: ${udoc.mail}`);
            
            // 检查用户是否参加了任何启用IP控制的比赛
            const userParticipatedContests = await db.collection('document.status').find({
                uid: udoc._id,
                docType: 30, // 比赛类型
                attend: 1    // 已参加
            }).toArray();

            console.log(`[IP控制] 用户 ${udoc._id} 参加的比赛:`, userParticipatedContests.map(p => p.docId));

            for (const participation of userParticipatedContests) {
                const setting = await ipControlModel.getContestIPControl(participation.docId);
                console.log(`[IP控制] 比赛 ${participation.docId} 的IP控制设置:`, setting);
                
                if (setting && setting.enabled) {
                    // 检查比赛是否在锁定期
                    const contest = await db.collection('document').findOne({
                        _id: participation.docId,
                        docType: 30
                    });

                    if (contest) {
                        const now = new Date();
                        const contestStart = new Date(contest.beginAt);
                        const lockStartTime = new Date(contestStart.getTime() - (setting.preContestLockMinutes || 60) * 60 * 1000);

                        console.log(`[IP控制] 比赛 ${contest.title} 锁定期检查:`, {
                            now: now.toISOString(),
                            contestStart: contestStart.toISOString(),
                            lockStartTime: lockStartTime.toISOString(),
                            inLockPeriod: now >= lockStartTime && now < contestStart
                        });

                        // 如果当前时间在锁定期内（锁定开始到比赛开始），禁止登录
                        if (now >= lockStartTime && now < contestStart) {
                            console.log(`[IP控制] 用户 ${udoc._id} 在锁定期内尝试登录，拒绝`);
                            throw new ForbiddenError(`比赛 "${contest.title}" 开始前${setting.preContestLockMinutes || 60}分钟内禁止登录，请在比赛开始后再次登录`);
                        }
                    }
                }
            }
            
            console.log(`[IP控制] 用户 ${udoc._id} 登录前检查通过`);
        } else {
            console.log(`[IP控制] 未找到用户 ${uname}`);
        }
    });

    // 监听用户登录后事件 - 记录IP和检查一致性
    ctx.on('handler/after/UserLogin#post', async (that) => {
        if (that.response.redirect && that.user) {
            const ip = that.request.ip;
            const ua = that.request.headers['user-agent'] || '';
            const userId = that.user._id;
            
            console.log(`[IP控制] 用户 ${userId} 登录后事件触发，IP: ${ip}, UA: ${ua.substring(0, 50)}...`);
            
            // 检查登录一致性
            const { allowed, reason } = await ipControlModel.checkLoginConsistency(
                userId, ip, ua
            );
            
            console.log(`[IP控制] 用户 ${userId} 登录一致性检查结果:`, { allowed, reason });
            
            if (!allowed) {
                console.log(`[IP控制] 用户 ${userId} 登录一致性检查失败，清除token`);
                // 清除登录Token，强制下线
                await ipControlModel.clearUserTokens(userId);
                throw new ForbiddenError(reason || '登录环境检查失败');
            }
            
            // 记录登录信息
            await ipControlModel.recordUserLogin(userId, ip, ua);
            console.log(`[IP控制] 已记录用户 ${userId} 的登录信息`);
        }
    });

    // 监听比赛页面访问事件 - 检查IP控制
    ctx.on('handler/before/ContestDetailHandler#get', async (that) => {
        const { tid: contestId } = that.args;
        const userId = that.user?._id;
        
        console.log(`[IP控制] 用户 ${userId} 访问比赛 ${contestId}`);
        
        // 获取IP控制设置并添加到模板数据中
        const setting = await ipControlModel.getContestIPControl(contestId);
        that.UiContext.setting = setting;
        
        console.log(`[IP控制] 比赛 ${contestId} 的IP控制设置:`, setting);
        
        if (!userId) {
            console.log(`[IP控制] 用户未登录，跳过检查`);
            return; // 未登录用户跳过检查
        }
        
        if (!setting || !setting.enabled) {
            console.log(`[IP控制] 比赛 ${contestId} 未启用IP控制或设置不存在`);
            return; // 未启用IP控制跳过
        }
        
        const ip = that.request.ip;
        const ua = that.request.headers['user-agent'] || '';
        
        console.log(`[IP控制] 用户 ${userId} 当前IP: ${ip}, UA: ${ua.substring(0, 50)}...`);
        
        // 检查是否在锁定期
        const contest = await db.collection('document').findOne({
            _id: contestId,
            docType: 30
        });

        if (contest) {
            const now = new Date();
            const contestStart = new Date(contest.beginAt);
            const lockStartTime = new Date(contestStart.getTime() - (setting.preContestLockMinutes || 60) * 60 * 1000);

            console.log(`[IP控制] 比赛 ${contestId} 时间信息:`, {
                now: now.toISOString(),
                contestStart: contestStart.toISOString(),
                lockStartTime: lockStartTime.toISOString(),
                lockMinutes: setting.preContestLockMinutes || 60
            });

            // 如果在锁定期内
            if (now >= lockStartTime && now < contestStart) {
                console.log(`[IP控制] 当前时间在锁定期内`);
                // 检查用户是否已经参加比赛
                const participantStatus = await db.collection('document.status').findOne({
                    uid: userId,
                    docType: 30,
                    docId: contestId,
                    attend: 1
                });
                
                console.log(`[IP控制] 用户 ${userId} 参赛状态:`, participantStatus);
                
                if (participantStatus) {
                    // 已参赛用户在锁定期被强制下线
                    console.log(`[IP控制] 锁定期内强制下线用户 ${userId}`);
                    await ipControlModel.clearUserTokens(userId);
                    throw new ForbiddenError(`比赛开始前${setting.preContestLockMinutes || 60}分钟内禁止访问比赛页面`);
                }
            }
        
            // 检查用户是否已参加比赛
            const participantStatus = await db.collection('document.status').findOne({
                uid: userId,
                docType: 30,
                docId: contestId,
                attend: 1
            });
            
            console.log(`[IP控制] 用户 ${userId} 参赛状态:`, participantStatus);
            
            if (participantStatus && now >= contestStart) {
                console.log(`[IP控制] 用户 ${userId} 已参赛且比赛已开始，检查IP一致性`);
                
                // 检查IP一致性
                let participant = await contestParticipantsColl.findOne({
                    contestId,
                    uid: userId
                });
                
                console.log(`[IP控制] 用户 ${userId} 的参赛记录:`, participant);
                
                if (participant && participant.firstLoginIP) {
                    // 检查IP和UA一致性
                    const ipMatches = participant.firstLoginIP === ip;
                    const uaMatches = setting.strictMode ? participant.firstLoginUA === ua : true;
                    
                    console.log(`[IP控制] IP一致性检查结果:`, {
                        originalIP: participant.firstLoginIP,
                        currentIP: ip,
                        ipMatches,
                        originalUA: participant.firstLoginUA?.substring(0, 50) + '...',
                        currentUA: ua.substring(0, 50) + '...',
                        uaMatches,
                        strictMode: setting.strictMode
                    });
                    
                    if (!ipMatches || !uaMatches) {
                        console.log(`[IP控制] 检测到违规访问，用户 ${userId} 将被阻止`);
                        
                        // 记录违规
                        await ipControlModel.recordViolation(userId, contestId, ip, ua, {
                            originalIP: participant.firstLoginIP,
                            originalUA: participant.firstLoginUA,
                            currentIP: ip,
                            currentUA: ua,
                            reason: !ipMatches ? 'IP_CHANGE' : 'UA_CHANGE'
                        });
                        
                        // 清除登录状态
                        await ipControlModel.clearUserTokens(userId);
                        
                        const reason = !ipMatches ? 
                            `IP地址已变更，原IP: ${participant.firstLoginIP}，当前IP: ${ip}` :
                            `浏览器环境已变更，请使用原始设备访问`;
                        
                        throw new ForbiddenError(`检测到设备变更，${reason}`);
                    }
                    
                    console.log(`[IP控制] IP/UA检查通过，更新登录记录`);
                    
                    // 更新最后登录时间和次数
                    await contestParticipantsColl.updateOne(
                        { contestId, uid: userId },
                        { 
                            $set: { lastLoginAt: new Date() },
                            $inc: { loginCount: 1 }
                        }
                    );
                } else if (participant) {
                    console.log(`[IP控制] 用户 ${userId} 首次访问比赛，记录IP和UA`);
                    
                    // 首次访问，记录IP和UA
                    await contestParticipantsColl.updateOne(
                        { contestId, uid: userId },
                        { 
                            $set: {
                                firstLoginIP: ip,
                                firstLoginUA: ua,
                                firstLoginAt: new Date(),
                                lastLoginAt: new Date(),
                                loginCount: 1
                            }
                        }
                    );
                    
                    console.log(`[IP控制] 已为用户 ${userId} 记录首次登录信息: IP=${ip}, UA=${ua.substring(0, 50)}...`);
                } else {
                    console.log(`[IP控制] 用户 ${userId} 没有参赛记录，创建新记录`);
                    
                    // 创建参赛记录
                    await contestParticipantsColl.insertOne({
                        contestId,
                        uid: userId,
                        forced: false,
                        addedAt: new Date(),
                        addedBy: userId,
                        firstLoginIP: ip,
                        firstLoginUA: ua,
                        firstLoginAt: new Date(),
                        lastLoginAt: new Date(),
                        loginCount: 1,
                        violationCount: 0
                    });
                    
                    console.log(`[IP控制] 已为用户 ${userId} 创建参赛记录`);
                }
            } else {
                console.log(`[IP控制] 用户 ${userId} 未参赛或比赛未开始，跳过IP检查`);
            }
        } else {
            console.log(`[IP控制] 找不到比赛 ${contestId} 的信息`);
        }
    });

    // 监听比赛参加事件 - 检查IP控制参赛权限
    ctx.on('handler/before/ContestDetailHandler#postAttend', async (that) => {
        const { domainId, tid: contestId } = that.args;
        const userId = that.user._id;
        
        console.log(`[IP控制] 用户 ${userId} 尝试参加比赛 ${contestId}`);
        
        // 检查比赛是否启用了IP控制
        const setting = await ipControlModel.getContestIPControl(contestId);
        console.log(`[IP控制] 比赛 ${contestId} 的IP控制设置:`, setting);
        
        if (setting && setting.enabled) {
            // 获取比赛信息
            const contest = await db.collection('document').findOne({
                _id: contestId,
                docType: 30
            });

            if (contest) {
                const now = new Date();
                const contestStart = new Date(contest.beginAt);

                console.log(`[IP控制] 比赛时间检查:`, {
                    now: now.toISOString(),
                    contestStart: contestStart.toISOString(),
                    started: now >= contestStart
                });

                // 如果比赛已经开始，禁止新用户加入
                if (now >= contestStart) {
                    console.log(`[IP控制] 比赛已开始，拒绝用户 ${userId} 加入`);
                    throw new ForbiddenError('比赛已开始，启用IP控制的比赛不允许比赛开始后加入');
                }

                console.log(`[IP控制] 比赛未开始，允许用户 ${userId} 参加`);
                // 检查用户是否在强制参赛列表中（如果需要强制参赛功能）
                const forcedParticipant = await contestParticipantsColl.findOne({
                    contestId,
                    uid: userId,
                    forced: true
                });
                
                // 如果设置了强制参赛且用户不在列表中，则拒绝
                // 这里可以根据需要调整逻辑，暂时允许所有用户在比赛开始前加入
                // if (!forcedParticipant) {
                //     throw new ForbiddenError('此比赛启用了IP控制，只有被管理员添加的用户才能参加');
                // }
            }
        } else {
            console.log(`[IP控制] 比赛 ${contestId} 未启用IP控制，允许参加`);
        }
    });

    // 监听代码提交事件 - 检查IP控制
    ctx.on('handler/before/ProblemSubmitHandler#post', async (that) => {
        const { pid: problemId } = that.args;
        const userId = that.user?._id;
        
        if (!userId) return;
        
        console.log(`[IP控制] 用户 ${userId} 尝试提交代码到题目 ${problemId}`);
        
        // 检查这个题目是否属于某个启用了IP控制的比赛
        const contests = await db.collection('document').find({
            docType: 30, // 比赛类型
            pids: problemId
        }).toArray();
        
        console.log(`[IP控制] 题目 ${problemId} 所属的比赛:`, contests.map(c => ({ id: c._id, title: c.title })));
        
        for (const contest of contests) {
            const setting = await ipControlModel.getContestIPControl(contest._id);
            
            if (setting && setting.enabled) {
                console.log(`[IP控制] 比赛 ${contest._id} 启用了IP控制，检查用户 ${userId} 的提交权限`);
                
                // 检查用户是否参加了这个比赛
                const participantStatus = await db.collection('document.status').findOne({
                    uid: userId,
                    docType: 30,
                    docId: contest._id,
                    attend: 1
                });
                
                if (participantStatus) {
                    const ip = that.request.ip;
                    const ua = that.request.headers['user-agent'] || '';
                    
                    console.log(`[IP控制] 用户 ${userId} 当前提交IP: ${ip}, UA: ${ua.substring(0, 50)}...`);
                    
                    // 检查IP一致性
                    const participant = await contestParticipantsColl.findOne({
                        contestId: contest._id,
                        uid: userId
                    });
                    
                    console.log(`[IP控制] 用户 ${userId} 在比赛 ${contest._id} 的参赛记录:`, participant);
                    
                    if (participant && participant.firstLoginIP) {
                        const ipMatches = participant.firstLoginIP === ip;
                        const uaMatches = setting.strictMode ? participant.firstLoginUA === ua : true;
                        
                        console.log(`[IP控制] 提交时IP一致性检查:`, {
                            originalIP: participant.firstLoginIP,
                            currentIP: ip,
                            ipMatches,
                            originalUA: participant.firstLoginUA?.substring(0, 50) + '...',
                            currentUA: ua.substring(0, 50) + '...',
                            uaMatches,
                            strictMode: setting.strictMode
                        });
                        
                        if (!ipMatches || !uaMatches) {
                            console.log(`[IP控制] 提交被拒绝：用户 ${userId} IP/UA不匹配`);
                            
                            // 记录违规
                            await ipControlModel.recordViolation(userId, contest._id, ip, ua, {
                                originalIP: participant.firstLoginIP,
                                originalUA: participant.firstLoginUA,
                                currentIP: ip,
                                currentUA: ua,
                                reason: !ipMatches ? 'IP_CHANGE_SUBMIT' : 'UA_CHANGE_SUBMIT',
                                action: 'submit'
                            });
                            
                            const reason = !ipMatches ? 
                                `IP地址已变更，原IP: ${participant.firstLoginIP}，当前IP: ${ip}` :
                                `浏览器环境已变更，请使用原始设备提交`;
                            
                            throw new ForbiddenError(`检测到设备变更，无法提交代码：${reason}`);
                        }
                        
                        console.log(`[IP控制] 提交检查通过，允许用户 ${userId} 提交代码`);
                    }
                }
            }
        }
    });

    // 定时任务：管理IP控制的锁定期和用户状态
    setTimeout(async () => {
        setInterval(async () => {
            try {
                // 获取所有启用IP控制的比赛
                const ipControlSettings = await ipControlSettingsColl.find({ enabled: true }).toArray();
                
                for (const setting of ipControlSettings) {
                    const contest = await db.collection('document').findOne({
                        _id: setting.contestId,
                        docType: 30
                    });

                    if (!contest) continue;

                    const now = new Date();
                    const contestStart = new Date(contest.beginAt);
                    const contestEnd = new Date(contest.endAt);
                    const lockStartTime = new Date(contestStart.getTime() - (setting.preContestLockMinutes || 60) * 60 * 1000);

                    // 检查是否刚进入锁定期（在锁定开始后的1分钟内）
                    const timeSinceLockStart = now.getTime() - lockStartTime.getTime();
                    const justEnteredLockPeriod = timeSinceLockStart >= 0 && timeSinceLockStart <= 5 * 60 * 1000; // 5分钟内算作刚进入

                    if (justEnteredLockPeriod && now < contestStart) {
                        console.log(`比赛 ${contest.title} 进入锁定期，清除所有参赛用户的登录状态`);
                        
                        // 获取所有参赛用户
                        const participants = await db.collection('document.status').find({
                            docType: 30,
                            docId: setting.contestId,
                            attend: 1
                        }).toArray();
                        
                        // 清除所有参赛用户的token
                        for (const participant of participants) {
                            await ipControlModel.clearUserTokens(participant.uid);
                            console.log(`清除用户 ${participant.uid} 的登录状态`);
                        }
                    }

                    // 在比赛进行期间，继续检查IP一致性
                    if (now >= contestStart && now <= contestEnd) {
                        // 这里可以添加额外的实时检查逻辑
                        // 例如检查已登录用户的IP是否发生变化
                    }
                }
            } catch (error) {
                console.error('IP控制定时任务执行失败:', error);
            }
        }, 1 * 60 * 1000); // 每1分钟执行一次，提高响应性
    }, 5000); // 5秒后开始执行

    // 添加导航菜单
    ctx.inject(['ui'], (c) => {
        c.injectUI('Notification', 'IP控制', { type: 'info' });
    });
}
