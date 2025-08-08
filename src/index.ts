import { Context, Schema, Session, h, Logger, Bot } from 'koishi';
import { } from '@koishijs/plugin-server'
import { sendRconCommand, translateDeathMessage } from './utils'

export const name = 'mctool';

const logger = new Logger(name);

export const inject = ['database', 'server'];

export const usage = `MC高级群服互通

搭配Minecraft Webhook插件（Spigot）使用以便接收webhook消息：https://github.com/MineJPGcraft/Minecraft-Webhook

功能：

1.QQ号与Minecraft绑定

2.死亡记录查询

3.在线人数查询

4.同步聊天

还有更多功能逐步开发中！`;

export interface Config {
    botid: string;
    platform: string;
    host: string;
    port: number;
    password: string;
    verificationTimeout: number;
    commandPrefix: string;
    rconConnectTimeout: number;
    rconResponseTimeout: number;
    webhookPath: string;
    webhookSecret?: string;
    bindChannel: string;
    worldMap: Record<string, string>;
    ischat: boolean;
    isdeath: boolean;
    isloginmsg: boolean;
    isjoinquitmsg: boolean;
    isDev: boolean;
    getGroupusername: boolean;
    isAt: boolean;
}


export const Config: Schema<Config> = Schema.object({
    botid: Schema.string().required().description('机器人自身ID'),
    platform: Schema.string().default('onebot').description('机器人平台'),
    host: Schema.string().required().description('Minecraft 服务器 RCON 地址'),
    port: Schema.number().default(25575).description('Minecraft 服务器 RCON 端口'),
    password: Schema.string().role('secret').required().description('RCON 密码'),
    verificationTimeout: Schema.number().default(10 * 60 * 1000).description('验证超时时间（毫秒）'),
    commandPrefix: Schema.string().default('mc').description('插件的主指令名'),
    rconConnectTimeout: Schema.number().default(5000).description('RCON 连接超时时间 (毫秒)'),
    rconResponseTimeout: Schema.number().default(10000).description('RCON 命令响应超时时间 (毫秒)'),
    webhookPath: Schema.string().default('/mcwebhook').description('Minecraft 服务器发送 webhook 的路径'),
    webhookSecret: Schema.string().role('secret').description('可选，Webhook 安全密钥。如果设置，请配置服务器在请求头中带上 "X-Secret" 或作为查询参数发送。'),
    bindChannel: Schema.string().description('群聊 ID').required(),
    worldMap: Schema.dict(Schema.string().description('显示名称')).role('table').description('自定义地图显示名称'),
    ischat: Schema.boolean().default(true).description('是否开启聊天同步'),
    isdeath: Schema.boolean().default(true).description('是否开启死亡信息记录'),
    isloginmsg: Schema.boolean().default(true).description('是否开启登录提醒'),
    isjoinquitmsg: Schema.boolean().default(true).description('是否开启加入退出提醒'),
    isDev: Schema.boolean().default(false).description('是否为开发模式(会显示调试信息)'),
    getGroupusername: Schema.boolean().default(false).description('是否尝试获取群聊用户名(仅OneBot)'),
    isAt: Schema.boolean().default(true).description('用户被提及是否在游戏里提示'),
});

declare module 'koishi' {
    interface Tables {
        minecraft_bindings: MinecraftBinding;
        minecraft_deaths: MinecraftDeath;
    }
}

export interface MinecraftBinding {
    id: number;
    platform: string;
    koishiUserId: string;
    mcUsername: string;
    bindTimestamp: Date;
    isfreeze: boolean;
}

export interface MinecraftDeath {
    id: number;
    mcUsername: string;
    deathTime: Date;
    dimension: string;
    reason: string;
    x: number | null;
    y: number | null;
    z: number | null;
}

interface PendingVerification {
    mcUsername: string;
    verificationCode: string;
    timeoutTimer: NodeJS.Timeout;
    timestamp: number;
}


export function apply(ctx: Context, config: Config) {
    ctx.i18n.define('zh-CN', require('./locales/zh-CN'))
    const mainCommand = config.commandPrefix || 'mc';

    ctx.model.extend('minecraft_bindings', {
        id: 'unsigned',
        platform: 'string',
        koishiUserId: 'string',
        mcUsername: 'string',
        bindTimestamp: 'timestamp',
        isfreeze: 'boolean'
    }, {
        primary: 'id',
        autoInc: true,
        unique: [
            ['platform', 'koishiUserId'],
            ['mcUsername'],
        ]
    });
    ctx.model.extend('minecraft_deaths', {
        id: 'unsigned',
        mcUsername: 'string',
        deathTime: 'timestamp',
        dimension: 'string',
        reason: 'string',
        x: 'double',
        y: 'double',
        z: 'double',
    }, {
        primary: 'id',
        autoInc: true,
    });

    const pendingVerifications = new Map<string, PendingVerification>();

    function clearPending(mcUsername: string) {
        const pending = pendingVerifications.get(mcUsername);
        if (pending) {
            clearTimeout(pending.timeoutTimer);
            pendingVerifications.delete(mcUsername);
            if (config.isDev) logger.info(`[Pending] Cleared pending verification for MC user: ${mcUsername}`);
        }
    }

    ctx.server.post(config.webhookPath, async (c) => {
        if (config.webhookSecret) {
            const secret = c.request.headers['x-secret'] || c.request.query.secret;
            if (secret !== config.webhookSecret) {
                if (config.isDev) logger.warn(`[Webhook] Received request with invalid secret from ${c.request.ip}`);
                c.response.status = 401;
                return 'Invalid secret';
            }
        }

        let payload;
        try {
            payload = c.request.body;
            if (typeof payload !== 'object') {
                throw new Error('Invalid JSON body');
            }
        } catch (error: any) {
            if (config.isDev) logger.warn(`[Webhook] Failed to parse JSON body from ${c.request.ip}: ${error.message}`);
            c.response.status = 400;
            return 'Invalid JSON body';
        }

        if (payload.event_type === 'login' && payload.player_name) {
            const mcUsername = payload.player_name;
            if (config.isDev) logger.info(`[Webhook] Received login event for player: ${mcUsername}`);

            try {
                const existingBinding = await ctx.database.get('minecraft_bindings', { mcUsername });
                if (existingBinding.length > 0) {
                    c.response.status = 200;
                    if (existingBinding[0].isfreeze) {
                        //没session没法使用本地化，实在是没办法。。。
                        const bot = ctx.bots.find(bot => bot.selfId === config.botid && bot.platform === config.platform)
                        const session = bot.session()
                        const kickMessage = session.text('mctool.freezemsg', [mainCommand])
                        const kickCommand = `kick ${mcUsername} ${kickMessage}`;
                        const kickResponse = await sendRconCommand(config, kickCommand);
                        return kickResponse;
                    }
                    if (config.isloginmsg) {
                        const d = new Date();
                        const bot = ctx.bots.find(bot => bot.selfId === config.botid && bot.platform === config.platform)
                        if (bot) {
                            const session = bot.session()
                            bot.sendPrivateMessage(existingBinding[0].koishiUserId, session.text('mctool.loginwarn', [mcUsername, d.getFullYear(), d.getMonth(), d.getDay(), d.getHours(), d.getMinutes(), d.getSeconds(), mainCommand]))
                        }
                    }
                    if (config.isjoinquitmsg) {
                        const bot = ctx.bots.find(bot => bot.selfId === config.botid && bot.platform === config.platform)
                        if (bot) {
                            const session = bot.session()
                            let username: string;
                            if (config.getGroupusername) {
                                username = (await bot.internal.getGroupMemberInfo(config.bindChannel, existingBinding[0].koishiUserId)).nickname
                            } else {
                                username = mcUsername
                            }
                            bot.sendMessage(config.bindChannel, session.text('mctool.loginmsg', [username]))
                        }
                    }
                    return 'OK';
                }
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                if (config.isDev) logger.info(`[Webhook] Starting verification for ${mcUsername}. Code: ${verificationCode}`);

                let bot = ctx.bots.find(bot => bot.selfId === config.botid && bot.platform === config.platform)
                let session = bot.session()
                let kickMessage = session.text('mctool.bindmsg', [verificationCode, config.bindChannel, mainCommand]);
                const kickCommand = `kick ${mcUsername} ${kickMessage}`;

                try {
                    const kickResponse = await sendRconCommand(config, kickCommand);
                    //logger.info(`[Webhook] Kicked player ${mcUsername} with verification code. RCON Response: ${kickResponse}`);

                    const timeoutTimer = setTimeout(async () => {
                        const pending = pendingVerifications.get(mcUsername);
                        if (pending && pending.verificationCode === verificationCode) {
                            //logger.warn(`[Pending] Verification timed out for MC user: ${mcUsername}`);
                            pendingVerifications.delete(mcUsername);
                        } else {
                            //logger.debug(`[Pending] Timeout triggered for ${mcUsername} but pending state changed or cleared.`);
                        }

                    }, config.verificationTimeout);

                    pendingVerifications.set(mcUsername, {
                        mcUsername,
                        verificationCode,
                        timeoutTimer,
                        timestamp: Date.now(),
                    });

                    c.response.status = 200;
                    return 'Verification process initiated';

                } catch (rconError: any) {
                    //logger.error(`[Webhook] Failed to kick player ${mcUsername} via RCON:`, rconError.message);
                    return 'Failed to kick player via RCON';
                }

            } catch (dbError: any) {
                logger.error(`[Webhook] Database error while processing login for ${mcUsername}:`, dbError);
                c.response.status = 500;
                return 'Database error';
            }

        }
        else if (payload.event_type === 'death' && payload.player_name && config.isdeath) {
            const mcUsername = payload.player_name;
            const reason = payload.death_message ?? '未知';
            const deathTime = payload.timestamp ? new Date(payload.timestamp) : new Date();
            const dimension = payload.location?.world ?? 'unknown';
            const x = payload.location?.x ?? null;
            const y = payload.location?.y ?? null;
            const z = payload.location?.z ?? null;

            //logger.info(`[Webhook] Received death event for player: ${mcUsername} at [${dimension}] ${x}, ${y}, ${z}`);

            try {
                await ctx.database.create('minecraft_deaths', {
                    mcUsername,
                    deathTime,
                    dimension,
                    reason,
                    x,
                    y,
                    z,
                });
                //logger.debug(`[Webhook] Recorded death for ${mcUsername}.`);

                const deathRecords = await ctx.database.get('minecraft_deaths', { mcUsername }, {
                    sort: { deathTime: 'desc' },
                });

                if (deathRecords.length > 5) {
                    const idsToDelete = deathRecords.slice(5).map(record => record.id);
                    const deleteResult = await ctx.database.remove('minecraft_deaths', { id: { $in: idsToDelete } });
                    //logger.debug(`[Webhook] Deleted ${deleteResult.removed} old death records for ${mcUsername}.`);
                }

                c.response.status = 200;
                return 'Death recorded successfully';

            } catch (dbError: any) {
                logger.error(`[Webhook] Database error while recording death for ${mcUsername}:`, dbError);
                c.response.status = 500;
                return 'Database error recording death';
            }
        }
        //聊天事件
        else if (payload.event_type === 'chat' && config.ischat) {
            //发送到设置的群
            const bot = ctx.bots.find(bot => bot.selfId === config.botid && bot.platform === config.platform)
            if (bot) {
                const session = bot.session();
                const mcUsername = payload.player_name;
                const existingBinding = await ctx.database.get('minecraft_bindings', { mcUsername });
                let username: string;
                if (config.getGroupusername) {
                    username = (await bot.internal.getGroupMemberInfo(config.bindChannel, existingBinding[0].koishiUserId)).nickname
                    // logger.info(await bot.internal.getGroupMemberInfo(config.bindChannel, existingBinding[0].koishiUserId))
                } else {
                    username = mcUsername
                }
                bot.sendMessage(config.bindChannel, session.text('mctool.syncmsg', [username, payload.chat_message]))
            }
            c.response.status = 200;
        }
        else if (payload.event_type === 'quit' && config.isjoinquitmsg) {
            //先判断是否绑定
            const mcUsername = payload.player_name;
            const existingBinding = await ctx.database.get('minecraft_bindings', { mcUsername });
            if (existingBinding.length > 0) {
                const bot = ctx.bots.find(bot => bot.selfId === config.botid && bot.platform === config.platform)
                if (bot) {
                    const session = bot.session();
                    let username: string;
                    if (config.getGroupusername) {
                        username = (await bot.internal.getGroupMemberInfo(config.bindChannel, existingBinding[0].koishiUserId)).nickname
                        // logger.info(await bot.internal.getGroupMemberInfo(config.bindChannel, existingBinding[0].koishiUserId))
                    } else {
                        username = mcUsername
                    }
                    bot.sendMessage(config.bindChannel, session.text('mctool.quitmsg', [username]))
                }
            }
            c.response.status = 200;
        } else {
            c.response.status = 200;
            return 'Not a valid event';
        }
    });

    const cmd = ctx.command(mainCommand, 'MC工具');

    cmd.subcommand('.code <code:string>', '提交游戏内收到的验证码', { checkArgCount: true })
        .usage(`请提供你在游戏内收到的6位数字验证码。例如：${mainCommand}.code 123456`)
        .action(async ({ session }, code) => {
            if (!session?.userId || !session?.platform || !session?.bot?.selfId) {
                return '无法获取您的用户信息，请稍后再试。';
            }

            if (!/^\d{6}$/.test(code)) {
                return '验证码格式错误，应为 6 位数字。';
            }

            let pending = undefined as PendingVerification | undefined;
            let mcUsername = undefined as string | undefined;
            let pendingKeyToDelete = undefined as string | undefined;
            for (const [userKey, pendingEntry] of pendingVerifications.entries()) {
                if (pendingEntry.verificationCode === code) {
                    pending = pendingEntry;
                    mcUsername = pendingEntry.mcUsername;
                    pendingKeyToDelete = userKey;
                    break;
                }
            }

            if (!pending || !mcUsername) {
                //logger.warn(`[CodeCmd] Incorrect or expired verification code submitted by ${session.platform}:${session.userId}. Code: ${code}`);
                return '验证码错误或已过期，请检查后重试或重新进入服务器获取新的验证码。';
            }

            //logger.info(`[CodeCmd] Verification code matched for MC user: ${mcUsername}. User submitting: ${session.platform}:${session.userId}`);

            clearPending(mcUsername);

            try {
                const existingBindingByUser = await ctx.database.get('minecraft_bindings', { platform: session.platform, koishiUserId: session.userId });
                if (existingBindingByUser.length > 0) {
                    //logger.warn(`[CodeCmd] Koishi user ${session.platform}:${session.userId} is already bound to ${existingBindingByUser[0].mcUsername}.`);
                    return `您的QQ账号已经绑定了 Minecraft 账号: ${existingBindingByUser[0].mcUsername}。如需解绑请联系管理员。`;
                }
                const existingBindingByMc = await ctx.database.get('minecraft_bindings', { mcUsername });
                if (existingBindingByMc.length > 0) {
                    //logger.warn(`[CodeCmd] MC user ${mcUsername} was bound by ${existingBindingByMc[0].platform}:${existingBindingByMc[0].koishiUserId}.`);
                    return `Minecraft 账号 ${mcUsername} 在您输入验证码期间已被其他用户绑定。请联系管理员确认。`;
                }

                await ctx.database.create('minecraft_bindings', {
                    platform: session.platform,
                    koishiUserId: session.userId,
                    mcUsername: mcUsername,
                    bindTimestamp: new Date(),
                    isfreeze: false,
                });

                //logger.success(`[CodeCmd] Binding saved: ${session.platform}:${session.userId} <-> ${mcUsername}`);
                return session.text('mctool.bindsuccess', [session.username, mcUsername]);

            } catch (dbError: any) {
                logger.error(`[CodeCmd] Database error while saving binding for ${session.platform}:${session.userId}:`, dbError);

                if (dbError.code === 'ER_DUP_ENTRY' || (dbError.message && dbError.message.includes('UNIQUE constraint failed'))) {
                    const existing = await ctx.database.get('minecraft_bindings', { $or: [{ platform: session.platform, koishiUserId: session.userId }, { mcUsername: mcUsername }] });
                    if (existing.length > 0) {
                        const conflict = existing[0];
                        if (conflict.mcUsername === mcUsername) {
                            return `绑定失败：Minecraft 账号 ${mcUsername} 在您验证期间已被绑定。请联系管理员处理。`;
                        } else {
                            return `绑定失败：您的QQ号似乎已绑定了其他 MC 账号 (${conflict.mcUsername})。`;
                        }
                    } else {
                        return '绑定失败：写入数据库时发生唯一性约束错误，但未能定位冲突记录。请联系管理员。';
                    }
                }
                return '绑定过程中发生数据库错误，请联系管理员。';
            }
        });
    ctx.middleware(async (session, next) => {
        if (session.isDirect && /^\d{6}$/.test(session.content ?? '')) {
            const code = session.content!;
            if (config.isDev) logger.debug(`[Middleware] Received potential verification code via DM: ${code}`);

            let pending = undefined as PendingVerification | undefined;
            let mcUsername = undefined as string | undefined;

            for (const [userKey, pendingEntry] of pendingVerifications.entries()) {
                if (pendingEntry.verificationCode === code) {
                    pending = pendingEntry;
                    mcUsername = pendingEntry.mcUsername;
                    break;
                }
            }

            if (!pending || !mcUsername) {
                return next();
            }

            clearPending(mcUsername);


            try {
                const existingBindingByUser = await ctx.database.get('minecraft_bindings', { platform: session.platform, koishiUserId: session.userId });
                if (existingBindingByUser.length > 0) {
                    //logger.warn(`[Middleware] Koishi user ${session.platform}:${session.userId} is already bound to ${existingBindingByUser[0].mcUsername}. (Via DM)`);
                    await session.send(`您的QQ号已经绑定了 Minecraft 账号: ${existingBindingByUser[0].mcUsername}。如需解绑请联系管理员。`);
                    return;
                }

                const existingBindingByMc = await ctx.database.get('minecraft_bindings', { mcUsername });
                if (existingBindingByMc.length > 0) {
                    await session.send(`Minecraft 账号 ${mcUsername}在您输入验证码期间已被其他用户绑定。请联系管理员确认。`);
                    return;
                }

                await ctx.database.create('minecraft_bindings', {
                    platform: session.platform,
                    koishiUserId: session.userId,
                    mcUsername: mcUsername,
                    bindTimestamp: new Date(),
                });

                await session.send(session.text('mctool.bindsuccess', [session.username, mcUsername]));
                return;

            } catch (dbError: any) {
                if (dbError.code === 'ER_DUP_ENTRY' || (dbError.message && dbError.message.includes('UNIQUE constraint failed'))) {
                    const existing = await ctx.database.get('minecraft_bindings', { $or: [{ platform: session.platform, koishiUserId: session.userId }, { mcUsername: mcUsername }] });
                    if (existing.length > 0) {
                        const conflict = existing[0];
                        if (conflict.mcUsername === mcUsername) {
                            await session.send(`绑定失败：Minecraft 账号 ${conflict.mcUsername} 在您验证期间已被绑定。请联系管理员处理。`);
                        } else {
                            await session.send(`绑定失败：您的QQ号似乎已绑定了其他 MC 账号 (${conflict.mcUsername})。`);
                        }
                    } else {
                        await session.send('绑定失败：写入数据库时发生唯一性约束错误，但未能定位冲突记录。请联系管理员。');
                    }
                    return;
                }
                await session.send('绑定过程中发生数据库错误，请联系管理员。');
                return;
            }
        }
        return next();
    });

    cmd.subcommand('.info', '查看您绑定的 Minecraft 账号')
        .action(async ({ session }) => {
            if (!session?.userId || !session?.platform) {
                return '无法获取用户信息。';
            }
            const binding = await ctx.database.get('minecraft_bindings', { platform: session.platform, koishiUserId: session.userId });
            if (binding.length > 0) {
                return `您 (${session.username}) 已绑定 Minecraft 账号: ${binding[0].mcUsername}`;
            } else {
                return `您尚未绑定 Minecraft 账号。请通过进入 Minecraft 服务器触发绑定流程，然后在QQ中使用 \`${mainCommand}.code <验证码>\` 完成绑定。`;
            }
        });

    ctx.command(`${mainCommand}.unbind <mcUsername:string>`, '管理员解除绑定 Minecraft 账号', { authority: 3 })
        .action(async ({ session }, mcUsername) => {
            if (!mcUsername) {
                return '请提供要解除绑定的 Minecraft 用户名。'
            }
            try {
                const result = await ctx.database.remove('minecraft_bindings', { mcUsername });
                if (result && typeof result === 'object' && 'deletedCount' in result && (result as any).deletedCount > 0) {
                    //logger.info(`[Admin] Removed binding for MC user: ${mcUsername}. (${(result as any).deletedCount} entries)`);
                    try {
                        const whitelistResponse = await sendRconCommand(config, `whitelist remove ${mcUsername}`);
                        //logger.info(`[Admin] Attempted to remove whitelist for ${mcUsername} after unbinding. Response: ${whitelistResponse}`);
                    } catch (rconErr: any) {
                        //logger.warn(`[Admin] Failed to remove whitelist for ${mcUsername} after unbinding:`, rconErr.message);
                    }
                    return `已解除 Minecraft 账号 ${mcUsername} 的绑定。`;
                } else {
                    return `未找到与 Minecraft 账号 ${mcUsername} 关联的绑定记录。`;
                }
            } catch (dbError: any) {
                logger.error(`[Admin] Database error during unbind for ${mcUsername}:`, dbError);
                return '解除绑定时发生数据库错误，请联系管理员。';
            }
        });
    if (config.isdeath) {
        cmd.subcommand('.deaths', '查询死亡记录')
            .action(async ({ session }) => {
                if (!session?.userId || !session?.platform) {
                    return '无法获取用户信息，请稍后再试。';
                }
                const platform = session.platform;
                const koishiUserId = session.userId;

                try {
                    const binding = await ctx.database.get('minecraft_bindings', { platform, koishiUserId });
                    if (binding.length === 0) {
                        return `您尚未绑定 Minecraft 账号。请通过进入 Minecraft 服务器触发绑定流程，然后在QQ中使用 \`${mainCommand}.code <验证码>\` 完成绑定。`;
                    }

                    const mcUsername = binding[0].mcUsername;

                    const deathRecords = await ctx.database.get('minecraft_deaths', { mcUsername }, {
                        sort: { deathTime: 'desc' },
                        limit: 5
                    });

                    if (deathRecords.length === 0) {
                        return `您的 Minecraft 账号 (${mcUsername}) 暂无最近的死亡记录。`;
                    }

                    let reply = `您的 Minecraft 账号 (${mcUsername}) 最近 ${deathRecords.length} 次死亡记录：\n`;

                    deathRecords.forEach(record => {
                        const deathTime = new Date(record.deathTime).toLocaleString();
                        let dimension: string;
                        if (config[record.dimension]) {
                            dimension = config[record.dimension];
                        } else {
                            dimension = record.dimension === 'world' ? '主世界' :
                                record.dimension === 'nether' ? '下界' :
                                    record.dimension === 'end' ? '末地' :
                                        record.dimension;
                        }
                        const location = (record.x !== null && record.y !== null && record.z !== null)
                            ? `位置 [${dimension}] ${Math.round(record.x)}, ${Math.round(record.y)}, ${Math.round(record.z)}`
                            : `位置未知`;
                        const reason = translateDeathMessage(record.reason, true);

                        reply += `- ${deathTime} 在 ${location}${reason}\n`;
                    });

                    return reply;

                } catch (dbError: any) {
                    logger.error(`[CmdDeaths] Database error retrieving death records for ${platform}:${koishiUserId}:`, dbError);
                    return '查询死亡记录时发生数据库错误，请联系管理员。';
                }
            });
    }
    cmd.subcommand('.list', '查看在线玩家')
        .action(async ({ session }) => {
            let response = await sendRconCommand(config, 'list');
            response = response.trim();
            const cleanedString = response.replace(/§./g, '');
            const match = cleanedString.match(/There are (\d+) out of maximum (\d+) players online\./);
            if (match) {
                const onlineCount = match[1];
                const maxCount = match[2];
                return `在线人数：${onlineCount}/${maxCount}`;
            }
            return cleanedString;
        })
    cmd.subcommand('.freeze', '冻结账号')
        .action(async ({ session }) => {
            if (!session?.userId || !session?.platform) {
                return '无法获取用户信息，请稍后再试。';
            }
            const platform = session.platform;
            const koishiUserId = session.userId;

            try {
                const binding = await ctx.database.get('minecraft_bindings', { platform, koishiUserId });
                if (binding.length === 0) {
                    return `您尚未绑定 Minecraft 账号。请通过进入 Minecraft 服务器触发绑定流程，然后在QQ中使用 \`${mainCommand}.code <验证码>\` 完成绑定。`;
                }
                //踢出玩家
                const response = await sendRconCommand(config, `kick ${binding[0].mcUsername} 帐号已被冻结`)
                await ctx.database.set('minecraft_bindings', { platform, koishiUserId }, { isfreeze: true });
                return '已冻结该账号。'
            } catch (error) {
                return '发生错误，请稍后再试。';
            }
        })
    cmd.subcommand('.unfreeze', '解冻账号')
        .action(async ({ session }) => {
            if (!session?.userId || !session?.platform) {
                return '无法获取用户信息，请稍后再试。';
            }
            const platform = session.platform;
            const koishiUserId = session.userId;

            try {
                const binding = await ctx.database.get('minecraft_bindings', { platform, koishiUserId });
                if (binding.length === 0) {
                    return `您尚未绑定 Minecraft 账号。请通过进入 Minecraft 服务器触发绑定流程，然后在QQ中使用 \`${mainCommand}.code <验证码>\` 完成绑定。`;
                }
                await ctx.database.set('minecraft_bindings', { platform, koishiUserId }, { isfreeze: false });
                return '已解冻该账号。'
            }
            catch (error) {
                return '发生错误，请稍后再试。';
            }
        })
    ctx.on('guild-member-removed', async (session) => {
        if (session.guildId === config.bindChannel) {
            try {
                const binding = await ctx.database.get('minecraft_bindings', { platform: session.platform, koishiUserId: session.userId });
                if (binding.length === 0) {
                    return;
                }
                await ctx.database.remove('minecraft_bindings', { platform: session.platform, koishiUserId: session.userId });
                return;
            }
            catch (e) {
                return;
            }
        }
    })
    ctx.on('message', async (session) => {
        if (session.channelId === config.bindChannel && config.ischat && session.userId !== config.botid && !session.isDirect) {
            const existingBinding = await ctx.database.get('minecraft_bindings', { koishiUserId: session.userId, platform: session.platform });
            let username: string;
            let isBind = false;
            if (existingBinding.length === 0) {
                username = session.username;
            } else {
                username = existingBinding[0].mcUsername;
                isBind = true;
            }
            // const chatCommand = `tellraw @a [{"text":"[QQ群] ","color":"gold"},{"text":"<${username}>","color":"white"},{"text":"${session.content}","color":"white"}]`;
            // 如果isBind就不加[QQ群]，否则加上
            const chatCommand = `tellraw @a [{"text":"${isBind ? '' : '[QQ群] '}", "color":"gold"},{"text":"<${username}>","color":"white"},{"text":"${session.content}","color":"white"}]`;
            const Response = await sendRconCommand(config, chatCommand);
            //logger.info(session)
            const Atlist: string[] = session.elements.filter((element) => element.type === 'at').map((element) => element.attrs.id);
            if (Atlist.length > 0 && config.isAt) {
                for (const atid of Atlist) {
                    const binding = await ctx.database.get('minecraft_bindings', { platform: session.platform, koishiUserId: atid });
                    if (binding.length > 0) {
                        const chatCommand = `tellraw ${binding[0].mcUsername} [{"color":"gold","text":"你被提及了"}]`;
                        const Response = await sendRconCommand(config, chatCommand);
                    }
                }
            }
        }
    })
}