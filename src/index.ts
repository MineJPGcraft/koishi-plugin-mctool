import { Context, Schema, Session, h, Logger } from 'koishi';
import { } from '@koishijs/plugin-server'
import { sendRconCommand, translateDeathMessage } from './utils'

export const name = 'mctool';

const logger = new Logger(name);

export const inject = ['database', 'server'];

export interface Config {
    host: string;
    port: number;
    password: string;
    verificationTimeout: number;
    commandPrefix: string;
    rconConnectTimeout: number;
    rconResponseTimeout: number;
    webhookPath: string;
    webhookSecret?: string;
    bindChannel?: string;
    worldMap: Record<string, string>;
}


export const Config: Schema<Config> = Schema.object({
    host: Schema.string().required().description('Minecraft 服务器 RCON 地址'),
    port: Schema.number().default(25575).description('Minecraft 服务器 RCON 端口'),
    password: Schema.string().role('secret').required().description('RCON 密码'),
    verificationTimeout: Schema.number().default(10 * 60 * 1000).description('验证超时时间（毫秒）'),
    commandPrefix: Schema.string().default('mc').description('插件的主指令名'),
    rconConnectTimeout: Schema.number().default(5000).description('RCON 连接超时时间 (毫秒)'),
    rconResponseTimeout: Schema.number().default(10000).description('RCON 命令响应超时时间 (毫秒)'),
    webhookPath: Schema.string().default('/mc-webhook').description('Minecraft 服务器发送 webhook 的路径'),
    webhookSecret: Schema.string().role('secret').description('可选，Webhook 安全密钥。如果设置，请配置服务器在请求头中带上 "X-Secret" 或作为查询参数发送。'),
    bindChannel: Schema.string().description('可选，告知玩家进行绑定的 Koishi 频道/群聊 ID。'),
    worldMap: Schema.dict(Schema.string().description('显示名称')).role('table').description('自定义地图显示名称'),
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
    const mainCommand = config.commandPrefix || 'mc';

    ctx.model.extend('minecraft_bindings', {
        id: 'unsigned',
        platform: 'string',
        koishiUserId: 'string',
        mcUsername: 'string',
        bindTimestamp: 'timestamp',
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
            logger.info(`[Pending] Cleared pending verification for MC user: ${mcUsername}`);
        }
    }

    ctx.server.post(config.webhookPath, async (c) => {
        if (config.webhookSecret) {
            const secret = c.request.headers['x-secret'] || c.request.query.secret;
            if (secret !== config.webhookSecret) {
                logger.warn(`[Webhook] Received request with invalid secret from ${c.request.ip}`);
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
            logger.warn(`[Webhook] Failed to parse JSON body from ${c.request.ip}: ${error.message}`);
            c.response.status = 400;
            return 'Invalid JSON body';
        }

        if (payload.event_type === 'login' && payload.player_name) {
            const mcUsername = payload.player_name;
            logger.info(`[Webhook] Received login event for player: ${mcUsername}`);

            try {
                const existingBinding = await ctx.database.get('minecraft_bindings', { mcUsername });
                if (existingBinding.length > 0) {
                    logger.info(`[Webhook] Player ${mcUsername} is already bound (Koishi user: ${existingBinding[0].platform}:${existingBinding[0].koishiUserId}). Doing nothing.`);
                    c.response.status = 200;
                    return 'Already bound';
                }
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                logger.info(`[Webhook] Starting verification for ${mcUsername}. Code: ${verificationCode}`);

                let kickMessage = `你的验证码是: ${verificationCode}. 请对机器人输入 "${mainCommand}.code ${verificationCode}" 来绑定你的账号。`;
                if (config.bindChannel) {
                    kickMessage = `你的验证码是: ${verificationCode}. 在QQ群 ${config.bindChannel} 或私聊机器人输入 "${mainCommand}.code ${verificationCode}" 来绑定你的账号。`;
                }
                const kickCommand = `kick ${mcUsername} ${kickMessage}`;

                try {
                    const kickResponse = await sendRconCommand(config, kickCommand);
                    logger.info(`[Webhook] Kicked player ${mcUsername} with verification code. RCON Response: ${kickResponse}`);

                    const timeoutTimer = setTimeout(async () => {
                        const pending = pendingVerifications.get(mcUsername);
                        if (pending && pending.verificationCode === verificationCode) {
                            logger.warn(`[Pending] Verification timed out for MC user: ${mcUsername}`);
                            pendingVerifications.delete(mcUsername);
                        } else {
                            logger.debug(`[Pending] Timeout triggered for ${mcUsername} but pending state changed or cleared.`);
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
                    logger.error(`[Webhook] Failed to kick player ${mcUsername} via RCON:`, rconError.message);
                    return 'Failed to kick player via RCON';
                }

            } catch (dbError: any) {
                logger.error(`[Webhook] Database error while processing login for ${mcUsername}:`, dbError);
                c.response.status = 500;
                return 'Database error';
            }

        }
        else if (payload.event_type === 'death' && payload.player_name) {
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
                logger.debug(`[Webhook] Recorded death for ${mcUsername}.`);

                const deathRecords = await ctx.database.get('minecraft_deaths', { mcUsername }, {
                    sort: { deathTime: 'desc' },
                });

                if (deathRecords.length > 5) {
                    const idsToDelete = deathRecords.slice(5).map(record => record.id);
                    const deleteResult = await ctx.database.remove('minecraft_deaths', { id: { $in: idsToDelete } });
                    logger.debug(`[Webhook] Deleted ${deleteResult.removed} old death records for ${mcUsername}.`);
                }

                c.response.status = 200;
                return 'Death recorded successfully';

            } catch (dbError: any) {
                logger.error(`[Webhook] Database error while recording death for ${mcUsername}:`, dbError);
                c.response.status = 500;
                return 'Database error recording death';
            }
        } else {
            logger.debug(`[Webhook] Received non-login event or missing data from ${c.request.ip}. Event type: ${payload.event_type}, Player: ${payload.player_name}`);
            c.response.status = 200;
            return 'Not a login event';
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
                });

                //logger.success(`[CodeCmd] Binding saved: ${session.platform}:${session.userId} <-> ${mcUsername}`);
                return `🎉 绑定成功！您的QQ账号 (${session.username}) 现已绑定到 Minecraft 账号: ${mcUsername}。现在可以进入服务器了。`;

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
            logger.debug(`[Middleware] Received potential verification code via DM: ${code}`);

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

                //logger.success(`[Middleware] Binding saved (DM): ${session.platform}:${session.userId} <-> ${mcUsername}`);

                const whitelistAddCmd = `whitelist add ${mcUsername}`;
                try {
                    const whitelistAddResp = await sendRconCommand(config, whitelistAddCmd);
                    //logger.info(`[Middleware] Added ${mcUsername} to whitelist after successful binding (DM). Response: ${whitelistAddResp}`);
                } catch (rconError: any) {
                    //logger.error(`[Middleware] Failed to add ${mcUsername} to whitelist after successful binding (DM):`, rconError.message);
                    await session.send(`注意：成功绑定账号 (${mcUsername})，但添加白名单失败 (${rconError.message})。请联系管理员手动添加白名单。`);
                    return;
                }

                await session.send(`🎉 绑定成功！您的QQ号 (${session.username}) 现已绑定到 Minecraft 账号: ${mcUsername}。现在可以进入服务器了。`);
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
}