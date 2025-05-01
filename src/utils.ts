import { Config } from './';
import { Socket } from 'net';
import { Buffer } from 'buffer';

const RCON_PACKET_TYPE_AUTH = 3;
const RCON_PACKET_TYPE_COMMAND = 2;
const RCON_PACKET_TYPE_RESPONSE = 0;

/**
 * 将 Minecraft 死亡消息转换为中文 (针对 1.21.4+).
 * 采用正则表达式匹配，更灵活.
 *
 * @param deathMessage Minecraft 死亡消息.
 * @param filterNickname 是否过滤掉昵称.  默认为 false.
 * @returns 转换后的中文死亡消息, 如果无法转换则返回 null.
 */
export function translateDeathMessage(deathMessage: string, filterNickname: boolean = false): string {
    interface TranslationRule {
      regex: RegExp;
      translation: string;
      killerGroup?: number; // 可选：指定哪个捕获组是凶手 (从 1 开始计数)
    }
  
    const translationRules: TranslationRule[] = [
      {
        regex: /was shot by (.*)/i,
        translation: "被 $1 射杀",
        killerGroup: 1,
      },
      {
        regex: /was slain by (.*)/i,
        translation: "被 $1 杀死",
        killerGroup: 1,
      },
          {
        regex: /was blown up by (.*)/i,
        translation: "被 $1 炸飞",
        killerGroup: 1,
      },
       {
        regex: /drowned/i,
        translation: "溺水身亡",
      },
      {
        regex: /fell from a high place/i,
        translation: "从高处摔落",
      },
      {
        regex: /tried to swim in lava/i,
        translation: "试图在熔岩里游泳",
      },
    ];
  
    for (const rule of translationRules) {
      const match = deathMessage.match(rule.regex); // 尝试匹配正则表达式
      if (match) {
        let translatedMessage = rule.translation;
  
        // 替换 $1, $2 等占位符
        for (let i = 1; i < match.length; i++) {
          translatedMessage = translatedMessage.replace(`$${i}`, match[i]);
        }
  
        if (filterNickname) {
            if (translatedMessage.includes("被undefined")) {
                translatedMessage = "被" + translatedMessage.split("被")[1]
            }
        
        } else {
            //如果不过滤昵称，将玩家昵称添加到消息开头
            const victimName = deathMessage.split(" ")[0];
            translatedMessage = victimName + translatedMessage;
        }
  
        return translatedMessage;
      }
    }
    return deathMessage; // 没有找到匹配的规则
  }

  
export function createRconPacket(type: number, body: string): Buffer {
    const bodyBuffer = Buffer.from(body, 'utf8');
    const length = Buffer.byteLength(body, 'utf8') + 10;
    const buffer = Buffer.alloc(length + 4);

    buffer.writeInt32LE(length, 0);
    buffer.writeInt32LE(0, 4);
    buffer.writeInt32LE(type, 8);
    buffer.write(body, 12, 'utf8');
    buffer.writeInt16LE(0, length + 2);

    return buffer;
}
export async function sendRconCommand(config: Config, command: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const socket = new Socket()
        let authenticated = false
        let responseBuffer = ''
        let expectedLength = 0

        socket.connect(config.port, config.host, () => {
            const authPacket = createRconPacket(RCON_PACKET_TYPE_AUTH, config.password)
            socket.write(authPacket)
        })

        socket.on('data', (data) => {
            try {
                const packetLength = data.readInt32LE(0)
                const packetType = data.readInt32LE(4)

                if (packetType === RCON_PACKET_TYPE_RESPONSE) {
                    if (!authenticated) {
                        authenticated = true
                        const commandPacket = createRconPacket(RCON_PACKET_TYPE_COMMAND, command)
                        socket.write(commandPacket)
                    } else {
                        const offset = 12
                        if (offset < 0 || offset >= data.length) {
                            throw new RangeError(`Invalid offset: ${offset}`)
                        }
                        const responseData = data.toString('utf8', offset, packetLength + 4)
                        responseBuffer += responseData
                        if (responseBuffer.length >= expectedLength) {
                            resolve(responseBuffer)
                            socket.destroy()
                        }
                    }
                } else if (packetType === RCON_PACKET_TYPE_AUTH && data.readInt32LE(8) === -1) {
                    reject('RCON 认证失败：密码错误')
                    socket.destroy()
                }
            } catch (error) {
                reject(`RCON 数据包解析错误：${error.message}`)
                socket.destroy()
            }
        })

        socket.on('end', () => {
            resolve(responseBuffer)
        })

        socket.on('error', (err) => {
            reject(`RCON 连接错误：${err.message}`)
        })
    })
}