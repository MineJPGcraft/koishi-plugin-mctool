# koishi-plugin-mctool

[![npm](https://img.shields.io/npm/v/koishi-plugin-mctool?style=flat-square)](https://www.npmjs.com/package/koishi-plugin-mctool)

与MC服务器互通

MC高级群服互通

搭配Minecraft Webhook插件（Spigot）使用以便接收webhook消息：https://github.com/MineJPGcraft/Minecraft-Webhook

功能：

1.QQ号与Minecraft绑定

2.死亡记录查询

3.在线人数查询

4. 同步聊天

还有更多功能逐步开发中！

## 账号绑定开关

配置项 `enableAccountBinding` 默认为 `true`。设为 `false` 后将关闭账号绑定及其相关功能，包括登录验证/警告、冻结与解冻、验证码、绑定状态查询、解绑、依赖绑定的死亡记录查询、加入/退出提醒和群聊 @ 游戏内提示；此模式仅保留群聊与 Minecraft 服务器之间的聊天互通。

## 群消息引用

插件会在内存中记录 `bindChannel` 最近一条非机器人群消息的消息 ID；不会保存消息正文，插件重启后记录清空。配置项 `quoteGroupCommandReplies` 默认为 `false`。开启后，仅由该群实际触发的插件指令回复会引用其触发消息；Minecraft Webhook 触发的独立群通知不会引用无关旧消息，也不会改变平台对主动消息的权限或频率限制。
