import type { Messages } from "@/locales/en"

/** Chinese texts. */
export const zh: Messages = {
  app: {
    signOut: "退出",
    otherLanguage: "English",
  },
  nav: {
    overview: "概览",
    config: "配置",
    versions: "版本",
  },
  common: {
    failed: "请求失败",
  },
  source: {
    db: "数据库",
    file: "文件",
    api: "API",
    ui: "面板",
    cli: "命令行",
  },
  login: {
    title: "登录 Wormway",
    description:
      "输入 Admin API 的 token。它保存在 Wormway 数据目录下的 admin.token 里；设置了 WORMWAY_ADMIN_TOKEN 时以它为准。",
    token: "Token",
    submit: "登录",
    wrongToken: "token 不正确。",
  },
  overview: {
    title: "概览",
    version: "Wormway 版本",
    uptime: "运行时长",
    config: "配置",
    configVersion: "{{source}}，版本 {{version}}",
    configNoVersion: "{{source}}，没有保存的版本",
    snapshot: "快照",
    listeners: "监听器",
    name: "名称",
    protocol: "协议",
    addresses: "地址",
    noListeners: "没有配置监听器。",
    instance: "实例 {{id}}",
  },
  config: {
    title: "配置",
    description: "当前生效的动态配置。",
    version: "版本 {{version}}",
    noVersion: "没有保存的版本",
    fileMode:
      "这些配置来自配置文件。修改文件后向 Wormway 发送 SIGHUP 即可生效。",
  },
  versions: {
    title: "版本",
    description:
      "每次修改都会保存为一个新版本。回滚会把旧版本的配置另存为一个新版本。",
    id: "版本",
    savedAt: "保存时间",
    source: "来源",
    comment: "备注",
    inEffect: "生效中",
    empty: "还没有保存过版本。",
    more: "加载更多",
    fileMode: "配置来自配置文件，保存的版本不会生效，也不能回滚。",
  },
  version: {
    title: "版本 {{id}}",
    back: "全部版本",
    rollback: "回滚到这个版本",
    confirmTitle: "回滚到版本 {{id}}？",
    confirmText: "版本 {{id}} 的配置会另存为一个新版本，并立即生效。",
    confirm: "回滚",
    cancel: "取消",
    rolledBack: "已回滚：当前生效的是版本 {{version}}。",
    unchanged: "这些配置已经在生效。",
    conflict: "配置在此期间被修改过。请查看版本列表后重试。",
    notFound: "版本 {{id}} 不存在。",
  },
  uptime: {
    days: "{{count}} 天",
    hours: "{{count}} 小时",
    minutes: "{{count}} 分钟",
    seconds: "{{count}} 秒",
  },
  notFound: {
    title: "页面不存在",
    back: "返回概览",
  },
}
