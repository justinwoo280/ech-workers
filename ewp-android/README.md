# EWP Android VPN Client

现代化的 Android VPN 客户端，基于 ewp-core gomobile 构建。

## 特性

- ✅ **现代化 UI** - Material Design 3 + Jetpack Compose
- ✅ **多协议支持** - WebSocket/gRPC/XHTTP
- ✅ **多安全特性** - ECH/Vision 流控/PQC
- ✅ **分应用代理** - 全局/绕过/仅代理三种模式
- ✅ **节点管理** - 添加/编辑/删除/选择节点
- ✅ **实时统计** - 流量、连接数、运行时间

## 架构

```
ewp-android/
├── app/src/main/java/com/echworkers/android/
│   ├── model/          # 数据模型
│   │   ├── EWPNode.kt
│   │   ├── ProxyMode.kt
│   │   ├── AppInfo.kt
│   │   └── VpnState.kt
│   ├── service/        # VPN 服务
│   │   └── EWPVpnService.kt
│   ├── data/           # Repository 层
│   │   ├── NodeRepository.kt
│   │   ├── VpnRepository.kt
│   │   └── AppRepository.kt
│   ├── viewmodel/      # ViewModel
│   │   └── MainViewModel.kt
│   ├── ui/             # UI 层
│   │   ├── screen/
│   │   │   ├── HomeScreen.kt
│   │   │   ├── NodeEditScreen.kt
│   │   │   └── AppSelectScreen.kt
│   │   ├── navigation/
│   │   │   └── Navigation.kt
│   │   └── theme/
│   │       ├── Color.kt
│   │       ├── Theme.kt
│   │       └── Type.kt
│   └── MainActivity.kt
└── app/libs/
    └── ewp-core.aar    # 从 ewp-core 编译得到
```

## 编译步骤

### 1. 编译 ewp-core AAR

```bash
cd ../ewp-core
build_android.bat
```

生成的 AAR 位于 `ewp-core/output/android/ewp-core.aar`

### 2. 复制 AAR 到项目

```bash
copy ..\ewp-core\output\android\ewp-core.aar app\libs\
```

### 3. 编译 APK

使用 Android Studio 打开项目或运行：

```bash
gradlew assembleDebug
```

## 使用说明

### 添加节点

1. 点击右下角 **+** 按钮
2. 填写节点信息：
   - **节点名称**：自定义名称
   - **服务器地址**：域名或 IP
   - **端口**：默认 443
   - **协议**：EWP 或 Trojan
   - **传输**：WebSocket/gRPC/XHTTP

### 连接 VPN

1. 在主界面选择节点
2. 点击 **连接** 按钮
3. 授予 VPN 权限
4. 连接成功后显示实时统计

### 分应用代理

1. 点击顶部应用图标进入应用选择
2. 选择代理模式：
   - **全局代理**：所有应用通过 VPN
   - **绕过模式**：勾选的应用不代理
   - **仅代理**：仅勾选的应用代理
3. 搜索并勾选应用
4. 返回主界面重新连接生效

## 技术栈

- **Kotlin** - 编程语言
- **Jetpack Compose** - UI 框架
- **Material Design 3** - 设计系统
- **Coroutines** - 异步编程
- **Kotlin Serialization** - JSON 序列化
- **StateFlow** - 响应式状态管理
- **VpnService** - Android VPN API
- **ewp-core (gomobile)** - Go 核心库

## 代理模式说明

### 全局代理
所有应用流量通过 VPN，最简单的模式。

### 绕过模式
勾选的应用直连，其他应用代理。适合：
- 国内应用直连（微信、支付宝等）
- 游戏直连避免延迟

### 仅代理
仅勾选的应用代理，其他直连。适合：
- 仅特定应用需要代理
- 节省流量

**注意**：本应用自身始终直连，避免 VPN 循环。

## 故障排除

### 连接失败

1. 检查节点配置是否正确
2. 检查网络连接
3. 查看日志：`adb logcat | grep EWP`

### 应用无法上网

1. 检查代理模式设置
2. 确认应用未被绕过
3. 重新连接 VPN

### 闪退

1. 确保 ewp-core.aar 是最新编译的
2. 检查日志中的错误信息
3. 重新安装应用

## License

MIT License
