package com.android.x;

/**
 * 壳源码按 com.android.x.MainActivity 引用设置入口。
 * 界面逻辑统一由项目自己的 MainActivity 提供，这里只保留类型桥接，
 * 让反编译出来的壳代码能继续编译。
 */
public class MainActivity extends github.shadowbaby.wechatxposed.hook.ui.MainActivity {
}
