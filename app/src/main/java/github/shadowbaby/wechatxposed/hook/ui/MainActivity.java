package github.shadowbaby.wechatxposed.hook.ui;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.Toolbar;
import github.shadowbaby.wechatxposed.hook.BuildConfig;
import github.shadowbaby.wechatxposed.hook.R;
import github.shadowbaby.wechatxposed.hook.loader.SecretConstants;
import github.shadowbaby.wechatxposed.hook.loader.util.Secret;

/**
 * 模块主界面，对齐原版 X 3.0 的 MainActivity：
 * Toolbar + 「前往设置」「强制停止微信」两个按钮 + 显示/隐藏桌面图标的菜单。
 *
 * 原版点击「前往设置」不是直接 startActivity 微信设置页，而是拉起
 * LauncherUI 并带上 extra {@code gotosettings=cn.android.x}，由壳在微信进程内
 * 接管跳转；这里保持一致。
 */
public class MainActivity extends Activity {

    /** 桌面图标别名，必须和 AndroidManifest 里的 activity-alias 完全一致。 */
    private static final String ICON_ALIAS =
            "github.shadowbaby.wechatxposed.hook.ui.MainActivityAlias";

    /**
     * 包名取编译期常量，不能用 getPackageName()：
     * X30Compat 会把模块包名伪装成壳包名 cn.android.x，运行期读到的值不可靠，
     * 用它构造 ComponentName 会被系统当成未知组件直接抛 IllegalArgumentException。
     */
    private static final String MODULE_PACKAGE = BuildConfig.APPLICATION_ID;

    private static final String WECHAT = Secret.of(SecretConstants.WECHAT_PACKAGE);

    private static final String WECHAT_LAUNCHER =
            Secret.of(SecretConstants.WECHAT_LAUNCHER_CLASS);

    /** 壳识别的模块标识，与壳包名一致。 */
    private static final String SHELL_PACKAGE = Secret.of(SecretConstants.SHELL_PACKAGE);

    private static final String GOTO_SETTINGS = Secret.of(SecretConstants.SHELL_GOTO_SETTINGS);

    private MenuItem iconItem;

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            // 主题是 NoActionBar，必须把 Toolbar 交给 Activity 当 ActionBar，
            // 否则 onCreateOptionsMenu 不会被调用，显示/隐藏图标的菜单项就不见了。
            setActionBar(toolbar);
            toolbar.setTitle(getString(R.string.app_name));
        }
        Button settings = findViewById(R.id.goto_settings);
        if (settings != null) {
            settings.setOnClickListener(view -> openWechatSettings());
        }
        Button appInfo = findViewById(R.id.goto_wechat_appinfo);
        if (appInfo != null) {
            appInfo.setOnClickListener(view -> openWechatAppInfo());
        }
    }

    /** 拉起微信并让壳跳到设置页。 */
    private void openWechatSettings() {
        Intent intent = getPackageManager().getLaunchIntentForPackage(WECHAT);
        if (intent == null) {
            intent = new Intent();
            intent.setClassName(WECHAT, WECHAT_LAUNCHER);
        }
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtra(GOTO_SETTINGS, SHELL_PACKAGE);
        startActivity(intent);
    }

    /** 打开微信的系统应用详情页，用于强制停止。 */
    private void openWechatAppInfo() {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(Uri.parse("package:" + WECHAT));
            startActivity(intent);
        } catch (ActivityNotFoundException ignored) {
            startActivity(new Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS));
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        iconItem = menu.findItem(R.id.action_icon);
        updateIconTitle();
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_icon) {
            boolean enabled = iconAliasEnabled();
            getPackageManager().setComponentEnabledSetting(
                    new ComponentName(MODULE_PACKAGE, ICON_ALIAS),
                    enabled ? PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                            : PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    PackageManager.DONT_KILL_APP);
            updateIconTitle();
        }
        return super.onOptionsItemSelected(item);
    }

    private boolean iconAliasEnabled() {
        return getPackageManager().getComponentEnabledSetting(
                new ComponentName(MODULE_PACKAGE, ICON_ALIAS))
                == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
    }

    private void updateIconTitle() {
        if (iconItem != null) {
            iconItem.setTitle(iconAliasEnabled() ? R.string.hide_icon : R.string.show_icon);
        }
    }
}
