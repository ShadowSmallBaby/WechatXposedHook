package io.github.shadowbaby.wechatxposed.hook.ui;

import android.app.Activity;
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
import io.github.shadowbaby.wechatxposed.hook.BuildConfig;
import io.github.shadowbaby.wechatxposed.hook.R;
import io.github.shadowbaby.wechatxposed.hook.framework.HookBootstrap;
import io.github.shadowbaby.wechatxposed.hook.loader.SecretConstants;

public class MainActivity extends Activity {

    private static final String ICON_ALIAS = BuildConfig.APPLICATION_ID
            + ".ui.MainActivityAlias";

    private MenuItem iconItem;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setActionBar(toolbar);
        toolbar.setTitle(getString(R.string.app_name));

        Button appInfo = findViewById(R.id.goto_wechat_appinfo);
        appInfo.setOnClickListener(view -> openAppInfo());
        Button settings = findViewById(R.id.goto_settings);
        settings.setOnClickListener(view -> openWeChatSettings());
    }

    private void openAppInfo() {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", SecretConstants.WECHAT_PACKAGE, null));
            startActivity(intent);
        } catch (Throwable ignored) {

        }
    }

    private void openWeChatSettings() {
        Intent intent = getPackageManager()
                .getLaunchIntentForPackage(SecretConstants.WECHAT_PACKAGE);
        if (intent == null) {
            intent = new Intent().setClassName(SecretConstants.WECHAT_PACKAGE,
                    "com.tencent.mm.ui.LauncherUI");
        }
        intent.putExtra("gotosettings", HookBootstrap.shellPackage());
        start(intent);
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
            boolean enabled = iconEnabled();
            getPackageManager().setComponentEnabledSetting(
                    new ComponentName(BuildConfig.APPLICATION_ID, ICON_ALIAS),
                    enabled ? PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                            : PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    PackageManager.DONT_KILL_APP);
            updateIconTitle();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private boolean iconEnabled() {
        return getPackageManager().getComponentEnabledSetting(
                new ComponentName(BuildConfig.APPLICATION_ID, ICON_ALIAS))
                == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
    }

    private void updateIconTitle() {
        if (iconItem != null) {
            iconItem.setTitle(getString(iconEnabled()
                    ? R.string.hide_icon : R.string.show_icon));
        }
    }

    private boolean start(Intent intent) {
        if (intent == null) {
            return false;
        }
        try {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            return true;
        } catch (Throwable error) {
            return false;
        }
    }
}
