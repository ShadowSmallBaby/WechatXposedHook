import github.shadowbaby.wechatxposed.hook.license.LicenseData;
import java.util.List;

/** 打印 LicenseData 为每个账号生成的行,供 run.py 与 scripts/generate_min_db.py 逐行对照。 */
public final class LicenseDataCheck {

    private static final String PREFIX = "  ";

    public static void main(String[] args) {
        for (String account : args) {
            System.out.println("account " + account);
            List<LicenseData.Row> rows = LicenseData.rows(account);
            for (LicenseData.Row row : rows) {
                System.out.println(PREFIX + row.tag + " [" + row.type + "] " + row.value);
            }
        }
    }
}
