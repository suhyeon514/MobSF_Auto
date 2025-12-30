Java.perform(function() {
    console.log('[*] ===== 통합 스크립트 시작 (Loaded from External File) =====');

    // ---------------------------------------------------------
    // 1. 보안 탐지 우회 (Root/Emulator Check Bypass)
    // ---------------------------------------------------------
    try {
        // 타겟 클래스: com.ldjSxw.heBbQd.a.b
        var TargetClass = Java.use('com.ldjSxw.heBbQd.a.b');

        // k 메소드 후킹
        TargetClass.k.overload('android.content.Context').implementation = function(context) {
            console.log('[SUCCESS] 😈 보안 탐지 함수(a.b.k)가 호출됨! -> False 리턴하여 속임');
            return false; 
        };
        console.log('[+] 보안 탐지 함수(a.b.k) 후킹 설정 완료');

    } catch (e) {
        console.log('[!] 타겟 클래스(a.b) 로드 실패 혹은 찾을 수 없음: ' + e);
    }

    // ---------------------------------------------------------
    // 2. 좀비 모드: 앱 강제 종료 방지 (Safety Net)
    // ---------------------------------------------------------
    var Activity = Java.use("android.app.Activity");
    Activity.finish.overload().implementation = function() {
        var name = this.getClass().getName();
        console.log("[!] 앱이 스스로 종료(finish) 시도: " + name);
        
        if (name.indexOf("IntroActivity") !== -1 || name.indexOf("BaseActivity") !== -1) {
                console.log("    >>> 🛡️ 종료 방어 성공 (Zombie Mode)");
                return; 
        }
        this.finish();
    };

    var System = Java.use("java.lang.System");
    System.exit.implementation = function(code) {
        console.log("[!] System.exit(" + code + ") 호출됨 -> 🛡️ 차단");
    };
});