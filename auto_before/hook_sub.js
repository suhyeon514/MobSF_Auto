console.log("[JS] Sub-App Hook Script Loaded into PID: " + Process.id);

// 초기 진입점
if (typeof Java === 'undefined') {
    console.log("[JS] Java global not ready. Waiting...");
    setTimeout(tryInit, 1000);
} else {
    tryInit();
}

function tryInit() {
    // [핵심 수정] 함수 안에서도 Java가 정의되었는지 먼저 확인해야 함
    if (typeof Java === 'undefined') {
        console.log("[JS] Java still not defined (Native context). Retrying in 1s...");
        setTimeout(tryInit, 1000);
        return;
    }

    // Java 객체가 존재하면 사용 가능 여부 확인
    if (Java.available) {
        console.log("[JS] Java is available. Starting hook...");
        Java.perform(startHook);
    } else {
        console.log("[JS] Java found but not available. Retrying in 1s...");
        setTimeout(tryInit, 1000);
    }
}

function startHook() {
    try {
        console.log("[JS] Hook Logic Start...");
        var targetClass = "com.bosetn.oct16m.kits.Kit"; 
        var methodName = "t0"; 

        try {
            var Kit = Java.use(targetClass);
            console.log("[JS] Found class: " + targetClass);

            var overloads = Kit[methodName].overloads;
            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log("[JS] 💉 t0() called! Returning false.");
                    return false;
                };
            });
            console.log("[JS] Hook installed on " + methodName);

        } catch (err) {
            console.log("[JS] Class not found (yet): " + err.message);
        }

    } catch (e) {
        console.log("[JS] Error: " + e.message);
    }
}