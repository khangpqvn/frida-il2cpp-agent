import "frida-il2cpp-bridge";

let utils = {
  toast: function (message: string) {
    Java.perform(function () {
      var context = Java.use("android.app.ActivityThread")
        .currentApplication()
        .getApplicationContext();

      Java.scheduleOnMainThread(function () {
        var toast = Java.use("android.widget.Toast");
        toast
          .makeText(context, Java.use("java.lang.String").$new(message), 1)
          .show();
      });
    });
  },
};
export { utils };
