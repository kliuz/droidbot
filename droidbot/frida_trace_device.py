import frida
import goless
import sys
import time  # TODO: delete

class FridaTrace(object):
    def __init__(self, app, on_message):
        """
        takes in the app name and an on_message function
        """
        self.app = app
        self.on_message = on_message
        self.script = """
        Java.perform(function() {

        // affects messages in conversation
        const String = Java.use("java.lang.String");
        String.toString.implementation = function() {
            const str = this.toString();
            if (str.includes("hello")) {
                send("triggered String.toString");
                return str.replace("hello", "goodbye");
            } else {
                return str;
            }
        }
        String.getBytes.overload("java.nio.charset.Charset").implementation = function(charset) {
            send("triggered String.getBytes(" + charset + ") on string: " + this.toString());
            const val = this.getBytes(charset);
            return val;
        }
        String.valueOf.overload("boolean").implementation = function(b) {
            send("triggered valueOf(" + b + ")");
            return this.valueOf(b);
        }
        String.valueOf.overload("char").implementation = function(c) {
            send("triggered valueOf(" + c + ")");
            return this.valueOf(c);
        }

        // affects notifications
        const StringBuilder = Java.use("java.lang.StringBuilder");
        StringBuilder.toString.implementation = function() {
            const str = this.toString();
            if (str.includes("hello")) {
                send("triggered StringBuilder.toString");
                return str.replace("hello", "goodbye");
            } else {
                return str;
            }
        }

        const StringBuffer = Java.use("java.lang.StringBuffer");
        StringBuffer.toString.implementation = function() {
            const str = this.toString();
            if (str.includes("hello")) {
                send("triggered StringBuffer.toString");
                return str.replace("hello", "goodbye");
            } else {
                return str;
            }
        }
        });
        """

    def start_trace(self):
        def on_process_crashed(crash):
            """
            generate log when process crashes
            """
            print('crash', crash, crash.report)

        def on_detached(reason, crash):
            """
            record when process becomes detached
            """
            print("on_detached()")
            print("reason:", reason)
            print("crash:", crash)
            sys.exit()

        device = frida.get_usb_device(1)
        device.on('process-crashed', on_process_crashed)

        session = device.attach(self.app)
        session.on('detached', on_detached)

        script = session.create_script(self.script)
        script.on('message', self.on_message)
        print('loading script...')
        script.load()

        try:
            print('reading stdin...')
            sys.stdin.read()
        except KeyboardInterrupt:
            pass

chan1 = goless.chan()
chan2 = goless.chan()

# receive message from agent within app
def on_message(message, data):
    """
    receives messages sent from inside the target process
    """
    chan1.send(message["payload"])

def func2():
    time.sleep(2)
    chan2.send("booyah")

ft = FridaTrace("com.whatsapp", on_message)
goless.go(ft.start_trace())
goless.go(func2)

while True:
    case, val = goless.select([goless.rcase(chan1), goless.rcase(chan2)])
    print(val)