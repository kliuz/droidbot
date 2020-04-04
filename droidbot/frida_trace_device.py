import frida
import sys
import threading
import time  # TODO: delete

from queue import Queue

class FridaTrace(object):
    def __init__(self, app, q):
        """
        takes in the app name and an on_message function
        """
        self.app = app
        self.q = q
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

        try:
            thread = threading.Thread(target=self.start_trace, args=())
            thread.daemon = True
            thread.start()
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
    
    def start_trace(self):
        """
        start execution trace of the target app, will block indefinitely
        """

        # receive message from agent within app
        def on_message(message, data):
            """
            receives messages sent from inside the target process
            """
            if message["type"] != "error":
                self.q.put(message["payload"])

        def on_process_crashed(crash):
            """
            generate log when process crashes
            """
            print("crash", crash, crash.report)

        def on_detached(reason, crash):
            """
            record when process becomes detached
            """
            print("on_detached()")
            print("reason:", reason)
            print("crash:", crash)
            sys.exit()

        device = frida.get_usb_device(1)
        device.on("process-crashed", on_process_crashed)

        session = device.attach(self.app)
        session.on("detached", on_detached)

        script = session.create_script(self.script)
        script.on("message", on_message)
        print("loading script...")
        script.load()

        try:
            print("reading stdin...")
            sys.stdin.read()
        except (KeyboardInterrupt, SystemExit):
            sys.exit()

# q = Queue()
# ft = FridaTrace("com.whatsapp", q)

# while True:
#     print(q.get())