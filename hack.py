import frida, sys

def on_message(message, data):
  if message['type'] == 'send':
    print("[*] {0}".format(message['payload']))
  else:
    print(message)

jscode = """
console.log('Started..');
Java.perform(function() {
  // var MainActivity = Java.use('com.wellbia.xigncode.XigncodeClient');
  // var MainActivity = Java.use('com.wellbia.xigncode.XigncodeClientSystem');
  // console.log(MainActivity.checkCheats);
  // console.log(MainActivity.OnHackDetected);
  // console.log(MainActivity.initialize);
  // MainActivity.onPause.implementation = function() {
  // MainActivity.ZCWAVE_OnActivityPause.overload().implementation = 
  // MainActivity.initialize.overload('android.app.Activity', 'java.lang.String', 'java.lang.String',
  //   'java.lang.String', 'com.wellbia.xigncode.XigncodeClientSystem$Callback').implementation = 

  var MainActivity = Java.use('net.kernys.aooni.MainActivity');
  MainActivity.OnHackDetected.overload('int', 'java.lang.String').implementation = function(arg0, arg1) {
    // console.log('com.wellbia.xigncode.XingcodeClient.initialize(' + arg0 + ', ' + arg1 + ', ' + arg2 + ')');
    console.log('MainActivity.OnHackDetected(' + arg0.toString(16) + ', ' + arg1 + ')');
  };

  var XigncodeActivity = Java.use('com.wellbia.xigncode.XigncodeActivity');
  XigncodeActivity.OnHackDetected.overload('int', 'java.lang.String').implementation = function(arg0, arg1) {
    console.log('[+] XigncodeActivity.OnHackDetected(' + arg0.toString(16) + ', ' + arg1 + ')');
  };

  var PauseActivity = Java.use('com.wellbia.xigncode.XigncodeClientSystem');
  PauseActivity.ZCWAVE_OnActivityPause.overload().implementation = function() {
    console.log('Done: ZCWAVE_OnActivityPause');
    // console.log("[+] send called from:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n") + " ");
    var addr = Thread.backtrace(this.context, Backtracer.ACCURATE);
    Process.enumerateModules({
      onMatch: function(module) {
        // console.log("- Module.name : " + module.name);
        // console.log("- Module.base : " + module.base);
      },
      onComplete: function() {
      }
    });

    for (var i = 0; i < addr.length; i++)
    {
      /*
      console.log('[+] Backtrace Address => ' + addr[i]);
      console.log(hexdump(addr[i], {
        offset: 0,
        length: 128,
        header: true,
        ansi: true
      }));
      */
    }
  };

  var xigncode = null;
  var xigncode_size = 0;
  var xraphael = null;
  var xraphael_size = 0;

  Process.enumerateModules({
    onMatch: function(module) {
      // console.log("- Module.name : " + module.name);
      // console.log("- Module.base : " + module.base);
      // console.log("- Module.size : " + module.size);

      if (module.name == "libxigncode.so")
      {
        xigncode = module.base;
        xigncode_size = module.size;

        console.log("- Module.name : " + module.name);
        console.log("- Module.base : " + module.base);
        console.log("- Module.size : " + module.size);
      }

      if (module.name == "xraphael_x86.xem")
      {
        xraphael =  module.base;
        xraphael_size = module.size;

        console.log("- Module.name : " + module.name);
        console.log("- Module.base : " + module.base);
        console.log("- Module.size : " + module.size);
      }       
    },
    onComplete: function() {
        console.log("[+] Process.enumerateModules Done.");
    }
  });

  // var xigncode = Process.findModuleByName("libxigncode.so");
  // var xigncode = Module.findBaseAddress("libxigncode.so");
  // if(xigncode != undefined && xraphael != undefined)

  if(xraphael != undefined)
  {
    Memory.protect(xraphael, xraphael_size, 'rwx');

    // var matches = Memory.scanSync(xigncode, xigncode_size,
    //      "55 89 E5 57 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ??  8D 64 24 A4 8B 75 08 65 A1 14");
    // var matches = Memory.scanSync(xigncode, xigncode_size, "49 6C 6C 65 67 61 6C 20 70 72 6F 67 72 61 6D 20 68 61 73 20 62 65 65 6E 20 64 65 74 65 63 74 65 64 20 62 79 20 58 49 47 4E 43 4F 44 45 33")
    // var matches = Memory.scanSync(xigncode, xigncode_size, "8B 44 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 10 83 C7 FC 83 EC 0C 56 52 51 50 57 E8 ?? ?? ?? ?? 83 C4 20 31 C0 5E 5F 5B C3")
    // var matches = Memory.scanSync(xigncode, xigncode_size, "0F 84 D0 00 00 00 83 EC 0C 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 69 C0 81 0F 7E 00 3D 4C A8 80 E3 7E 16 3D 4D A8 80 E3 74 1E 3D 54 ED A1 FC 75 1F 8D 83 DC 3D F5 FF EB 3B");

    var xraphael_matches = Memory.scanSync(xraphael, xraphael_size, "55 53 57 56 81 EC BC 06 00 00 E8 00 00 00 00 5B 81 C3 ED 77 22 00 8B BC 24 D4 06 00 00 8B B4 24 D0 06 00 00 65 A1 14 00 00 00 89 84 24 B8 06 00 00 83 FF 11 75 17 8B 46 18 8B 08 83 EC 0C 50 FF 51 20 83 C4 10 85 C0 0F 85 18 03 00 00");
    if (xraphael_matches.length != 0)
    {
      console.log('[PATCH TARGET FOUND] ' + xraphael_matches[0].address);
      Memory.writeU8(xraphael_matches[0].address, 0x31);
      Memory.writeU8(xraphael_matches[0].address.add(1), 0xC0);
      Memory.writeU8(xraphael_matches[0].address.add(2), 0xC3);
      console.log(hexdump(xraphael_matches[0].address, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
      }));
    }

    var xraphael_matches1 = Memory.scanSync(xraphael, xraphael_size, "55 53 57 56 81 EC CC 00 00 00 E8 00 00 00 00 5B 81 C3 49 6E 22 00 8B 8C 24 E0 00 00 00 65 A1 14 00 00 00 89 84 24 C8 00 00 00 8D 51 04 89 54 24 14 8B 41 04 39 D0 0F 84 F5 02 00 00 8D 8B ?? ?? ?? ?? 89 4C 24 20 8D 8B");
    if (xraphael_matches1.length != 0)
    {
      console.log('[PATCH TARGET FOUND] ' + xraphael_matches1[0].address);
      Memory.writeU8(xraphael_matches1[0].address, 0x31);
      Memory.writeU8(xraphael_matches1[0].address.add(1), 0xC0);
      Memory.writeU8(xraphael_matches1[0].address.add(2), 0xC3);
      console.log(hexdump(xraphael_matches1[0].address, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
      }));
    }

    var xraphael_matches2 = Memory.scanSync(xraphael, xraphael_size, "55 53 57 56 83 EC 1C E8 00 00 00 00 5B 81 C3 F0 6E 22 00 8B 44 24 30 8B 78 08");
    if (xraphael_matches2.length != 0)
    {
      console.log('[PATCH TARGET FOUND] ' + xraphael_matches2[0].address);
      Memory.writeU8(xraphael_matches2[0].address, 0x31);
      Memory.writeU8(xraphael_matches2[0].address.add(1), 0xC0);
      Memory.writeU8(xraphael_matches2[0].address.add(2), 0xC3);
      console.log(hexdump(xraphael_matches2[0].address, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
      }));
    }
  }

  if(xigncode != undefined)
  {
    Memory.protect(xigncode, xigncode_size, 'rwx');

    var xigncode_matches = Memory.scanSync(xigncode, xigncode_size, "53 E8 ?? ?? ?? ?? 81 C3 D9 AA 0E 00 8D 64 24 F8 8B 83 ?? ?? ?? ?? 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 8D 64 24 08 5B C3");
    if (xigncode_matches.length != 0)
    {
      console.log('[PATCH TARGET FOUND] ' + xigncode_matches[0].address);
      Memory.writeU8(xigncode_matches[0].address, 0x31);
      Memory.writeU8(xigncode_matches[0].address.add(1), 0xC0);
      Memory.writeU8(xigncode_matches[0].address.add(2), 0xC3);
      console.log(hexdump(xigncode_matches[0].address, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
      }));
    }
  }

  /*
  var buf = Memory.readByteArray(matches[0].address, 256);
  console.log(hexdump(buf, {
    offset: 0,
    length: 256,
    header: true,
    ansi: true
  }));

  Interceptor.attach(matches[0].address, {
    onEnter: function (args) {
      Memory.writeU16(matches[0].address.add(0x6E), 0x9090);
      console.log(hexdump(matches[0].address, {
        offset: 0,
        length: 256,
        header: true,
        ansi: true
      }));

      // var maxPatchSize = 64;
      // Memory.patchCode(matches[0].address.add(0x6E), maxPatchSize, function (code) {
      //   var cw = new X86Writer(code, { pc: matches[0].address });
      //   cw.putMovRegU32('eax', 9000);
      //   cw.putRet();
      //   cw.flush();
      // });

      console.log('[+] Trigger is called..');
    },
    onLeave: function (retval) {
      console.log("retval = " + retval.toInt32());
      retval.replace(219);
    }
  });

  Interceptor.attach(matches[0].address.add(0x82), {
    onEnter: function (args) {
      console.log('[+] OnHackDetected');
      console.log(hexdump(matches[0].address, {
        offset: 0,
        length: 256,
        header: true,
        ansi: true
      }));
    },
    onLeave: function (retval) {
    }
  });
  */

  /*
  var addr = Module.findExportByName("libc.so", "memcmp");
  console.log('addr = 0x' + addr.toString(16));
  Interceptor.attach(Module.findExportByName("libc.so", "memcmp"),
  {
    onEnter: function(args)
    {
      if(args[2].toInt32() > 0)
      {
        var src = Memory.readCString(ptr(args[0]), args[2].toInt32() + 1);
        var dst = Memory.readCString(ptr(args[1]), args[2].toInt32() + 1);
        if(dst.indexOf("/system/xbin/su") !== -1 || 
           dst.indexOf("/system/bin/su") !== -1 ||
           dst.indexOf("/system/app/SuperUser.apk") !== -1 ||
           dst.indexOf("/data/data/com.noshufou.android.su") !== -1 ||
           dst.indexOf("/sbin/su") !== -1)
        {
          console.log("args[1] = " + dst);
          console.log("[+] su detecting is founded. " + dst + " --> c8c8c8c8 is changed..");
          args[1] = ptr(0);
        }
      }
    },
    onLeave: function(retval)
    {
      // print retval
    }
  });
  */

  Interceptor.attach(Module.findExportByName(null, "exit"),
  {
    onEnter: function(args)
    {
      console.log("[+] exit() is called from:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n") + " ");
    },
    onLeave: function(retval)
    {
      retval = ptr(0);
    }
  });
});
"""

process = frida.get_usb_device().attach('net.kernys.aooni')
#device = frida.get_device_manager().enumerate_devices()[-1]
#pid = device.spawn(["net.kernys.aooni"])
#process = device.attach(pid)
#device.resume(pid)
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
