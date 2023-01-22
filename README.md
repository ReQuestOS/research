# Oculus Quest research
*Version 1.0*

This document is about the inner workings of the Oculus Quest. Most of it should apply for the Quest 2 as well, as they have the same OS (mostly)

It is aimed at people, wanting to find out how their Oculus Quest works. (I refuse to call it Meta Quest, cause that's a stupid name). If you know anything, not described here, create an issues or - better yet - a pull request. I'm thankful for all the help I can get.

## Basics
The Oculus Quest and Quest 2 both run a modified version of Android 10 (as of 2022-09-03) on top of Qualcomm Hardware. All the normal security measures are implemented and there is no public way to unlock the bootloader.

Luckily all system apps can be dumped using `adb` and REd using JADX. Almost all the information that you find here is obtained this way, so take it with a grain of salt.

## Quest Hardware (and low level software)

### Fastboot (ABL)
Nothing unusual. Currently, no access to a recent ABL binary.

Some commands, shown [here](https://github.com/QuestEscape/research#commands) seem to not be there anymore. Maybe they have a different name now.

#### RE Notes
ABL status bits `DAT_000848f0` (least to most significant):
* 0: is unlocked
* 1: is critical unlocked
* 2: is charger screen enabled
* 3: is retail device
* 4: is device tampered with
* 5: reserved???
* 6: verified boot enabled (ignored if device is locked)
* 7: verity enabled (ignored if device is locked)
* 8: boot with retail keymaster (only taken into account if device is critically unlocked)

Bootloader behavior:
* Verity status is controlled by DAT_000786c if device is not unlocked.
* Verified boot is always enabled if device is not unlocked
* Boot with retail keymaster is on if device is not unlocked otherwise it's off. If the device is critically unlocked, it can be controlled as stated above

## System Software
Mostly not obfuscated

### Injection Stuff
`com.facebook.inject`

Widely used dependency

TODO: More writeup

Some Strings:
* `UL`
* `ULSEP`
* `_UL__ULSEP_`

### System packages
The system packages can be found in four different places:
* /system/app
* /system/priv-app
* /system/product/app
* /system/product/priv-app

Some packages contain services. These services run in the background (mostly as system user) and do various things from OTA updates to the guardian system.

Note: NUX is a shorthand for "new user experience", so things that a new user sees on first start (Intro videos, tutorials, etc.).

#### Horizon
`com.oculus.horizon`

Not to be confused with "Horizon Worlds", Meta's new metaverse. This seems to be the core package that manages a lot of the Oculus system.

* User authentication (see [User Authentication](#user-authentication))
* Gatekeepers (see [Feature Gates](#feature-gates))

Application class `com.oculus.headlesshorizon.HeadlessHorizonApplication`

Made up of about 182 modules. These are annotated with `@InjectorModule`.

#### OSUpdater
`com.oculus.updater`

More about updates in section [OTA Updates](#ota-updates)

#### DeviceAuthServer
`com.oculus.deviceauthserver`

The device registers itself on Oculus' servers using a secret certificate stored on a partition that is inaccessible without root/system privileges. When it registers itself, it gets a few tokens that are later used for various purposes like fetching OTA updates. `DeviceAuthServer` manages all the tokens and certificates. The services only allows Oculus system apps to obtain tokens. The partition where the secret certificate is stored is mounted a `/persist`.

#### CompanionServer
`com.oculus.companion.server`

This service communicates with the Oculus companion (the Oculus app that you install on your phone). It can do a lot of things from enabling/disabling ADB to launching apps. It is registered as device administrator.

See [Companion App](#companion-app)

#### GatekeeperServer
`com.oculus.gatekeeperservice`

A caching proxy for the gatekeeper functionality in [Horizon](#horizon)

#### OCMS (Oculus mobility services)
`com.oculus.ocms`

TODO: Investigate

#### Yadi (YadiOs)
`com.oculus.yadi`

Internal package installer

#### VrShell
`com.oculus.vrshell`

Is responsible for displaying 2D UI and for hosting 2D apps.

`com.oculus.vrshell.home`

Hosts your home environment.

`com.oculus.vrshell.desktop`

Propably for work mode.

#### SystemUX
`com.oculus.systemux`

Provides system UI components. May be comparable to Android's systemui

#### Oculus Settings

Maybe in VRShell???

Oculus Settings app. The normal Android settings app is also present.


#### Meta Cam???
`com.oculus.metacam`

"Virtual camera" for casting in-headset content? Also named `vrcam`

#### Oculus Browser
`com.oculus.browser`

Chromium based browser. Codename `Carmel`???

#### Device Companion Manager
`com.android.companiondevicemanager`???

Maybe something with the [Companion App](#companion-app)?

### OTA Updates
TODO

### Framework additions (Oculus Platform)
Oculus have added quite a few APIs to the Android framework (found in `/system/framework/`). These are mostly wrappers far all the system services mentioned above.

Files: 
* `com.oculus.os.platform.jar`
* `com.oculus.os.platform-res.apk`
* `oculus-system-services.jar` ???

You can find all the oculus android permissions in `com.oculus.os.platform.jar` under `oculus.platform.Manifest`.

#### App Quirks
TODO

### Device Authentication
DeviceAuthServer

DeviceCertService: `/system/vendor/lib64/libdevicecertservice.so`

The first token is fetched from `https://graph.facebook-hardware.com/register`

New tokens are fetched from `https://graph.facebook-hardware.com/login_request`

The device certificate is needed for both operations.

Two certificates:
* For locked devices: `/persist/certificates/[ALIAS]/secure.crt`
* For unlocked devices: `/persist/certificates/[ALIAS]/insecure.crt`

Known aliases:
* `device_identity`


### User Authentication
User authentication is done by the [Horizon](#horizon) package.

Access tokens, scoped access tokens, app ids, app secrets

TODO: Investigate into Meta accounts

### Internal Facebook/Oculus API
Many system (Android) packages include an internal version of the Facebook and Oculus API. It looks like unused classes and functions are removed/collapsed during compilation. This leads to different instances of the same classes in different (Android) packages even though it's apparent that they once were the same thing. This is easy to see because of the (Java) package structure. 

### Feature Gates
TODO

### FBPermissions
Oculus/Facebook seem to have their own permission system for internal use. Each app contains the file `asstes/fbpermissions.json`. It contains a list of packages and the permissions, the app has for them along with a signature that will be verified by the target package.

`assets/fbpermissions.json`
```json
{
    "TARGET_PACKAGE_NAME": {
        "permissions": ["target.package.example.PERMISSION"], 
        "signature": {
            "algorithm": "sha256withrsa", 
            "value": "SIGNATURE IN BASE64"
        }
    },
    "SOME_OTHER_TARGET_PACKAGE_NAME": {
        ...
    },
    ...
}
```

SOME_PACKAGE has to be the package for which the permission is required??? TODO: How to calculate signature.

#### Signature generation (incomplete)
```java

ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

void generateDataToSign(Context context, String yourPackageName, String targetPackageName) {
    PackageInfo packageInfo = context.getPackageManager().getPackageInfo(yourPackageName, 64);

    byteArrayOutputStream.write(1);
    byteArrayOutputStream.write(permissions.count & 255);
    for (permission : permission) {
        writeString(permission);
    }
    
    byteArrayOutputStream.write(2);
    writeString(yourPackageName);

    byteArrayOutputStream.write(3);
    String yourPackageVersionCode = String.valueOf(packageInfo.getLongVersionCode());
    writeString(yourPackageVersionCode);

    byteArrayOutputStream.write(4);
    Signature signature = packageInfo.signatures[0];
    byte[] bytes = signature.toByteArray();
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(bytes);
    base64encodedSha265Hash = Base64.encodeToString(messageDigest2.digest());
    writeString(base64encodedSha265Hash);

    byteArrayOutputStream.write(5);
    writeString(targetPackageName);

    byte[] bytes = byteArrayOutputStream.toByteArray();
    bytes[1] = (byte) (5 & 255);
    // Here's your data. Now go sign it!
    // If you can ;)
    // Good luck finding Oculus' private certificate xD
}

void writeString(String string) {
	byte[] bytes = str.getBytes(charsetUtf8);
    int length = bytes.length;
    byteArrayOutputStream.write(length & 255);
    byteArrayOutputStream.write(bytes, 0, length);
}

```

#### Signature checking
The data has to be signed with the same private certificate as the target package.

```
TODO: Add public signature
```


### API Endpoints
There are a few GraphQL API endpoints that are used to get information about apps, updates and users.

* graph.oculus.com
* graph.facebook.com
* graph.[SOMETHING].oculus.com
* graph.[SOMETHING].facebook.com
* graph.facebook-hardware.com

The addresses with [SOMETHING] in them are used for internal testing.

* GET `/mobile_release_updates` (OTA updates)
* GET `/features` (config & gatekeepers)
* POST `/user_heartbeat?current_status=ONLINE`
* GET `/auth/create_session_for_app?format=json`
* GET `/auth/create_session_for_app?format=json&generate_session_cookies=1`
* GET & POST `/graphql`
* POST `/authenticate_application`
* POST `/two_factor_methods`
* POST `/device_scoped_user_access_token`
* POST `/fbauth`
* POST `/resend_delta_pin`
* POST `/two_factor_send_code`
* POST `/login_checkpoint_verify`
* POST `/two_factor_verify_code`
* POST `/device_remote_wipe_completed`
* ...

### Possible weak points
This is a list of weak points, I've come across during my research. These may or may not exist in future versions of the OS.

#### Hostname injection
`GraphQLClient` and other API classes look for the system property `debug.oculus.graphtier` that can be changed through the ADB shell using `setprop`. If it finds a value for the property, it will send all requests to `graph.[GRAPHTIER].oculus.com`. If we cleverly set the property to something like `example.com/` the device will build the base URL `graph.example.com/.oculus.com/` which we would result in a hostname of `graph.example.com`. We can then get a CA signed certificate, for example from Let's encrypt and use it in a program like Burp Suite to do a MITM attack. Now we only need to get around the certificate pinning.

#### Certificate (un)pinning
`FbCertificatePinnerFactory` checks if the build time is older than one year. By changing the current time, we can trick it into not pinning certificates. However, `FbPinningTrustManager` is actively pinning certificates.

On every request `FbPinningTrustManager` (or one of its extending classes) checks if the calling package is older than one year and if so, it disables pinning. While this would be easy to get around, many free CA signed SSL certificates are only valid for 90 days. This means that you can only set the time 90 days into the future while keeping the certificate valid. This means you have to wait at least 275 days without doing an update until this works.

## Companion App
Made with flutter?

## Fun facts
* Using the `settings` CLI app, you can change the display brightness and other settings, inaccessible from the GUI
* There seems to be a battery extension, referred to as `Molokini` (found in [Framework additions](#framework-additions-oculus-platform)) There are functions to calculate the total battery level of the internal and external battery as well some other things.
* The Quest can be in a docked state (at least there is code in [Framework additions](#framework-additions-oculus-platform) for it)

## Random Notes 'n Stuff
* Mobilelab (test)
* 

## Interesting resources
If you want to read more, have a look at these resources. I used some information from them, so thanks to all of those people.

* https://github.com/QuestEscape/research
* https://github.com/QuestEscape/updates
* https://github.com/ComputerElite/OculusGraphQLApiLib
* https://github.com/ComputerElite/OculusDB
* https://github.com/ComputerElite/QuestTools
* https://github.com/Blueforcer/Quest_Updater
* https://github.com/Nuvido/Quest2_Research
* https://github.com/basti564/Oculess
* https://github.com/facebookincubator/oculus-linux-kernel