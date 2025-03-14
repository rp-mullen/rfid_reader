// File generated by FlutterFire CLI.
// ignore_for_file: type=lint
import 'package:firebase_core/firebase_core.dart' show FirebaseOptions;
import 'package:flutter/foundation.dart'
    show defaultTargetPlatform, kIsWeb, TargetPlatform;

/// Default [FirebaseOptions] for use with your Firebase apps.
///
/// Example:
/// ```dart
/// import 'firebase_options.dart';
/// // ...
/// await Firebase.initializeApp(
///   options: DefaultFirebaseOptions.currentPlatform,
/// );
/// ```
class DefaultFirebaseOptions {
  static FirebaseOptions get currentPlatform {
    if (kIsWeb) {
      return web;
    }
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return android;
      case TargetPlatform.iOS:
        return ios;
      case TargetPlatform.macOS:
        return macos;
      case TargetPlatform.windows:
        return windows;
      case TargetPlatform.linux:
        throw UnsupportedError(
          'DefaultFirebaseOptions have not been configured for linux - '
          'you can reconfigure this by running the FlutterFire CLI again.',
        );
      default:
        throw UnsupportedError(
          'DefaultFirebaseOptions are not supported for this platform.',
        );
    }
  }

  static const FirebaseOptions web = FirebaseOptions(
    apiKey: 'AIzaSyC459x659zMXaUEq86fKk6rDzVDp_9fmIo',
    appId: '1:99581400570:web:c7b7c68f9cfe3af2b24043',
    messagingSenderId: '99581400570',
    projectId: 'rfid-reader-67828',
    authDomain: 'rfid-reader-67828.firebaseapp.com',
    databaseURL: 'https://rfid-reader-67828-default-rtdb.firebaseio.com',
    storageBucket: 'rfid-reader-67828.firebasestorage.app',
    measurementId: 'G-3YW6QR2P43',
  );

  static const FirebaseOptions android = FirebaseOptions(
    apiKey: 'AIzaSyBY-KMTwcV7ltbE3hWhpZ6hdxQ2aUKYn-U',
    appId: '1:99581400570:android:4e448787edad1800b24043',
    messagingSenderId: '99581400570',
    projectId: 'rfid-reader-67828',
    databaseURL: 'https://rfid-reader-67828-default-rtdb.firebaseio.com',
    storageBucket: 'rfid-reader-67828.firebasestorage.app',
  );

  static const FirebaseOptions ios = FirebaseOptions(
    apiKey: 'AIzaSyBrdjdlHyhGQjL6tT8SVZymRoZlmZUTHvo',
    appId: '1:99581400570:ios:efe350d874387c38b24043',
    messagingSenderId: '99581400570',
    projectId: 'rfid-reader-67828',
    databaseURL: 'https://rfid-reader-67828-default-rtdb.firebaseio.com',
    storageBucket: 'rfid-reader-67828.firebasestorage.app',
    iosBundleId: 'com.example.flutterRfid',
  );

  static const FirebaseOptions macos = FirebaseOptions(
    apiKey: 'AIzaSyBrdjdlHyhGQjL6tT8SVZymRoZlmZUTHvo',
    appId: '1:99581400570:ios:efe350d874387c38b24043',
    messagingSenderId: '99581400570',
    projectId: 'rfid-reader-67828',
    databaseURL: 'https://rfid-reader-67828-default-rtdb.firebaseio.com',
    storageBucket: 'rfid-reader-67828.firebasestorage.app',
    iosBundleId: 'com.example.flutterRfid',
  );

  static const FirebaseOptions windows = FirebaseOptions(
    apiKey: 'AIzaSyC459x659zMXaUEq86fKk6rDzVDp_9fmIo',
    appId: '1:99581400570:web:0354ecceb0f83251b24043',
    messagingSenderId: '99581400570',
    projectId: 'rfid-reader-67828',
    authDomain: 'rfid-reader-67828.firebaseapp.com',
    databaseURL: 'https://rfid-reader-67828-default-rtdb.firebaseio.com',
    storageBucket: 'rfid-reader-67828.firebasestorage.app',
    measurementId: 'G-7CBCZXM5XM',
  );
}
