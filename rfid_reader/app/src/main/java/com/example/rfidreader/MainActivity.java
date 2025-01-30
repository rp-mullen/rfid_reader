package com.example.rfidreader;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.Ndef;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import android.widget.Button;
import com.example.rfidreader.R;
import com.google.firebase.FirebaseApp;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends AppCompatActivity {
    private NfcAdapter nfcAdapter;
    private TextView textView;
    private DatabaseReference database;
    private Button saveButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        FirebaseApp.initializeApp(this);
        textView = findViewById(R.id.textView);
        saveButton = findViewById(R.id.saveButton);
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        database = FirebaseDatabase.getInstance().getReference();

        if (nfcAdapter == null) {
            Toast.makeText(this, "NFC not supported on this device", Toast.LENGTH_LONG).show();
            finish();
        }

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String data = textView.getText().toString();
                if (!data.isEmpty()) {
                    saveToFirebase(data);
                } else {
                    Toast.makeText(MainActivity.this, "No data to save", Toast.LENGTH_SHORT).show();
                }
            }
        });

    }

    @Override
    protected void onResume() {
        super.onResume();
        Intent intent = new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
    }

    @Override
    protected void onPause() {
        super.onPause();
        nfcAdapter.disableForegroundDispatch(this);
    }

    @SuppressLint("SetTextI18n")
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        if (tag != null) {
            Ndef ndef = Ndef.get(tag);
            if (ndef != null) {
                try {
                    ndef.connect();
                    NdefMessage messages = ndef.getNdefMessage();
                    if (messages != null) {
                        for (NdefRecord record : messages.getRecords()) {
                            byte[] payload = record.getPayload();
                            Charset textEncoding = (payload[0] & 0x80) == 0 ? Charset.forName("UTF-8") : Charset.forName("UTF-16");
                            String text = new String(payload, 3, payload.length - 3, textEncoding);
                            textView.setText("NDEF Tag Content: " + text);
                        }
                    }
                    ndef.close();
                } catch (Exception e) {
                    textView.setText("Error reading NDEF data");
                }
            } else {
                // Handle other tag types that do not support NDEF
                String tagTech = tag.getTechList()[1];
                if (tagTech.equals("android.nfc.tech.IsoDep")) {
                    // Handle ISO-DEP (for example, MIFARE or other ISO 14443-4 tags)
                    handleIsoDepTag(tag);
                } else if (tagTech.equals("android.nfc.tech.MifareClassic")) {
                    // Handle MIFARE Classic (e.g., older MIFARE tags)
                    handleMifareClassicTag(tag);
                } else if (tagTech.equals("android.nfc.tech.NfcA")) {
                    // Handle NFC-A (for example, NTAG tags)
                    handleNfcATag(tag);
                } else {
                    textView.setText("Tag detected but not NDEF-formatted");
                }
            }
        }
//        StringBuilder sb = new StringBuilder();
//        if (tag != null) {
//            String[] techList = tag.getTechList();
//            for (String tech : techList) {
//                sb.append("NFC + Tag supports: " + tech + "\n");
//            }
//        }
       // textView.setText(sb.toString());
    }

    private void handleIsoDepTag(Tag tag) {
        IsoDep isoDep = IsoDep.get(tag);
        try {
            isoDep.connect();
            // Send and receive commands to read or write data
            byte[] response = isoDep.transceive(new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x07});
            textView.setText("ISO-DEP Tag Data: " + bytesToHex(response));
        } catch (Exception e) {
            textView.setText("Error reading ISO-DEP tag");
        } finally {
            try {
                isoDep.close();
            } catch (Exception e) {
                // Handle closing failure
            }
        }
    }

    private void handleMifareClassicTag(Tag tag) {
        MifareClassic mifareClassic = MifareClassic.get(tag);
        try {
            mifareClassic.connect();

            // Authenticate to sector 1 with the default key
            boolean isAuthenticated = mifareClassic.authenticateSectorWithKeyA(1, MifareClassic.KEY_DEFAULT);
            if (isAuthenticated) {
                // Read a block from sector 1 (e.g., block 4)
                byte[] data = mifareClassic.readBlock(4);  // Sector 1 block 4
                textView.setText("MIFARE Classic Data: " + bytesToHex(data));
            } else {
                textView.setText("Authentication failed on sector 1");
            }

        } catch (Exception e) {
            textView.setText("Error reading MIFARE Classic tag: " + e.getMessage());
        } finally {
            try {
                mifareClassic.close();
            } catch (Exception e) {
                // Handle closing failure
            }
        }
    }

    private void handleNfcATag(Tag tag) {
        NfcA nfcA = NfcA.get(tag);
        try {
            nfcA.connect(); // Establish a connection with the tag

            // Send a simple command to read the UID of the NFC-A tag (0x30 is the READ command for NFC-A)
            byte[] command = new byte[] { 0x30, 0x00 };  // Standard command to read UID
            byte[] response = nfcA.transceive(command);

            // Check if response is valid (response length should be > 0)
            if (response != null && response.length > 0) {
                Log.d("NFC", "Received response: " + bytesToHex(response));
                textView.setText("NFC-A Tag UID: " + bytesToHex(response));
            } else {
                textView.setText("Failed to read NFC-A tag data");
            }

        } catch (Exception e) {
            textView.setText("Error reading NFC-A tag: " + e.getMessage());
        } finally {
            try {
                nfcA.close(); // Close the connection after reading
            } catch (Exception e) {
                // Handle closing failure
            }
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02X ", b));
        }
        return stringBuilder.toString();
    }

    private void saveToFirebase(String data) {
        Map<String, Object> tagEntry = new HashMap<>();

        String key = database.child("nfc_tags").push().getKey(); // Generate a unique key
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date());

        tagEntry.put("notes", data);
        tagEntry.put("timestamp", timestamp);

        database.push().setValue(tagEntry)
                .addOnSuccessListener(aVoid -> Toast.makeText(MainActivity.this, "Data Saved successfully!", Toast.LENGTH_SHORT).show())
                .addOnFailureListener(e -> Toast.makeText(MainActivity.this, "Failed to save tag", Toast.LENGTH_SHORT).show());
    }
}