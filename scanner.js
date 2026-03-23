const DICTIONARY = {
    "INFRA": {
        "Firebase": "66 69 72 65 62 61 73 65 69 6f",
        "AWS_Key": "41 4b 49 41",
        "Google_Key": "41 49 7a 61"
    },
    "AUTH": {
        "JWT": "65 79 4a 68",
        "Bearer": "42 65 61 72 65 72 20",
        "OTP_Label": "6f 74 70 5f 63 6f 64 65"
    },
    "BUSINESS": {
        "Admin_Flag": "22 69 73 41 64 6d 69 6e 22",
        "CPF_Field": "22 63 70 66 22",
        "Email_Match": "40 67 6d 61 69 6c 2e 63 6f 6d",
        "JSON_PWD": "22 70 61 73 73 77 6f 72 64 22 3a", // "password":
        "JSON_SENHA": "22 73 65 6e 68 61 22 3a"       // "senha"
    },
    "TARGET": {
        "Google_Hex": "77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d"
    }
};

let reports = [];

function extractString(addr) {
    try {
        const buf = addr.readByteArray(256);
        const bytes = new Uint8Array(buf);
        let str = "";
        for (let i = 0; i < bytes.length; i++) {
            if (bytes[i] >= 32 && bytes[i] <= 126) str += String.fromCharCode(bytes[i]);
            else break;
        }
        return str;
    } catch (e) { return null; }
}

function startSuperScanner() {
    setInterval(() => {
        Process.enumerateRanges('rw-').forEach(range => {
            for (let category in DICTIONARY) {
                for (let label in DICTIONARY[category]) {
                    Memory.scan(range.base, range.size, DICTIONARY[category][label], {
                        onMatch: function(address, size) {
                            const data = extractString(address);
                            if (data && !reports.some(r => r.data === data)) {
                                const entry = {
                                    timestamp: new Date().toLocaleTimeString(),
                                    category: category,
                                    label: label,
                                    address: address.toString(),
                                    data: data
                                };
                                reports.push(entry);
                                
                                send(entry); 
                            }
                        },
                        onComplete: function() {}
                    });
                }
            }
        });
    }, 5000);
}

startSuperScanner();
