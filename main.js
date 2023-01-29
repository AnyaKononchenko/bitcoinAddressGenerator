let binaryPrivateKey = document.getElementById('binaryPrivateKey'),
    hexPrivateKey = document.getElementById('hexPrivateKey'),
    publicKey = document.getElementById('publicKey'),
    addr = document.getElementById('addr'),
    publicKeyCompressed = document.getElementById('publicKeyCompr'),
    addrCompressed = document.getElementById('addrCompr'),
    generateBtn = document.getElementById('generate');


function generateRandomBinary() {
    let bin = []
    for (let i = 0; i < 256; i++)
        bin.push(getRndInteger(0, 1));
    return bin.join('');
}

function getRndInteger(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function bin2hex(bin) {
    let i = 0, l = bin.length, chr, hex = '';
    let res = l % 4;
    for (i; i < l - res; i += 4) {
        chr = parseInt(bin.substr(-i - 4, 4), 2).toString(16);
        hex = chr.concat(hex);
    }
    if (res > 0) {
        hex = parseInt(bin.substr(0, res), 2).toString(16).concat(hex)
    } // converts the residual if bin str not devided by 4
    return hex;
}


function calcAddress(sec_key) {
    let hash_str = pad(sec_key, 64, "0");
    let hash = Crypto.util.hexToBytes(hash_str);
    let eckey = new Bitcoin.ECKey(hash);
    let eckey_c = new Bitcoin.ECKey(hash);
    let curve = getSECCurveByName("secp256k1");
    let pt = curve.getG().multiply(eckey.priv);
    eckey_c.pub = getEncoded(pt, true);
    eckey_c.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey_c.pub);//returns ripemd160(sha256())
    let hash160 = eckey.getPubKeyHash();
    let hash160_c = eckey_c.getPubKeyHash();

    let pubkey = Crypto.util.bytesToHex(getEncoded(pt, false));
    let pubkey_c = Crypto.util.bytesToHex(eckey_c.pub);
    let addr = new Bitcoin.Address(hash160);
    let addr_c = new Bitcoin.Address(hash160_c);
    return [pubkey, addr, pubkey_c, addr_c];
}

// Function add ch="0" to make the exact length
function pad(str, len, ch) {
    let padding = '';
    for (let i = 0; i < len - str.length; i++) {
        padding += ch;
    }
    return padding + str;
}

// Function returns compressed or uncompressed public key
function getEncoded(pt, compressed) {
    var x = pt.getX().toBigInteger();
    var y = pt.getY().toBigInteger();
    var enc = integerToBytes(x, 32);
    if (compressed) {
        if (y.isEven()) {
            enc.unshift(0x02);
        } else {
            enc.unshift(0x03);
        }
    } else {
        enc.unshift(0x04);
        enc = enc.concat(integerToBytes(y, 32));
    }
    return enc;
}


function init(){
    binaryPrivateKey.innerText = generateRandomBinary();
    hexPrivateKey.innerText = bin2hex(binaryPrivateKey.innerText);
    let res = calcAddress(hexPrivateKey.innerText);
    publicKey.innerText = res[0];
    addr.innerText = res[1].toString();
    publicKeyCompressed.innerText = res[2];
    addrCompressed.innerText = res[3].toString();
    addr.classList = 'payAttention';
}

generateBtn.addEventListener('click', init)