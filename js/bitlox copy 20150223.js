
(function($) {

/////////////////////////////////////////////////
// functions from Brainwallet for message signing
/////////////////////////////////////////////////
    var key = null;
    var network = null;
    var gen_from = 'pass';
    var gen_compressed = false;
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var TIMEOUT = 600;
    var timeout = null;

    var PUBLIC_KEY_VERSION = 0;
    var PRIVATE_KEY_VERSION = 0x80;
    var ADDRESS_URL_PREFIX = 'http://blockchain.info'

    var sgData = null;
    var sgType = 'inputs_io';

    function setErrorState(field, err, msg) {
        var group = field.closest('.controls');
        if (err) {
            group.addClass('has-error');
            group.attr('title',msg);
        } else {
            group.removeClass('has-error');
            group.attr('title','');
        }
    }

    function sgOnChangeType() {
        var id = $(this).attr('name');
        if (sgType!=id)
        {
          sgType = id;
          if (sgData!=null)
            sgSign();
        }
    }

//     function updateAddr(from, to) {
    function updateAddr(to) {
//         var sec = from.val();
        var addr = '';
        var eckey = null;
        var compressed = false;
        try {
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
            if (payload.length > 32) {
                payload.pop();
                compressed = true;
            }
            eckey = new Bitcoin.ECKey(payload);
            var curve = getSECCurveByName("secp256k1");
            var pt = curve.getG().multiply(eckey.priv);
            eckey.pub = getEncoded(pt, compressed);
            eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.pub);
            addr = new Bitcoin.Address(eckey.getPubKeyHash());
            addr.version = (version-128)&255;
            setErrorState(from, false);
        } catch (err) {
            setErrorState(from, true, "Bad private key");
        }
        to.val(addr);
        return {"key":eckey, "compressed":compressed, "addrtype":version, "address":addr};
    }

    function sgGenAddr() {
        updateAddr($('#sgSec'), $('#sgAddr'));
    }

    function sgOnChangeSec() {
        $('#sgSig').val('');
        sgData = null;
        clearTimeout(timeout);
        timeout = setTimeout(sgGenAddr, TIMEOUT);
    }

    function fullTrim(message)
    {
        console.log("in FullTrim");
        message = message.replace(/^\s+|\s+$/g, '');
        message = message.replace(/^\n+|\n+$/g, '');
        return message;
    }

    var sgHdr = [
      "-----BEGIN BITCOIN SIGNED MESSAGE-----",
      "-----BEGIN SIGNATURE-----",
      "-----END BITCOIN SIGNED MESSAGE-----"
    ];

    var qtHdr = [
      "-----BEGIN BITCOIN SIGNED MESSAGE-----",
      "-----BEGIN BITCOIN SIGNATURE-----",
      "-----END BITCOIN SIGNATURE-----"
    ];

    function makeSignedMessage(type, msg, addr, sig)
    {
      if (type=='inputs_io')
        return sgHdr[0]+'\n'+msg +'\n'+sgHdr[1]+'\n'+addr+'\n'+sig+'\n'+sgHdr[2];
      else if (type=='armory')
        return sig;
      else
        return qtHdr[0]+'\n'+msg +'\n'+qtHdr[1]+'\nVersion: Bitcoin-qt (1.0)\nAddress: '+addr+'\n\n'+sig+'\n'+qtHdr[2];
    }

    function sgSign() {
      var message = $('#sgMsg').val();
      var p = updateAddr($('#sgSec'), $('#sgAddr'));

      if ( !message || !p.address )
        return;

      message = fullTrim(message);

      if (sgType=='armory') {
        var sig = armory_sign_message (p.key, p.address, message, p.compressed, p.addrtype);
      } else {
        var sig = sign_message(p.key, message, p.compressed, p.addrtype);
      }

      sgData = {"message":message, "address":p.address, "signature":sig};

      $('#sgSig').val(makeSignedMessage(sgType, sgData.message, sgData.address, sgData.signature));
    }

    function sgOnChangeMsg() {
        $('#sgSig').val('');
        sgData = null;
        clearTimeout(timeout);
        timeout = setTimeout(sgUpdateMsg, TIMEOUT);
    }

    function sgUpdateMsg() {
        $('#vrMsg').val($('#sgMsg').val());
    }

    // -- verify --
    function vrOnChangeSig() {
        //$('#vrAlert').empty();
        window.location.hash='#verify';
    }

    function vrPermalink()
    {
      var msg = $('#vrMsg').val();
      var sig = $('#vrSig').val();
      var addr = $('#vrAddr').val();
      return '?vrMsg='+encodeURIComponent(msg)+'&vrSig='+encodeURIComponent(sig)+'&vrAddr='+encodeURIComponent(addr);
    }

    function splitSignature(s)
    {
      var addr = '';
      var sig = s;
      if ( s.indexOf('\n')>=0 )
      {
        var a = s.split('\n');
        addr = a[0];

        // always the last
        sig = a[a.length-1];

        // try named fields
        var h1 = 'Address: ';
        for (i in a) {
          var m = a[i];
          if ( m.indexOf(h1)>=0 )
            addr = m.substring(h1.length, m.length);
        }

        // address should not contain spaces
        if (addr.indexOf(' ')>=0)
          addr = '';

        // some forums break signatures with spaces
        sig = sig.replace(" ","");
      }
      return { "address":addr, "signature":sig };
    }

    function splitSignedMessage(s)
    {
      s = s.replace('\r','');

      for (var i=0; i<2; i++ )
      {
        var hdr = i==0 ? sgHdr : qtHdr;

        var p0 = s.indexOf(hdr[0]);
        if ( p0>=0 )
        {
          var p1 = s.indexOf(hdr[1]);
          if ( p1>p0 )
          {
            var p2 = s.indexOf(hdr[2]);
            if ( p2>p1 )
            {
              var msg = s.substring(p0+hdr[0].length+1, p1-1);
              var sig = s.substring(p1+hdr[1].length+1, p2-1);
              var m = splitSignature(sig);
              msg = fullTrim(msg); // doesn't work without this
              return { "message":msg, "address":m.address, "signature":m.signature };
            }
          }
        }
      }
      return false;
    }

    function vrVerify() {
        var s = $('#vrSig').val();
        var p = splitSignedMessage(s);
        var res = verify_message(p.signature, p.message, PUBLIC_KEY_VERSION);

        if (!res) {
          var values = armory_split_message(s);
          res = armory_verify_message(values);
          p = {"address":values.Address};
        }

        $('#vrAlert').empty();

        var clone = $('#vrError').clone();

        if ( p && res && (p.address==res || p.address==''))
        {
          clone = p.address==res ? $('#vrSuccess').clone() : $('#vrWarning').clone();
          clone.find('#vrAddr').text(res);
        }

        clone.appendTo($('#vrAlert'));

        return false;
    }
/////////////////////////////////////////////////
/////////////////////////////////////////////////
// functions from Brainwallet for message signing
/////////////////////////////////////////////////
// END
/////////////////////////////////////////////////




    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    // BITLOX SPECIFIC
    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////




    ///////////////////////////////////////////////////////////////////////////////////////
    // PROTOBUF
    ///////////////////////////////////////////////////////////////////////////////////////




    function initialize_protobuf_encode() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();

//         var tempBuffer = ByteBuffer.allocate(1024);

		var randomnumber= d2h(Math.floor(Math.random()*1000000001));
        console.log("randomnumber: " + randomnumber);

//         var bb = new ByteBuffer();
//             bb.writeUint8(0x31);
//             bb.writeUint8(0x32);
// 			bb.flip();


		var bb = new ByteBuffer();
        var parseLength = randomnumber.length
// 	console.log("utx length = " + parseLength);
        var i;
        for (i = 0; i < parseLength; i += 2) {
            var value = randomnumber.substring(i, i + 2);
// 	console.log("value = " + value);		
            var prefix = "0x";
            var together = prefix.concat(value);
// 	console.log("together = " + together);
            var result = parseInt(together);
// 	console.log("result = " + result);

            bb.writeUint8(result);
        }
        bb.flip();
			
        var initializeContents = new Device.Initialize({
            "session_id": bb,
        });

        tempBuffer = initializeContents.encode();
        var tempTXstring = tempBuffer.toString('hex');
//         document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
        // 	console.log("txSize = " + txSize);
        // 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
        // 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "0017"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("init: " + tempTXstring);
		autoCannedTransaction(tempTXstring);


    }


	function directLoadWallet(walletToLoad) {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
	
		var walletToLoadNumber = Number(walletToLoad);
        var loadWalletMessage = new Device.LoadWallet({
			"wallet_number": walletToLoadNumber
        });    

	
        tempBuffer = loadWalletMessage.encode();
        var tempTXstring = tempBuffer.toString('hex');
        document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
	console.log("tempTXstring = " + tempTXstring);
// 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
// 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "000B"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("tempTXstring = " + tempTXstring);

        autoCannedTransaction(tempTXstring);
	}


    function constructOTP() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();

        var otpCommandValue = document.getElementById('otp_input').value;
        
// 		var bbOTP = new ByteBuffer();
//         var parseLength = otpCommandValue.length
// // 	console.log("utx length = " + parseLength);
//         var i;
//         for (i = 0; i < parseLength; i += 2) {
//             var value = otpCommandValue.substring(i, i + 2);
// // 	console.log("value = " + value);		
//             var prefix = "0x";
//             var together = prefix.concat(value);
// // 	console.log("together = " + together);
//             var result = parseInt(together);
// // 	console.log("result = " + result);
// 
//             bbOTP.writeUint8(result);
//         }
//         bbOTP.flip();
        
        var otpMessage = new Device.OtpAck({
			"otp": otpCommandValue
        });    

	
        tempBuffer = otpMessage.encode();
        var tempTXstring = tempBuffer.toString('hex');
        document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
	console.log("tempTXstring = " + tempTXstring);
// 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
// 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "0057"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("tempTXstring = " + tempTXstring);
        return tempTXstring;
    }


	function constructPIN() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
		var pin = Crypto.util.bytesToHex(Crypto.charenc.UTF8.stringToBytes(document.getElementById('pin_input').value));
		
		var bbPIN = new ByteBuffer();
        var parseLength = pin.length
// 	console.log("utx length = " + parseLength);
        var i;
        for (i = 0; i < parseLength; i += 2) {
            var value = pin.substring(i, i + 2);
// 	console.log("value = " + value);		
            var prefix = "0x";
            var together = prefix.concat(value);
// 	console.log("together = " + together);
            var result = parseInt(together);
// 	console.log("result = " + result);

            bbPIN.writeUint8(result);
        }
        bbPIN.flip();
        
        var pinAckMessage = new Device.PinAck({
			"password": bbPIN
        });    

	
        tempBuffer = pinAckMessage.encode();
        var tempTXstring = tempBuffer.toString('hex');
        document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
	console.log("tempTXstring = " + tempTXstring);
// 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
// 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "0054"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("tempTXstring = " + tempTXstring);

        autoCannedTransaction(tempTXstring);
	
	}

////////////////////////////
// New wallet
// 
// Responses: Success or Failure
// Response interjections: ButtonRequest
// wallet_name is stored purely for the convenience of the host. It should be
// a null-terminated UTF-8 encoded string with a maximum length of 40 bytes.
// To create an unencrypted wallet, exclude password.
// message NewWallet
// {
// 	optional uint32 wallet_number = 1 ;//[default = 0];
// 	optional bytes password = 2;
// 	optional bytes wallet_name = 3;
// 	optional bool is_hidden = 4 ;//[default = false];
// }
////////////////////////////

    function constructNewWallet() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
        
// WALLET NUMBER
		var walletNumber = Number(document.getElementById('new_wallet_number').value);
		
// PASSWORD
		var passwordString = document.getElementById('new_wallet_password').value;
		if (passwordString != ''){
			var password = Crypto.util.bytesToHex(Crypto.charenc.UTF8.stringToBytes(passwordString));
			console.log("pass: " + password);    
			var bbPass = new ByteBuffer();
			var parseLength = password.length
	// 	console.log("utx length = " + parseLength);
			var i;
			for (i = 0; i < parseLength; i += 2) {
				var value = password.substring(i, i + 2);
	// 	console.log("value = " + value);		
				var prefix = "0x";
				var together = prefix.concat(value);
	// 	console.log("together = " + together);
				var result = parseInt(together);
	// 	console.log("result = " + result);

				bbPass.writeUint8(result);
			}
			bbPass.flip();
		}else{
			var bbPass = null;
		}
		
// NAME
        var nameToUse = document.getElementById('new_wallet_name').value;
        console.log("name: " + nameToUse);    
            
        var nameToUseHexed = toHexPadded40bytes(nameToUse);    
        console.log("namehexed: " + nameToUseHexed);    
        
		var bbName = new ByteBuffer();
        var parseLength = nameToUseHexed.length
// 	console.log("utx length = " + parseLength);
        var i;
        for (i = 0; i < parseLength; i += 2) {
            var value = nameToUseHexed.substring(i, i + 2);
// 	console.log("value = " + value);		
            var prefix = "0x";
            var together = prefix.concat(value);
// 	console.log("together = " + together);
            var result = parseInt(together);
// 	console.log("result = " + result);

            bbName.writeUint8(result);
        }
        bbName.flip();
// end NAME        
        
        
// HIDDEN
		var is_hidden = document.getElementById("new_wallet_isHidden").checked;
		
		        
        
        var newWalletMessage = new Device.NewWallet({
        	"wallet_number": walletNumber
        	,
        	"password": bbPass
        	,
        	"wallet_name": bbName
        	,
        	"is_hidden": is_hidden
        });    
            
        tempBuffer = newWalletMessage.encode();
        var tempTXstring = tempBuffer.toString('hex');
        document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
	console.log("tempTXstring = " + tempTXstring);
// 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
// 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "0004"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("tempTXstring = " + tempTXstring);

        autoCannedTransaction(tempTXstring);

//         return renameCommand;
    }


////////////////////////////
// Rename loaded wallet
////////////////////////////

    function constructRenameWallet() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
        
        var nameToUse = document.getElementById('rename_wallet_input').value;
        console.log("name: " + nameToUse);    
            
        var nameToUseHexed = toHexPadded40bytes(nameToUse);    
        console.log("namehexed: " + nameToUseHexed);    
        
		var bb = new ByteBuffer();
        var parseLength = nameToUseHexed.length
// 	console.log("utx length = " + parseLength);
        var i;
        for (i = 0; i < parseLength; i += 2) {
            var value = nameToUseHexed.substring(i, i + 2);
// 	console.log("value = " + value);		
            var prefix = "0x";
            var together = prefix.concat(value);
// 	console.log("together = " + together);
            var result = parseInt(together);
// 	console.log("result = " + result);

            bb.writeUint8(result);
        }
        bb.flip();
        
        
        
        var walletrenameContents = new Device.ChangeWalletName({
        	"wallet_name": bb
        });    
            
        tempBuffer = walletrenameContents.encode();
        var tempTXstring = tempBuffer.toString('hex');
        document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
	console.log("tempTXstring = " + tempTXstring);
// 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
// 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "000F"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("tempTXstring = " + tempTXstring);

        autoCannedTransaction(tempTXstring);

//         return renameCommand;
    }


////////////////////////////
// Sign Message with address
////////////////////////////

	function signMessageWithDevice() {
		console.log("in signMessageWithDevice");
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();


	   	var message_string = document.getElementById("sgMsg").value;
	    message_string = fullTrim(message_string);
	    document.getElementById("sgMsgHidden").value = message_string;

		var message_concat_bytes = msg_bytes("Bitcoin Signed Message:\n").concat(msg_bytes(message_string));
		console.log("2b hashed msg bytes: " + message_concat_bytes);

		var message_concat_hex = Crypto.util.bytesToHex(message_concat_bytes);
		console.log("2b hashed msg hex: " +  message_concat_hex);


		
		address_handle_root = Number(document.getElementById("sgRoot").value);
		address_handle_chain = Number(document.getElementById("sgChain").value);
		address_handle_index = Number(document.getElementById("sgIndex").value);
		
		var bb = new ByteBuffer();
        var parseLength = message_concat_hex.length
// 	console.log("utx length = " + parseLength);
        var i;
        for (i = 0; i < parseLength; i += 2) {
            var value = message_concat_hex.substring(i, i + 2);
// 	console.log("value = " + value);		
            var prefix = "0x";
            var together = prefix.concat(value);
// 	console.log("together = " + together);
            var result = parseInt(together);
// 	console.log("result = " + result);

            bb.writeUint8(result);
        }
        bb.flip();

		var txContents = new Device.SignMessage({
		"address_handle_extended": 
				{
					"address_handle_root": address_handle_root, 
					"address_handle_chain": address_handle_chain, 
					"address_handle_index": address_handle_index
				},
		"message_hash": bb
// 		,
// 		"message_data": message_string
		});
        tempBuffer = txContents.encode();
        var tempTXstring = tempBuffer.toString('hex');
        document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
// 	console.log("txSize = " + txSize);
// 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
// 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "0070"; 
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        console.log("tempTXstring = " + tempTXstring);

        autoCannedTransaction(tempTXstring);
		
	}

////////////////////////////
// Create Wallets
////////////////////////////

    var createWallet = function() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
	}
	
	
////////////////////////////
// Sign Transaction Prep
////////////////////////////

    var prepForSigning = function(unsignedtx, originatingTransactionArray, originatingTransactionArrayIndices, address_handle_chain, address_handle_index) {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
            
            
        console.log("OTA 0: " + originatingTransactionArray[0]);
        console.log("OTA 1: " + originatingTransactionArray[1]);

		var numberOfInputsinArray = originatingTransactionArray.length;
        console.log("numberOfInputsinArray: " + numberOfInputsinArray);
        
        
		var address_handle_root = [];
		address_handle_root[0] = 0;
		address_handle_root[1] = 0;

		var address_handle_extended_data = []; // empty array
		var k;
		for (k=0;k<numberOfInputsinArray;k++)
		{
			address_handle_extended_data.push({address_handle_root: address_handle_root[k], address_handle_chain: address_handle_chain[k], address_handle_index: address_handle_index[k]});
		}
		console.log(JSON.stringify(address_handle_extended_data));

// INPUTS
		var inputHexTemp = "";
		var j;
		for (j=0; j<numberOfInputsinArray; j++){
//         wrapper:
			var tempOriginating = "";
			var is_ref01 = "01";
			var output_num_select = valueFromInteger(originatingTransactionArrayIndices[j]);
//         previous transaction data:
			output_num_select = Crypto.util.bytesToHex(output_num_select);
			console.log("output_num_select: " + j +" : "+ output_num_select);
			tempOriginating = is_ref01.concat(output_num_select);
			tempOriginating = tempOriginating.concat(originatingTransactionArray[j]);
			inputHexTemp = inputHexTemp.concat(tempOriginating);
		}
// END INPUTS
        var tempBuffer = ByteBuffer.allocate(1024);
// OUTPUTS
        var is_ref00 = "00";
        unsignedtx = is_ref00.concat(unsignedtx);
        console.log("utx = " + unsignedtx);
        var hashtype = "01000000";
        unsignedtx = unsignedtx.concat(hashtype);

        unsignedtx = inputHexTemp.concat(unsignedtx);
        
		var sizeOfInput =  unsignedtx.length;
        console.log("sizeOfInput = " + sizeOfInput);

        var bb = ByteBuffer.allocate((sizeOfInput/2)+64);

        var i;
        for (i = 0; i < sizeOfInput; i += 2) {
            var value = unsignedtx.substring(i, i + 2);
            // 		console.log("value = " + value);		
            var prefix = "0x";
            var together = prefix.concat(value);
            // 		console.log("together = " + together);
            var result = parseInt(together);
            // 		console.log("result = " + result);

            bb.writeUint8(result);
        }
        bb.flip();
// END OUTPUTS




		console.log("address_handle_chain[0]" + address_handle_chain[0]);       
		console.log("address_handle_index[0]" + address_handle_index[0]);       
      

//         var txContents = new Device.SignTransactionExtended({
//         	"address_handle_extended": address_handle_extended_data
//         	,
//             "transaction_data": bb
//         });
        
        
         var txContents = new Device.SignTransactionExtended({
        	"address_handle_extended": 
        	[
        		{
					"address_handle_root": address_handle_root[0], 
					"address_handle_chain": address_handle_chain[0], 
					"address_handle_index": address_handle_index[0]
				}
// 				depending on the number of inputs this will be extended as shown
				,
        		{
					"address_handle_root": address_handle_root[1], 
					"address_handle_chain": address_handle_chain[1], 
					"address_handle_index": address_handle_index[1]
				}
			],
            "transaction_data": bb
        });
        

               
        tempBuffer = txContents.encodeDelimited();
        
        
        var tempTXstring = tempBuffer.toString('hex');
//         document.getElementById("temp_results").innerHTML = tempTXstring;
        txSize = d2h((tempTXstring.length) / 2).toString('hex');
        // 	console.log("txSize = " + txSize);
        // 	console.log("txSize.length = " + txSize.length);
        var j;
        var txLengthOriginal = txSize.length;
        for (j = 0; j < (8 - txLengthOriginal); j++) {
            var prefix = "0";
            txSize = prefix.concat(txSize);
        }
        // 	console.log("txSizePadded = " + txSize);
        tempTXstring = txSize.concat(tempTXstring);

        var command = "0065"; // extended
        tempTXstring = command.concat(tempTXstring);

        var magic = "2323"
        tempTXstring = magic.concat(tempTXstring);
        document.getElementById("device_signed_transaction").textContent = tempTXstring;
    }

    var sendTransactionForSigning = function() {
        var preppedForDevice = document.getElementById("device_signed_transaction").textContent;
        // 	console.log("send to device = " + preppedForDevice);
        autoCannedTransaction(preppedForDevice);
//         pausecomp(50);
//         hidWriteRawData(deviceCommands.button_ack);

    }




    ///////////////////////////////////////////////////////////////////////////////////////
    // PROTOBUF (end)
    ///////////////////////////////////////////////////////////////////////////////////////

    // constants 
    var pollInterval = 500;

    var hidapiPluginConstants = {
        VendorID: 0x03EB,
        ProductID: 0x204F
            //0x6E68   
    };
    //         var hidapiPluginConstants = {
    //             VendorID:  0x03EB, 
    //             ProductID: 0x6e68
    //             //0x6E68   
    //         };

    function getMnemonic() {
        //         	var entropy = '99,219,173,7,201,65,77,162,9,160,160,128,12,40,208,35,123,231,35,53,209,47,40,174,152,130,112,65,197,246,201,9';
        //         	var entropy = '63DBAD07C9414DA209A0A0800C28D0237BE72335D12F28AE98827041C5F6C909';
        var entropy128 = '63DBAD07C9414DA209A0A0800C28D023';
        // 			var entropyBytes=new Uint8Array(32);        	
        // 			entropyBytes = (0x63,0xDB,0xAD,0x07,0xC9,0x41,0x4D,0xA2,0x09,0xA0,0xA0,0x80,0x0C,0x28,0xD0,0x23,0x7B,0xE7,0x23,0x35,0xD1,0x2F,0x28,0xAE,0x98,0x82,0x70,0x41,0xC5,0xF6,0xC9,0x09);
        var mnemonic = BIP39.entropyToMnemonic(entropy128);
        document.getElementById("mnemonic").innerHTML = mnemonic;

        var seedHex = BIP39.mnemonicToSeedHex(mnemonic)
        document.getElementById("seed").innerHTML = seedHex;
    }

    var deviceCommands = {
        initialize: '232300170000000A0A083132333435363738',
        ping: '23230000000000070A0548656C6C6F',
        format_storage: '2323000D000000220A204242424242424242424242424242424242424242424242424242424242424242',
        get_master_public_key: '2323001500000000',
        button_ack: '2323005100000000',
        button_cancel: '2323005200000000',
        pin_cancel: '2323005500000000',
        otp_ack: '23230057000000060A04', //'23230057000000060A0435383532' sample with 0x35383532 as otp return 5852
        otp_cancel: '2323005800000000',

        list_wallets: '2323001000000000',
        backup_wallet: '2323001100000000',

        scan_wallet: '2323006100000000',
        new_wallet_0:  '23230004000000020800',
        new_wallet_1:  '23230004000000020801',
        new_wallet_2:  '23230004000000020802',
        new_wallet_3:  '23230004000000020803',
        new_wallet_4:  '23230004000000020804',
        new_wallet_5:  '23230004000000020805',
        new_wallet_6:  '23230004000000020806',
        new_wallet_7:  '23230004000000020807',
        new_wallet_8:  '23230004000000020808',
        new_wallet_9:  '23230004000000020809',
        new_wallet_10: '2323000400000002080A',
        new_wallet_11: '2323000400000002080B',
        new_wallet_12: '2323000400000002080C',
        new_wallet_13: '2323000400000002080D',
        new_wallet_14: '2323000400000002080E',
        new_wallet_15: '2323000400000002080F',
        new_wallet_16: '23230004000000020810',
        new_wallet_17: '23230004000000020811',
        new_wallet_18: '23230004000000020812',
        new_wallet_19: '23230004000000020813',
        new_wallet_20: '23230004000000020814',
        new_wallet_21: '23230004000000020815',
        new_wallet_22: '23230004000000020816',
        new_wallet_23: '23230004000000020817',
        new_wallet_24: '23230004000000020818',
        new_wallet_25: '23230004000000020819',

        load_wallet:    '2323000B00000000',
        load_wallet_0:  '2323000B000000020800',
        load_wallet_1:  '2323000B000000020801',
        load_wallet_2:  '2323000B000000020802',
        load_wallet_3:  '2323000B000000020803',
        load_wallet_4:  '2323000B000000020804',
        load_wallet_5:  '2323000B000000020805',
        load_wallet_6:  '2323000B000000020806',
        load_wallet_7:  '2323000B000000020807',
        load_wallet_8:  '2323000B000000020808',
        load_wallet_9:  '2323000B000000020809',
        load_wallet_10: '2323000B00000002080A',
        load_wallet_11: '2323000B00000002080B',
        load_wallet_12: '2323000B00000002080C',
        load_wallet_13: '2323000B00000002080D',
        load_wallet_14: '2323000B00000002080E',
        load_wallet_15: '2323000B00000002080F',
        load_wallet_16: '2323000B000000020810',
        load_wallet_17: '2323000B000000020811',
        load_wallet_18: '2323000B000000020812',
        load_wallet_19: '2323000B000000020813',
        load_wallet_20: '2323000B000000020814',
        load_wallet_21: '2323000B000000020815',
        load_wallet_22: '2323000B000000020816',
        load_wallet_23: '2323000B000000020817',
        load_wallet_24: '2323000B000000020818',
        load_wallet_25: '2323000B000000020819',

        delete_wallet_0: '23230016000000020800',
        delete_wallet_1: '23230016000000020801',
        delete_wallet_2: '23230016000000020802',
        delete_wallet_3: '23230016000000020803',
        delete_wallet_4: '23230016000000020804',
        delete_wallet_5: '23230016000000020805',

        get_entropy_4096_bytes: '2323001400000003088020',
        get_entropy_32_bytes: '23230014000000020820',
        reset_lang: '2323005900000000',
        get_device_uuid: '2323001300000000',
        features: '2323003A00000000',
        deadbeef: '7E7E',
    };



    function pausecomp(ms) {
        ms += new Date().getTime();
        while (new Date() < ms) {}
    }


    // "globals" 
    var incoming = '';
    var prevsD = '';
    var plugin;
    var result;
    var path;
    var device = null;
    var deviceUnplugged = false;
    var deviceOpen = false;
    var edge = false;

    function pausecomp(milliseconds) {
        var start = new Date().getTime();
        for (var i = 0; i < 1e7; i++) {
            if ((new Date().getTime() - start) > milliseconds) {
                break;
            }
        }
    }


    String.prototype.chunk = function(n) {
        if (typeof n == 'undefined') n = 2;
        return this.match(RegExp('.{1,' + n + '}', 'g'));
    };

    var padding = Array(64).join('0');

    function pad(pad, str, padLeft) {
        if (str == undefined) return pad;
        if (padLeft) {
            return (pad + str).slice(-pad.length);
        } else {
            return (str + pad).substring(0, pad.length);
        }
    }

    function d2h(d) {
        return d.toString(16);
    }

    function h2d(h) {
        return parseInt(h, 16);
    }

    function toHex(str) {
        var hex = '';
        for (var i = 0; i < str.length; i++) {
            hex += '' + str.charCodeAt(i).toString(16);
        }
        return hex;
    }

    function toHexPadded40bytes(str) {
        var hex = '';
        var length = 40;
		var bytes;
        if (str.length <= 40) {
            length = str.length;
        }

		hex = Crypto.util.bytesToHex(Crypto.charenc.UTF8.stringToBytes(str));
		

        while (hex.length < 80) {
            hex += '20';
        }
        return hex;
    }



    function hex2a(hexx) {
        var hex = hexx.toString(); //force conversion
        var str = '';
        for (var i = 0; i < hex.length; i += 2)
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        return str;
    }

    function pluginLoaded() {
        pluginDetect();
        console.log("Plugin loaded!");
        hidScan();
    }

    // function pluginDetect() install, detect plugin 
    var FireBreath;
    var el = "";
    var mimeType = "application/x-hidapibrowserplugin";
    var name = "hidapiBrowserPlugin";

    function pluginDetect() {
            if (typeof FireBreath === 'undefined') {
                FireBreath = {};
                FireBreath.pluginDefs = {};

                if (typeof(navigator.plugins[name]) != "undefined") {
                    var re = /([0-9.]+)\.dll/; // look for the version at the end of the filename, before dll

                    // Get the filename
                    var filename = navigator.plugins[name].filename;
                    // Search for the version
                    var fnd;
                    fnd = re.exec(filename);
                    if (fnd === null) { // no version found
                        return true; // plugin installed, unknown version
                    } else {
                        return fnd[1]; // plugin installed, returning version
                    }

                } // end if typeof(navigator.plugins[name]) != "undefined" 
                else { //	else not installed; install it now: 
                    alert("plugin not installed. ");
                }
            } // end if typeof FireBreath === 'undefined'
        } // end function pluginDetect() 

    function hidScan() {
            plugin = document.getElementById("hidapiPlugin");
            result = plugin.hid_enumerate();

            for (var i = 0; i < result.length; i++) {
                if ((result[i]["vendor_id"] == hidapiPluginConstants.VendorID) && (result[i]["product_id"] == hidapiPluginConstants.ProductID)) {
                    document.getElementById("status").innerHTML = "Device Connected";
                    path = result[i]["path"];
                    break;
                }
            }
            if (typeof path == "undefined") {
                deviceOpen = false;
                document.getElementById("status").innerHTML = "Device not found";
                // 				alert("Device not found");
                return;
            }
            if (deviceOpen == false) {
                device = plugin.hid_open_path(path);
                if (device == null) {
                    alert("Error opening device");
                    deviceOpen = false;
                    return;
                } else {
                    deviceOpen = true;
                    deviceUnplugged = false;
                    setTimeout(monitorUSBHID, 50); //##########################
                    console.log("hidScan: Found USB device");
                }
            } else {
                console.log("hidScan: USB device online");
                // 				pausecomp(10000); 
                //             	hidWriteRawData(deviceCommands.list_wallets);
            }
        } //end hidScan()

    function monitorUSBHID() {
            if (device != null) { // device enumerated, opened
                // 				hid_set_nonblocking(1);
                hidReadData(); //Parse incoming frame
            } else if (deviceUnplugged == true) { // unplugged 
                result = null;
                result = plugin.hid_enumerate();
                if (result != null) {
                    // plugged back in? finish hidScan():  this needs some work still
                    for (var i = 0; i < result.length; i++) {
                        if ((result[i]["vendor_id"] == hidapiPluginConstants.VendorID) && (result[i]["product_id"] == hidapiPluginConstants.ProductID)) {
                            path = result[i]["path"];
                            if (typeof path == "undefined") {
                                deviceOpen = false;
                                alert("Device not found");
                            }
                            if (deviceOpen == false) {
                                device = plugin.hid_open_path(path);
                                if (device == null) {
                                    document.getElementById("status").innerHTML = "Error opening device";
                                    // 									alert("Error opening device");
                                    deviceOpen = false;
                                } else {
                                    deviceOpen = true;
                                    deviceUnplugged = false;
                                    setTimeout(monitorUSBHID, 50); //##########################
                                    document.getElementById("status").innerHTML = "Device Connected";
                                    // 									alert("monitorUSBHID: Found HID device");
                                }
                            } else {
                                document.getElementById("status").innerHTML = "Device reconnected";
                                // 								alert("Device re-opened");
                            }
                            break;
                        }
                    }
                } //  end  if (result != null) 
            } //  end  else if (deviceUnplugged == true) 
            setTimeout(monitorUSBHID, 50); //##########################
        } //end monitorUSBHID

    function hidWriteData(dataToSend) {
        var sendToDevice = '';
        var name_element = document.getElementById(dataToSend);
        var name = name_element.value;
        sendToDevice = name;
        sendToDevice = '00' + sendToDevice + '7E7E';
        var txResult = device.hid_write(sendToDevice);
        // 			console.log('HID TX size: ' + txResult);
    }

    function hidWriteRawData(dataToSend) {
        sendToDevice = '00' + dataToSend + '7E7E';
        var txResult = device.hid_write(sendToDevice);
//         console.log("TX: " + sendToDevice);
    }


    //Grab the incoming frame 
    function hidReadData() {
        var sD = '';
        var magic = '2323';
        sD = device.hid_read(64);
        if (((sD[60] != 2) || (sD[61] != 3)) && ((sD[62] == 2) && (sD[63] == 3))) {
            //                     console.log('EDGE:' + sD);
            sD = sD + device.hid_read(64);
            //                     console.log('EDGE WRAP:' + sD);
        }

        if (sD.match(/2323/)) {
            headerPosition = sD.search(2323)
            if (headerPosition >= 48) sD = sD + device.hid_read(64);
            var command = sD.substring(headerPosition + 4, headerPosition + 8)
            document.getElementById("command").innerHTML = command;
            var payloadSize = sD.substring(headerPosition + 8, headerPosition + 16)
            decPayloadSize = h2d(payloadSize);
            document.getElementById("payLoadSize").innerHTML = payloadSize;
            while ((headerPosition + 16 + 2 * (decPayloadSize)) > sD.length) {
                sD = sD + device.hid_read(64);
            }
            var payload = sD.substring(headerPosition + 16, headerPosition + 16 + (2 * (decPayloadSize)))
            document.getElementById("payload_HEX").innerHTML = payload;
            document.getElementById("payload_ASCII").innerHTML = hex2a(payload);
            processResults(command, payloadSize, payload);
        }
//                 console.log('RX: ' + sD);

        if (deviceUnplugged == false && sD == "") { //If nothing is detected, close down port
            console.log("Device unplugged");
            document.getElementById("status").innerHTML = "Device disconnected";
            closeDevice();
            deviceUnplugged = true;
            //                setTimeout(monitorUSBHID, 2000);
            return;
        }
    }


    function closeDevice() { // works 
        if (device) {
            device.close(device);
            device = null;
            deviceOpen = false;
            console.log("HID device closed");
        }
    }


    function processResults(command, length, payload) {
            var ProtoBuf = dcodeIO.ProtoBuf;
            var ByteBuffer = dcodeIO.ByteBuffer;
            var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
                Device = builder.build();

// 			console.log("RX: " + command);
            command = command.substring(2, 4)
            console.log('to process:' + command + ' ' + length + ' ' + payload);
            switch (command) {
                case "3A": // initialize
//                     var featuresMessage = Device.Features.decodeHex(payload);
//                     console.log("session id: " + featuresMessage.echoed_session_id);
                    break;
                case "30": // public address
                    ecdsa = payload.substring(8, 74);
                    // 					ecdsa = payload.substring(8,138); //uncompressed
                    // 					console.log('ecdsa from device ' + ecdsa);
                    document.getElementById("ecdsa").innerHTML = ecdsa;
                    ripe160of2 = payload.substring(78, 118);
                    // 					ripe160of2 = payload.substring(142,182);
                    document.getElementById("ripe160of2").innerHTML = ripe160of2;
                    // 					console.log('RIPE from device ' + ripe160of2);
                    pub58 = ecdsaToBase58(ecdsa);
                    document.getElementById("address_58").innerHTML = pub58;

                    break;
                case "31": // number of addresses in loaded wallet
                    numberOfAddresses = payload.substring(2, 4);
                    // 					console.log('# of addresses ' + numberOfAddresses);
                    document.getElementById("numberOfAddresses").innerHTML = numberOfAddresses;

                    break;
                case "32": // Wallet list
                    var walletMessage = Device.Wallets.decodeHex(payload);
							
                    console.log("number of wallets: " + walletMessage.wallet_info.length);
                    var walletsIndex;
                    for (walletsIndex=0; walletsIndex < walletMessage.wallet_info.length; walletsIndex++){
						console.log("wallet structure number: " + walletMessage.wallet_info[walletsIndex].wallet_number);
						console.log("wallet structure name: " + walletMessage.wallet_info[walletsIndex].wallet_name.toString("utf8"));
						console.log("wallet structure uuid: " + walletMessage.wallet_info[walletsIndex].wallet_uuid.toString("hex"));
						console.log("wallet version: " + walletMessage.wallet_info[walletsIndex].version);
                    }
				

                    $("#wallet_table").find("tr").remove();
                    var walletDataArray = "";
                    walletDataArray = walletMessage.wallet_info;
                    var index;
                    for (index = 0; index < walletDataArray.length; index++) {
                        var wallet_number = walletMessage.wallet_info[index].wallet_number;
                        var wallet_name = walletMessage.wallet_info[index].wallet_name.toString("utf8");
                        var row = '<tr id="wallet_' + wallet_number + '"><td class="iterator">' + wallet_number + '</td><td class="address-field" id="name_' + wallet_number + '" style="cursor:pointer">' + wallet_name + '</td></tr>';
                        $('#wallet_table').append(row);
                    }
                    break;

                case "33": // Ping response
                    var PingResponse = Device.PingResponse.decodeHex(payload);
                    console.log(PingResponse);
                    console.log('echo: ' + PingResponse.echoed_greeting + ' session ID: ' + PingResponse.echoed_session_id);
                    break;
                    //         		case 09: // ping return
                    //         			break;
                    //         		case 50: // button ack
                    //         			break;
                case "34": // success
                    break;
                case "35": // general purpose error/cancel
//                     var Failure = Device.Failure.decodeHex(payload);
//                     console.log(Failure);
//                     console.log('error #: ' + Failure.error_code + ' error: ' + Failure.error_message);
                    break;
                case "36": // device uuid return
                    var DeviceUUID = Device.DeviceUUID.decodeHex(payload);
                    console.log('device uuid: ' + DeviceUUID.device_uuid);
                    break;
                case "39": // signature return [original]
                    var Signature = Device.Signature.decodeHex(payload);
                    // 					Signature.signature_data
                    break;
                case "62": // parse & insert xpub from current wallet //RETURN from scan wallet
                    var CurrentWalletXPUB = Device.CurrentWalletXPUB.decodeHex(payload);
                    // 					$("#bip32_source_key").CurrentWalletXPUB.xpub;

                    document.getElementById("bip32_source_key").textContent = CurrentWalletXPUB.xpub;
// 					pausecomp(500);

                    // 					make sure the xpub is evaluated:
                    var source_key = $("#bip32_source_key").val();
//                     var source_key = CurrentWalletXPUB.xpub;
                    useNewKey(source_key);

                    break;
                case "64": // signature return
//                     var SignatureComplete = Device.SignatureComplete.decodeHex(payload);
                    
//                     var data_size = (SignatureComplete.signature_data_complete.toString("hex").length)/2;
//                     var data_size_hex = d2h(data_size);
// 
// 					var ecdsa_size = (SignatureComplete.signature_ecdsa_complete.toString("hex").length)/2;
//                     var ecdsa_size_hex = d2h(ecdsa_size);
// 
// 					var total_scriptSig_Size = data_size + ecdsa_size + 2;
// 					var total_scriptSig_Size_hex = d2h(total_scriptSig_Size)
// 					
// 					console.log("SigCom scriptSig length: " + total_scriptSig_Size_hex);
// 					console.log("SigCom signature_data length: " + data_size_hex);
// 					console.log("SigCom signature_data: " + SignatureComplete.signature_data_complete.toString("hex"));
// 					console.log("SigCom signature_ecdsa length: " + ecdsa_size_hex);
// 					console.log("SigCom signature_ecdsa: " + SignatureComplete.signature_ecdsa_complete.toString("hex"));

                    break;

                case "71": // message signing return
                	console.log("########## in case 71 ###########");
                    var SignatureMessage = Device.SignatureMessage.decodeHex(payload);
                    
                    var data_size = (SignatureMessage.signature_data_complete.toString("hex").length)/2;
                    var data_size_hex = d2h(data_size);

					console.log("SigMsg signature_data length: " + data_size_hex);
					console.log("SigMsg signature_data hex: " + SignatureMessage.signature_data_complete.toString("hex"));

					var SigByteArrayHex = Crypto.util.hexToBytes(SignatureMessage.signature_data_complete.toString("hex"));

					var compressed = true;
					var addrtype = 0;
					var address = document.getElementById("sgAddr").value;
	    			var message = document.getElementById("sgMsgHidden").value;
					
					var sig = sign_message_device_processing(message, address, SigByteArrayHex, compressed, addrtype);

					sgData = {"message":message, "address":address, "signature":sig};
					var sgType = 'inputs_io';
					
					$('#sgSig').val(makeSignedMessage(sgType, sgData.message, sgData.address, sgData.signature));


                    break;


                default:
                	break;
            } //switch

        } //function processResults

    function compareRIPE160() {
        var areEqual = dev.toUpperCase() === calc.toUpperCase();
        if (areEqual) {
            document.getElementById("RIPEDEVICE").addClass("has-success has-feedback");
        }
    }
    var tempRIPECALC;

    function ecdsaToBase58(publicKeyHex) {
        //could use publicKeyBytesCompressed as well
        var hash160 = Crypto.RIPEMD160(Crypto.util.hexToBytes(Crypto.SHA256(Crypto.util.hexToBytes(publicKeyHex))))

        document.getElementById("ripe160of2_CALC").innerHTML = hash160.toUpperCase();

        var version = 0x00 //if using testnet, would use 0x6F or 111.
        var hashAndBytes = Crypto.util.hexToBytes(hash160)
        hashAndBytes.unshift(version)

        var doubleSHA = Crypto.SHA256(Crypto.util.hexToBytes(Crypto.SHA256(hashAndBytes)))
        var addressChecksum = doubleSHA.substr(0, 8)
            // 		console.log(addressChecksum) //26268187

        var unencodedAddress = "00" + hash160 + addressChecksum

        // 		console.log(unencodedAddress)
        /* output
		  003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187
		*/

        var address = Bitcoin.Base58.encode(Crypto.util.hexToBytes(unencodedAddress))
            // 		console.log("Address58 " + address) //16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS
        return address;
    }

    function makeListItems(theList, theID, theContent, theCount, theStart) {
        var myItems = [];
        var myList = $(theList);
        var myContent = theContent;
        var myID = theID;
        var myCount = theCount;
        var myStart = theStart;
        for (var i = myStart; i < myCount; i++) {
            myItems.push("<li><a href=\"#\" id=\"" + myID + "" + i + "\">" + myContent + " " + i + "</a></li>");
            // 			myItems.push( "<li id=\"" + myID + "" + i + "\">" +  myContent + " " + i + "</li>" );

        }

        myList.append(myItems.join(""));
    }

    function loadWalletNames() {
        hidWriteRawData(deviceCommands.list_wallets);
    }


    function autoCannedTransaction(transData) {
        chunkSize = 32;
        var chunkedTData = [];
        var tempDTS = '';
        tempDTS = transData;
//         console.log('Size of transData : ' + tempDTS.length);
        var transDataRemainder = tempDTS.length % 16;
//         console.log('Remainder : ' + transDataRemainder);
        if(transDataRemainder==0||transDataRemainder==12||transDataRemainder==14){
			var prepend = '00000000';
			tempDTS = prepend.concat(tempDTS);
		}			
//         console.log('tempDTS : ' + tempDTS);
        chunkedTData = tempDTS.chunk(chunkSize);
//         console.log('Number of chunks : ' + chunkedTData.length);
        for (i = 0; i < (chunkedTData.length - 1); i++) {
            dataToSend = chunkedTData[i];
            sendToDevice = '00' + dataToSend;
            var txResult = device.hid_write(sendToDevice);
//             console.log('HID TX : ' + sendToDevice);
//             console.log('HID TX size: ' + txResult);
            pausecomp(50);
        }

        dataToSend = chunkedTData[chunkedTData.length - 1];
//         console.log('dataToSend.length: ' + dataToSend.length); 
		sendToDevice = '00' + dataToSend + '7E7E';
		var txResult = device.hid_write(sendToDevice);
// 		console.log('HID TX : ' + sendToDevice);
// 		console.log('HID TX size: ' + txResult);
    }

    function testUploader(transData) {
        chunkSize = 32;
        var chunkedTData = [];
        var tempDTS = '';
        tempDTS = transData;
        chunkedTData = tempDTS.chunk(chunkSize);
        console.log('Number of chunks : ' + chunkedTData.length);
        for (i = 0; i < (chunkedTData.length - 1); i++) {
            dataToSend = chunkedTData[i];
            sendToDevice = '00' + dataToSend;
            var txResult = device.hid_write(sendToDevice);
            console.log('HID TX : ' + sendToDevice);
            console.log('HID TX size: ' + txResult);

            pausecomp(50);
        }

        dataToSend = chunkedTData[chunkedTData.length - 1];
        sendToDevice = '00' + dataToSend; // deadbeef removed
        var txResult = device.hid_write(sendToDevice);
        console.log('HID TX : ' + sendToDevice);
        console.log('HID TX size: ' + txResult);


    }

    function restoreWallet(transData) {
        chunkSize = 32;
        var chunkedTData = [];
        var tempDTS = '';
        tempDTS = transData;
        chunkedTData = tempDTS.chunk(chunkSize);
        console.log('Number of chunks : ' + chunkedTData.length);
        for (i = 0; i < (chunkedTData.length - 1); i++) {
            dataToSend = chunkedTData[i];
            sendToDevice = '00' + dataToSend;
            var txResult = device.hid_write(sendToDevice);
            console.log('HID TX : ' + sendToDevice);
            console.log('HID TX size: ' + txResult);

            pausecomp(50);
        }

        dataToSend = chunkedTData[chunkedTData.length - 1];
        sendToDevice = '00' + dataToSend + '7E7E';
        var txResult = device.hid_write(sendToDevice);
        console.log('HID TX : ' + sendToDevice);
        console.log('HID TX size: ' + txResult);


    }



    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    // LOCKBOX SPECIFIC END
    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////




    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    // BIP32 SPECIFIC 
    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////



    var MAINNET_PUBLIC = 0x0488b21e;
    var MAINNET_PRIVATE = 0x0488ade4;
    var TESTNET_PUBLIC = 0x043587cf;
    var TESTNET_PRIVATE = 0x04358394;

    var RECEIVE_CHAIN = 0;
    var CHANGE_CHAIN = 1;

    var GAP = 5; // how many extra addresses to generate

    var key = null;
    var network = null;
    var addresses = {
        "receive": {},
        "change": {}
    };;
    var balance = 0;
    var pending = 0;
    var unspent = {};
    var lastone = {
        "receive": GAP,
        "change": GAP
    };
    var chains = {
        "receive": null,
        "change": null
    };
    var usechange = 0;

    var clearData = function() {
        key = null;
        network = null;
        addresses = {
            "receive": {},
            "change": {}
        };
        balance = 0;
        pending = 0;
        unspent = {};
        lastone = {
            "receive": GAP,
            "change": GAP
        };
        chains = {
            "receive": null,
            "change": null
        };
        usechange = 0;

        $("#receive_table").find("tr").remove();
        $("#change_table").find("tr").remove();
        $("#balance_display").text('?');
    }

    var ops = Bitcoin.Opcode.map;

    //------------
    // From https://gist.github.com/paolorossi/5747533
    function Queue(handler) {
            var queue = [];

            function run() {
                var callback = function() {
                        queue.shift();
                        // when the handler says it's finished (i.e. runs the callback)
                        // We check for more tasks in the queue and if there are any we run again
                        if (queue.length > 0) {
                            run();
                        }
                    }
                    // give the first item in the queue & the callback to the handler
                handler(queue[0], callback);
            }

            // push the task to the queue. If the queue was empty before the task was pushed
            // we run the task.
            this.append = function(task) {
                queue.push(task);
                if (queue.length === 1) {
                    run();
                }
            }
        }
        // small handler that launch task and calls the callback
        // when its finished
    var queue = new Queue(function(task, callback) {
        task(function() {
            // call an option callback from the task
            if (task.callback)
                task.callback();
            // call the buffer callback.
            callback();
        });
    });
    //------------



    var getAddr = function(key) {
        var hash160 = key.eckey.getPubKeyHash();
        var addr = new Bitcoin.Address(hash160);
        addr.version = 0x6f; // testnet
        return addr.toString();
    }

    var generate = function() {

        for (var i = 0; i < 12; i++) {
            c = b.derive_child(i);
            childs.push(c);
            addresses.push(getAddr(c));
            $("#results").append(getAddr(c) + "<br>");
        }

    }

    var hashFromAddr = function(string) {

        var bytes = Bitcoin.Base58.decode(string);
        var hash = bytes.slice(0, 21);
        var checksum = Crypto.SHA256(Crypto.SHA256(hash, {
            asBytes: true
        }), {
            asBytes: true
        });

        if (checksum[0] != bytes[21] ||
            checksum[1] != bytes[22] ||
            checksum[2] != bytes[23] ||
            checksum[3] != bytes[24]) {
            throw "Checksum validation failed!";
        }

        this.version = hash.shift();
        this.hash = hash;
        return hash;
    }

    var createOutScript = function(address) {
        var script = new Bitcoin.Script();
        script.writeOp(ops.OP_DUP);
        script.writeOp(ops.OP_HASH160);
        script.writeBytes(hashFromAddr(address));
        script.writeOp(ops.OP_EQUALVERIFY);
        script.writeOp(ops.OP_CHECKSIG);
        return script;
    }

    var valueFromNumber = function(number) {
        var value = BigInteger.valueOf(number * 1e8);
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
        return value;
    }

    var valueFromSatoshi = function(number) {
        var value = BigInteger.valueOf(number);
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
        return value;
    }

    var valueFromInteger = function(number) {
        var value = BigInteger.valueOf(number);
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 4) value.push(0);
        return value;
    }


    var createtx = function() {
        var intx = "1197be06096230bf4b8e4de121607dd797c60df60545eda8d90b7f876f24694e";
        in0 = b.derive_child(1)
        var inaddr = getAddr(in0);
        var outaddr0 = "n2hpygZMYkGAB2zbLEaUbBr3EJ5NK9vMHp";
        var outaddr1 = getAddr(b.derive_child(0));
        console.log(inaddr);
        console.log(outaddr0);
        console.log(outaddr1);

        o0s = createOutScript(outaddr0);
        o1s = createOutScript(outaddr1);
        to0 = new Bitcoin.TransactionOut({
            value: valueFromNumber(0.01234567),
            script: o0s
        });
        to1 = new Bitcoin.TransactionOut({
            value: valueFromNumber(0.007),
            script: o1s
        });

        var tx = new Bitcoin.Transaction();

        tx.addOutput(to0);
        tx.addOutput(to1);

        tin = new Bitcoin.TransactionIn({
            outpoint: {
                hash: Bitcoin.Util.bytesToBase64(Bitcoin.Util.hexToBytes(intx).reverse()),
                index: 0
            },
            script: createOutScript(inaddr),
            sequence: 4294967295
        });
        tx.addInput(tin);

        tx.signWithKey(in0.eckey)

        return tx;
    }

    var parseScriptString = function(scriptString) {
        var opm = Bitcoin.Opcode.map;
        var inst = scriptString.split(" ");
        var bytescript = [];
        for (thisinst in inst) {
            var part = inst[thisinst];
            if ("string" !== typeof part) {
                continue;
            }
            if ((part.length > 3) && (part.slice(0, 3) == 'OP_')) {
                for (name in opm) {
                    if (name == part) {
                        bytescript.push(opm[name])
                    }
                }
            } else if (part.length > 0) {
                bytescript.push(Bitcoin.Util.hexToBytes(part));
            }
        }
        return bytescript;
    };

    var goodUpdate = function(addr) {
        return function(data, textStatus, jqXHR) {
            unspent[addr] = data.unspent_outputs;
            thisbalance = 0;
            thispending = 0;
            for (var x = 0; x < unspent[addr].length; x++) {
                if (confirmations === 0) {											//fix this to withhold unconfirmed
                    thispending += unspent[addr][x].value;
                } else {
                    thisbalance += unspent[addr][x].value;
                }
            }
            balance += thisbalance;
            $("#balance_display").text(balance / 100000000); // Satoshi to BTC
            $("#" + addr).children(".balance").text(thisbalance / 100000000);
        };
    }
    var noUpdate = function(addr) {
        return function(jqXHR, textStatus, errorThrown) {
            if (jqXHR.status != 500) {
                console.log(errorThrown);
            } else {
                $("#" + addr).children(".balance").text(0);
            }
        }
    }
    var reUpdateBalances = function() {
        var addresslist = [];
        for (var k in addresses) {
            addresslist = addresslist.concat(Object.keys(addresses[k]));
        }
        balance = 0;
        for (var i = 0; i < addresslist.length; i++) {
            var addr = addresslist[i]

            var jqxhr = $.get('https://blockchain.info/unspent', {
                    "active": addr,
                    "cors": true,
                    "json": true,
                    "api": "1af870b5-15c4-4584-80c3-03935f97d11b"
                })
                .done(goodUpdate(addr))
                .fail(noUpdate(addr))
                .always(function() {});
        }
    }

    var gotUnspent = function(chain, index, addr) {
        return function(data, textStatus, jqXHR) {
        	console.log("chain " + chain);
        	console.log("index " + index);
        	console.log("addr " + addr);
			if(chain === "receive"){
				chain_numerical = 0;
				}
				else
				{
				chain_numerical = 1;
				}
            unspent[addr] = data.unspent_outputs;
            thisbalance = 0
            
            for (var x = 0; x < unspent[addr].length; x++) {
                thisbalance += unspent[addr][x].value;
                unspent[addr][x].chain = chain_numerical;
                unspent[addr][x].index = index;
            }
            balance += thisbalance;
            $("#balance_display").text(balance / 100000000); // Satoshi to mBTC
            $("#" + addr).children(".balance").text(thisbalance / 100000000);
        };
    }
    var gotUnspentError = function(chain, index, addr) {
        return function(jqXHR, textStatus, errorThrown) {
            if (jqXHR.status != 500) {
                console.log(errorThrown);
            } else {
                $("#" + addr).children(".balance").text(0);
            }
        }
    }

    var checkReceived = function(chain, index, addr, callback) {
        return function(data, textStatus, jqXHR) {
            if (parseInt(data) > 0) {
                var newlast = Math.max(index + GAP + 1, lastone[chain]);
                lastone[chain] = newlast;
                queue.append(generateAddress(chain, index + 1));

                if (chain === 'change') {
                    usechange = index + 1;
                }

                var jqxhr2 = $.get('https://blockchain.info/unspent', {
                        "active": addr,
                        "cors": true,
                        "json": true,
                        "api": "1af870b5-15c4-4584-80c3-03935f97d11b"
                    })
                    .done(gotUnspent(chain, index, addr))
                    .fail(gotUnspentError(chain, index, addr))
                    .always(function() {});
                callback();
            } else {
                $("#balance_display").text(balance / 100000000); // Satoshi to mBTC
                $("#" + addr).children(".balance").text(0);
                if (index < lastone[chain] - 1) {
                    queue.append(generateAddress(chain, index + 1));
                }
                callback();
            }
        }
    }

    var updateBalance = function(chain, index, addr, callback) {
        var jqxhr = $.get('https://blockchain.info/q/getreceivedbyaddress/' + addr, {
                'cors': true,
                'api': '1af870b5-15c4-4584-80c3-03935f97d11b'
            }, 'text')
            .done(checkReceived(chain, index, addr, callback));

    }


    //     var fetchFullTXHex = function(txHex) {
    //     	var theInputHex = $.get('https://blockchain.info/rawtx/'+txHex, {
    //     				'format':'hex',
    //     				'cors': true,
    // 			       	'api': '1af870b5-15c4-4584-80c3-03935f97d11b'})
    // 			 .done(function(data){
    // 				console.log("input full hex: " + data);
    // 				document.getElementById('input_tx_full').textContent = data;
    // 			 });      	
    //     }
    // 




    // Simple task to generate addresses and query them;
    var generateAddress = function(chain, index) {
        return function(callback) {
            if (chains[chain]) {
                var childkey = chains[chain].derive_child(index);
                var childaddr = childkey.eckey.getBitcoinAddress().toString();

                var qrcode = ''
                var qrcode2 = ''
                if (chain === 'receive') {
                    qrcode = ' <span class="open-qroverlay glyphicon glyphicon-qrcode" data-toggle="modal" data-target="#qroverlay" data-addr="' + childaddr + '"></span>';
                    qrcode2 = ' <span class="open-sendMsgFrom glyphicon glyphicon-envelope" data-target="#sign" data-addr="' + childaddr + '" data-index="' + index + '" data-chain="' + chain + '"></span>';
                }
                var row = '<tr id="' + childaddr + '"><td class="iterator">' + index + '</td><td class="address-field">' + childaddr + qrcode + qrcode2 + '</td><td class="balance">?</td></tr>';
                $('#' + chain + '_table').append(row);
                addresses[chain][childaddr] = childkey;

                if (navigator.onLine) {
                    updateBalance(chain, index, childaddr, callback);
                } else {
                    if (index < lastone[chain] - 1) {
                        queue.append(generateAddress(chain, index + 1));
                    }
                    callback();
                }
            } else {
                callback();
            }
        }
    }

    var genTransaction = function() {
        if (balance > 0) {
            var receiver = $("#receiver_address").val()
            var amount = Math.ceil(parseFloat($("#receiver_monies").val()) * 100000000);
            var fee = Math.ceil(parseFloat($("#fee_monies").val()) * 100000000);
            if (!(amount > 0)) {
                console.log("Nothing to do");
            }
            if (!(fee >= 0)) {
                fee = 0;
            }
            var target = amount + fee;
            if (target > balance) {
                alert("Not enough money yo!");
                return
            } else {
                // prepare inputs
                var fullInputTransactionHash = [];
                var fullInputTXindex = [];
                var address_handle_chain = [];
                var address_handle_index = [];
				var scriptsToReplace = [];

                var incoin = [];
                for (var k in unspent) {
                    var u = unspent[k];
                    for (var i = 0; i < u.length; i++) {
                        var ui = u[i]
                        var coin = {
                            "hash": ui.tx_hash,
                            "age": ui.confirmations,
                            "address": k,
                            "coin": ui,
                            "chain": ui.chain,
                            "index": ui.index
                        };
            			console.log("address: " + coin.address);
//             			console.log("coin: " + coin.coin);
            			console.log("chain: " + coin.chain);
            			console.log("index: " + coin.index);
                        incoin.push(coin);
                    }
                }
                var sortcoin = _.sortBy(incoin, function(c) {
                    return c.age;
                });

                inamount = 0;
                var tx = new Bitcoin.Transaction();

                var toaddr = new Bitcoin.Address(receiver);
                var to = new Bitcoin.TransactionOut({
                    value: valueFromSatoshi(amount),
                    script: Bitcoin.Script.createOutputScript(toaddr)
                });
                tx.addOutput(to);

                var usedkeys = [];
                for (var i = 0; i < sortcoin.length; i++) {
                    var coin = sortcoin[i].coin;
                    var tin = new Bitcoin.TransactionIn({
                        outpoint: {
                            hash: Bitcoin.Util.bytesToBase64(Bitcoin.Util.hexToBytes(coin.tx_hash)), // no .reverse()!
                            index: coin.tx_output_n
                        },
                        script: Bitcoin.Util.hexToBytes(coin.script),
                        sequence: 4294967295
                    });
					scriptsToReplace[i] = coin.script;
                    fullInputTransactionHash[i] = Bitcoin.Util.bytesToHex(Bitcoin.Util.hexToBytes(coin.tx_hash).reverse());
            		console.log("fullInputTransactionHash[" + i + "]: " + fullInputTransactionHash[i]);
                    fullInputTXindex[i] = coin.tx_output_n;
                    address_handle_chain[i] = coin.chain;
                    address_handle_index[i] = coin.index;

                    tx.addInput(tin);
                    inamount += coin.value;
                    usedkeys.push(sortcoin[i].address);

                    if (inamount >= target) {
                        break;
                    }
                }

                // 		Need to add the block with the amounts HERE ###########################
                // 		var prepForDevice = 1;
                // 		if (prepForDevice) {
                // 			sequence: 4294967295
                // 			num_outputs:
                // 			for(number of inputs){
                // 				amount: [in satoshis],
                // 				scriptPubSig: [the script or nothing actually as it is skipped]				
                // 			}	
                // 			is_ref = 00
                // 			version = 00000000
                // 			txhash	= [which one?]	
                // 			input_transaction_ref_number = [8 bytes]
                // 			scriptPubSig of the SELECTED output		
                // 		}

                if (inamount > target) {
                    var changeaddr = chains['change'].derive_child(usechange).eckey.getBitcoinAddress();
                    var ch = new Bitcoin.TransactionOut({
                        value: valueFromSatoshi(inamount - target),
                        script: Bitcoin.Script.createOutputScript(changeaddr)
                    });
                    tx.addOutput(ch);
                }

                if (key.has_private_key) {
                    for (var i = 0; i < usedkeys.length; i++) {
                        k = usedkeys[i];
                        var inchain = null;
                        if (k in addresses['receive']) {
                            inchain = addresses['receive'];
                        } else if (k in addresses['change']) {
                            inchain = addresses['change'];
                        }
                        if (inchain) {
                            tx.signWithKey(inchain[k].eckey);
                        } else {
                            console.log("Don't know about all the keys needed.");
                        }
                    }
                    $("#signedtxlabel").show()
                    $("#unsignedtxlabel").hide()
                    $("#submit_signed_transaction").removeAttr('disabled');
                } else {
                    $("#unsignedtxlabel").show()
                    $("#signedtxlabel").hide()
                    $("#submit_signed_transaction").attr('disabled', true);
                }
                $("#output_transaction").val(Bitcoin.Util.bytesToHex(tx.serialize()));
                var unsignedTransactionToBeCoded = Bitcoin.Util.bytesToHex(tx.serialize());
                var fullInputTXHex = [];
                console.log("fullInputTXindex.length: " + fullInputTXindex.length);

		
// 				$.when(
// 						function(){
// 							console.log("in the when");
// 							for (var i = 0; i < fullInputTXindex.length; i++) {
// 									fullInputTXHex[i] = $.get('https://bitcoin.toshi.io/api/v0/transactions/' + fullInputTransactionHash[i] + '.hex')
// 									.done(function(data){
// 										console.log("done TX hash # " + i)
// 									})
// 									.fail(function() {console.log("fail in get TX hash # " + i)})
// 									.always(function() {console.log("through TX hash # " + i)});
// 							};
// 						}
// 					)
// 					.done(function(){
// 							console.log("finished data hashes");
// 							prepForSigning(unsignedTransactionToBeCoded, fullInputTXHex, fullInputTXindex, address_handle_chain, address_handle_index);
// 						}
// 					);
				
// 				prepForSigning(unsignedTransactionToBeCoded, fullInputTXHex, fullInputTXindex, address_handle_chain, address_handle_index);
					
// 				$.when(
// 					(
// 						function(){
// 							console.log("in the when");
// 							for (var i = 0; i < fullInputTXindex.length; i++) {
// 									fullInputTXHex[i] = $.get('https://bitcoin.toshi.io/api/v0/transactions/' + fullInputTransactionHash[i] + '.hex')
// 									.done(function(data){
// 										console.log("done TX hash # " + i);
// 										console.log("TX: " + data)
// 									})
// 									.fail(function() {console.log("fail in get TX hash # " + i)})
// 									.always(function() {console.log("through TX hash # " + i)});
// 							};
// 						}
// 					)
// 					.done(function(){
// 							prepForSigning(unsignedTransactionToBeCoded, fullInputTXHex, fullInputTXindex, address_handle_chain, address_handle_index);
// 						}
// 					));

				$.when(
					(
						($.get('https://bitcoin.toshi.io/api/v0/transactions/' + fullInputTransactionHash[0] + '.hex')
							.done(function(data){
								fullInputTXHex[0] = data;
							})
						),
						($.get('https://bitcoin.toshi.io/api/v0/transactions/' + fullInputTransactionHash[1] + '.hex')
							.done(function(data){
								fullInputTXHex[1] = data;
							})
						)
					)
					.done(function(){
							prepForSigning(unsignedTransactionToBeCoded, fullInputTXHex, fullInputTXindex, address_handle_chain, address_handle_index);
						}
					));
 
// 				$.when(
// 					(
// 						($.get('https://blockchain.info/rawtx/' + fullInputTransactionHash[0], {
// 							'format': 'hex',
// 							'cors': true,
// 							'api': '1af870b5-15c4-4584-80c3-03935f97d11b'
// 							})
// 							.done(function(data){
// 								fullInputTXHex[0] = data;
// 							})
// 						),
// 						($.get('https://blockchain.info/rawtx/' + fullInputTransactionHash[1], {
// 							'format': 'hex',
// 							'cors': true,
// 							'api': '1af870b5-15c4-4584-80c3-03935f97d11b'
// 							})
// 							.done(function(data){
// 								fullInputTXHex[1] = data;
// 							})
// 						)
// 					)
// 					.done(function(){
// 							prepForSigning(unsignedTransactionToBeCoded, fullInputTXHex, fullInputTXindex, address_handle_chain, address_handle_index);
// 						}
// 					));
 
  
 
                console.log("fullInputTXindex: " + fullInputTXindex);
                console.log("unsignedTransactionToBeCoded: " + unsignedTransactionToBeCoded);
                console.log("scripts to replace: " + scriptsToReplace[0]);



                return tx;

            }
        }
    }








    var iterateTXhashes = function() {

    }

    var useNewKey = function(source_key) {
        var keylabel = "";
        var networklabel = "";
        clearData();

        try {
            key = new BIP32(source_key);
        } catch (e) {
            console.log(source_key);
            console.log("Incorrect key?");
        }
        if (key) {
            switch (key.version) {
                case MAINNET_PUBLIC:
                    keylabel = "Public key";
                    network = 'prod';
                    networklabel = "Bitcoin Mainnet";
                    break;
                case MAINNET_PRIVATE:
                    keylabel = "Private key";
                    network = 'prod';
                    networklabel = "Bitcoin Mainnet";
                    break;
                case TESTNET_PUBLIC:
                    keylabel = "Public key";
                    network = 'test';
                    networklabel = "Bitcoin Testnet";
                    break;
                case TESTNET_PRIVATE:
                    keylabel = "Private key";
                    network = 'test';
                    networklabel = "Bitcoin Testnet";
                    break;
                default:
                    key = null;
                    console.log("Unknown key version");
            }
            Bitcoin.setNetwork(network);
        }
        $("#bip32_key_info_title").text(keylabel);
        $("#network_label").text(networklabel);

        console.log("key depth: " + key.depth);

        if (key.depth != 1) {
            alert("Non-standard key depth: should be 1, and it is " + key.depth + ", are you sure you want to use that?");
        }

        chains["receive"] = key.derive_child(RECEIVE_CHAIN);
        chains["change"] = key.derive_child(CHANGE_CHAIN);

        queue.append(generateAddress("receive", 0));
        queue.append(generateAddress("change", 0));

    };

    function onInput(id, func) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
            jQuery.data(this, "lastvalue", $(this).val());
        });
    };

    var onUpdateSourceKey = function() {
        var source_key = $("#bip32_source_key").val();
        useNewKey(source_key);
    }




    $(document).on("click", ".open-qroverlay", function() {
        var myAddress = $(this).data('addr');
        console.log("-->" + myAddress);
        $("#qraddr").text(myAddress);

        var qrCode = qrcode(5, 'H');
        var text = "bitcoin:" + myAddress;
        text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
        qrCode.addData(text);
        qrCode.make();
        $('#genAddrQR').html(qrCode.createImgTag(4));

    });

    $(document).on("click", ".open-sendMsgFrom", function() {
        document.getElementById("sgMsg").value = '';
        document.getElementById("sgMsgHidden").value = '';
        document.getElementById("sgAddr").value = '';
        document.getElementById("sgRoot").value = '';
        document.getElementById("sgChain").value = '';
        document.getElementById("sgIndex").value = '';
        
        var myAddress = $(this).data('addr');
        var myRoot = 0;
        var myChainText = $(this).data('chain');
        var myChain = '';
        if(myChainText == "receive"){
        	myChain = 0;
		}
			else
		{
        	myChain = 1;
		}
        var myIndex = $(this).data('index');
        console.log("-->" + myAddress);
        console.log("-->" + myRoot);
        console.log("-->" + myChain);
        console.log("-->" + myIndex);
        
        document.getElementById("sgAddr").value = myAddress;
        document.getElementById("sgRoot").value = Number(myRoot);
        document.getElementById("sgChain").value = Number(myChain);
        document.getElementById("sgIndex").value = Number(myIndex);

		$('#myTab a[href="#sign"]').tab('show');
		$('html, body').animate({scrollTop:0}, 'slow');
    });

    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    // BIP32 SPECIFIC END
    ///////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////




    $(document).ready(function() {

		

        onInput("#bip32_source_key", onUpdateSourceKey);

        $('#generate_transaction').click(genTransaction);


        $('#prep_for_device').click(prepForSigning);
        $('#sign_transaction_with_device').click(sendTransactionForSigning);
        
//         $('#sgSignDevice').on('click', function() {
//         	event.preventDefault();
//         	signMessageWithDevice();
//             pausecomp(10);        	
//             hidWriteRawData(deviceCommands.button_ack);
//         });

        $('#sgSignDevice').click(signMessageWithDevice);

        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////
        // LOCKBOX SPECIFIC ON READY
        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////

        //         console.log( "ready!" );
        pluginLoaded(); //  enter js: detect if plugin present. 

//         makeListItems("#load_wallet_list", "load_wallet_", "Load Wallet", 6, 0);
        makeListItems("#get_address", "get_address_", "Get Address", 10, 0);
        makeListItems("#delete_wallet_list", "delete_wallet_", "Delete Wallet", 6, 0);
        makeListItems("#new_wallet_list", "new_wallet_", "New Wallet", 26, 0);


        $('#status').on('click', function() {
            hidScan();
        });


        $('#initialize').on('click', function() {
            event.preventDefault();
            initialize_protobuf_encode();
        });

        $('#direct_load_wallet').on('click', function() {
            event.preventDefault();
            var walletToLoad = document.getElementById('direct_load_wallet_input').value;
            directLoadWallet(walletToLoad);
        });

        $('#ping').on('click', function() {
            hidWriteRawData(deviceCommands.ping);
        });

        $('#format_storage').on('click', function() {
            hidWriteRawData(deviceCommands.format_storage);
        });

        $('#button_ack').on('click', function() {
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#button_cancel').on('click', function() {
            hidWriteRawData(deviceCommands.button_cancel);
        });

        $('#list_wallets').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.list_wallets);
        });

        $('#new_wallet').on('click', function() {
            hidWriteRawData(deviceCommands.new_wallet);
        });

        $('#new_wallet_default').on('click', function() {
            hidWriteRawData(deviceCommands.new_wallet_default);
        });

        $('#load_wallet_0').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_0);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#load_wallet_1').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_1);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#load_wallet_2').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_2);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#load_wallet_3').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_3);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#load_wallet_4').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_4);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#load_wallet_5').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_5);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#get_entropy_32_bytes').on('click', function() {
            hidWriteRawData(deviceCommands.get_entropy_32_bytes);
        });

        $('#autoCannedTransaction_1').on('click', function() {
            autoCannedTransaction(deviceCommands.sign_transaction_1);
        });

        $('#autoCannedTransaction_2').on('click', function() {
            autoCannedTransaction(deviceCommands.sign_transaction_2);
        });

        $('#autoCannedTransaction_10').on('click', function() {
            autoCannedTransaction(deviceCommands.sign_transaction_10);
        });

        $('#autoCannedTransaction_11').on('click', function() {
            autoCannedTransaction(deviceCommands.sign_transaction_11);
        });

        $('#autoCannedTransaction_12').on('click', function() {
            autoCannedTransaction(deviceCommands.sign_transaction_12);
        });

        $('#otp_ack').on('click', function() {
            hidWriteRawData(constructOTP());
        });

        $('#otp_cancel').on('click', function() {
            hidWriteRawData(deviceCommands.otp_cancel);
        });

        $('#pin_ack').on('click', function() {
            constructPIN();
        });

        $('#pin_cancel').on('click', function() {
            hidWriteRawData(deviceCommands.pin_cancel);
        });

        $('#backup_wallet').on('click', function() {
            hidWriteRawData(deviceCommands.backup_wallet);
        });

        $('#get_master_public_key').on('click', function() {
            hidWriteRawData(deviceCommands.get_master_public_key);
        });

        $('#restore_wallet').on('click', function() {
            restoreWallet(deviceCommands.restore_wallet);
        });

        $('#delete_wallet_0').on('click', function() {
            hidWriteRawData(deviceCommands.delete_wallet_0);
        });

        $('#delete_wallet_1').on('click', function() {
            hidWriteRawData(deviceCommands.delete_wallet_1);
        });

        $('#delete_wallet_2').on('click', function() {
            hidWriteRawData(deviceCommands.delete_wallet_2);
        });

        $('#delete_wallet_3').on('click', function() {
            hidWriteRawData(deviceCommands.delete_wallet_3);
        });

        $('#delete_wallet_4').on('click', function() {
            hidWriteRawData(deviceCommands.delete_wallet_4);
        });

        $('#delete_wallet_5').on('click', function() {
            hidWriteRawData(deviceCommands.delete_wallet_5);
        });

        $('#get_device_uuid').on('click', function() {
            hidWriteRawData(deviceCommands.get_device_uuid);
        });


        $('#reset_lang').on('click', function() {
            hidWriteRawData(deviceCommands.reset_lang);
        });

        $('#mnemonicButton').on('click', function() {
            getMnemonic();
        });


        $('#scan_wallet').on('click', function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $('#rename_wallet_variable').on('click', function() {
            hidWriteRawData(constructRenameWallet());
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_action').on('click', function(event) {
            event.preventDefault();
            constructNewWallet();
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#uuid').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.get_device_uuid);
        });

        $('#payments_toggle').click(function() {
            $('#payments_panel').slideToggle('fast', function() {
                // Animation complete.
            });
        });


        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////
        // TO BE DEPRECATED
        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////

        $('#new_wallet_0').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_0);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_1').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_1);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_2').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_2);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_3').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_3);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_4').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_4);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_5').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_5);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_6').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_6);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_7').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_7);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_8').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_8);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_9').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_9);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_10').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_10);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_11').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_11);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_12').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_12);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_13').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_13);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_14').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_14);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_15').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_15);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_16').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_16);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_17').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_17);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_18').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_18);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_19').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_19);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_20').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_20);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_21').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_21);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_22').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_22);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_23').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_23);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_24').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_24);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });

        $('#new_wallet_25').on('click', function(event) {
            event.preventDefault();
            hidWriteRawData(deviceCommands.new_wallet_25);
            pausecomp(10);
            hidWriteRawData(deviceCommands.button_ack);
        });



        $(document).on("click", "#wallet_0", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_0);
//             check 34
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_0").innerHTML;
//             check field loaded
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_1", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_1);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_1").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_2", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_2);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_2").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_3", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_3);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_3").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_4", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_4);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_4").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_5", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_5);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_5").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_6", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_6);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_6").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_7", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_7);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_7").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_8", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_8);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_8").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_9", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_9);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_9").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_10", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_10);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_10").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_11", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_11);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_11").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_12", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_12);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_12").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_13", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_13);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_13").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_14", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_14);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_14").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_15", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_15);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_15").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_16", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_16);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_16").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_17", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_17);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_17").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_18", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_18);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_18").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_19", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_19);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_19").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_20", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_20);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_20").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_21", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_21);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_21").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_22", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_22);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_22").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_23", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_23);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_23").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_24", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_24);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_24").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });

        $(document).on("click", "#wallet_25", function() {
            event.preventDefault();
            hidWriteRawData(deviceCommands.load_wallet_25);
            document.getElementById("loaded_wallet_name").innerHTML = document.getElementById("name_25").innerHTML;
            pausecomp(10);
            hidWriteRawData(deviceCommands.scan_wallet);
        });








        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////
        // LOCKBOX SPECIFIC ON READY END
        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////
// 
//         // sign
// 
//         $('#sgSec').val($('#sec').val());
//         $('#sgAddr').val($('#addr').val());
//         $('#sgMsg').val("This is an example of a signed message.");
// 
//         onInput('#sgSec', sgOnChangeSec);
//         onInput('#sgMsg', sgOnChangeMsg);
// 
//         $('#sgSign').click(sgSign);
//         $('#sgForm').submit(sgSign);
// 
//         // verify
// 
//         $('#vrVerify').click(vrVerify);
//         onInput('#vrSig', vrOnChangeSig);
// 
//         $('#sgType label input').on('change', sgOnChangeType);
// 
//         $('#vrSig').val('-----BEGIN BITCOIN SIGNED MESSAGE-----\n'
//         +'This is an example of a signed message.\n'
//         +'-----BEGIN SIGNATURE-----\n'
//         +'<insert address here>\n'
//         +'Gyk26Le4ER0EUvZiFGUCXhJKWVEoTtQNU449puYZPaiUmYyrcozt2LuAMgLvnEgpoF6cw8ob9Mj/CjP9ATydO1k=\n'
//         +'-----END BITCOIN SIGNED MESSAGE-----');




        monitorUSBHID();


    });



})(jQuery);