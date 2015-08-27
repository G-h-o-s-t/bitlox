(function($) {

// globals
	var scriptsToReplace = [];


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
    
    
    
    
    function txOnAddDest() {
        var list = $(document).find('.txCC');
        var clone = list.last().clone();
        clone.find('.help-inline').empty();
        clone.find('.control-label').text('Cc');
        var dest = clone.find('#txDest');
        var value = clone.find('#txValue');
        clone.insertAfter(list.last());
        onInput(dest, txOnChangeDest);
        onInput(value, txOnChangeDest);
        dest.val('');
        value.val('');
        $('#txRemoveDest').attr('disabled', false);
        return false;
    }

    function txOnRemoveDest() {
        var list = $(document).find('.txCC');
        if (list.size() == 2)
            $('#txRemoveDest').attr('disabled', true);
        list.last().remove();
        return false;
    }

    function txOnChangeDest() {
        var balance = parseFloat($('#txBalance').val());
        var fval = parseFloat('0'+$('#txValue').val());
        var fee = parseFloat('0'+$('#txFee').val());

        if (fval + fee > balance) {
            fee = balance - fval;
            $('#txFee').val(fee > 0 ? fee : '0.00');
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
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
    // PROTOBUF ENCODED MESSAGES
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


	function constructPing() {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
		var pin = Crypto.util.bytesToHex(Crypto.charenc.UTF8.stringToBytes(document.getElementById('ping_input').value));
		
// 		var bbPIN = new ByteBuffer();
//         var parseLength = pin.length
// // 	console.log("utx length = " + parseLength);
//         var i;
//         for (i = 0; i < parseLength; i += 2) {
//             var value = pin.substring(i, i + 2);
// // 	console.log("value = " + value);		
//             var prefix = "0x";
//             var together = prefix.concat(value);
// // 	console.log("together = " + together);
//             var result = parseInt(together);
// // 	console.log("result = " + result);
// 
//             bbPIN.writeUint8(result);
//         }
//         bbPIN.flip();
        
        var pinAckMessage = new Device.Ping({
			"greeting": document.getElementById('ping_input').value
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

        var command = "0000"; 
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
		
// PASSWORD *DEPRECATED* Value in this field merely toggles the on-device password routine
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
// Sign Transaction Prep
////////////////////////////

    var prepForSigning = function(unsignedtx, originatingTransactionArray, originatingTransactionArrayIndices, address_handle_chain, address_handle_index) {
        var ProtoBuf = dcodeIO.ProtoBuf;
        var ByteBuffer = dcodeIO.ByteBuffer;
        var builder = ProtoBuf.loadProtoFile("js/messages.proto"),
            Device = builder.build();
		var numberOfInputsinArray = originatingTransactionArray.length;
        console.log("numberOfInputsinArray: " + numberOfInputsinArray);
            
		var m;
		for(m = 0; m < numberOfInputsinArray; m++)
        {    
	        console.log("Originating Transaction "+m+": " + originatingTransactionArray[m]);
		}

        
        
		var address_handle_root = [];
		for(m = 0; m < numberOfInputsinArray; m++)
		{
			address_handle_root[m] = 0;
		}
		
		var address_handle_extended_data = []; // empty array
		var k;
		for (k=0;k<numberOfInputsinArray;k++)
		{
			address_handle_extended_data.push({address_handle_root: address_handle_root[k], address_handle_chain: address_handle_chain[k], address_handle_index: address_handle_index[k]});
		}
		console.log(JSON.stringify(address_handle_extended_data));

// EXPERIMENTAL
		var change_address_data = []; // empty array
		var kk;
		for (kk=0;kk<1;kk++)
		{
			change_address_data.push({address_handle_root: 0, address_handle_chain: 1, address_handle_index: 3});
		}
		console.log("change: " + JSON.stringify(change_address_data));



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


		for(m = 0; m < numberOfInputsinArray; m++)
		{
			console.log("address_handle_root["+m+"]" + address_handle_root[m]);       
			console.log("address_handle_chain["+m+"]" + address_handle_chain[m]);       
			console.log("address_handle_index["+m+"]" + address_handle_index[m]);       
      	}

        var txContents = new Device.SignTransactionExtended({
        	"address_handle_extended": address_handle_extended_data
        	,
            "transaction_data": bb
//             ,
//             "change_address": address_handle_extended_data
        });
        
        
//          var txContents = new Device.SignTransactionExtended({
//         	"address_handle_extended": 
//         	[
//         		{
// 					"address_handle_root": address_handle_root[0], 
// 					"address_handle_chain": address_handle_chain[0], 
// 					"address_handle_index": address_handle_index[0]
// 				}
// // 				depending on the number of inputs this will be extended as shown
// // 				,
// //         		{
// // 					"address_handle_root": address_handle_root[1], 
// // 					"address_handle_chain": address_handle_chain[1], 
// // 					"address_handle_index": address_handle_index[1]
// // 				}
// // 				,
// //         		{
// // 					"address_handle_root": address_handle_root[2], 
// // 					"address_handle_chain": address_handle_chain[2], 
// // 					"address_handle_index": address_handle_index[2]
// // 				}
// // 				,
// //         		{
// // 					"address_handle_root": address_handle_root[3], 
// // 					"address_handle_chain": address_handle_chain[3], 
// // 					"address_handle_index": address_handle_index[3]
// // 				}
// // 				,
// //         		{
// // 					"address_handle_root": address_handle_root[4], 
// // 					"address_handle_chain": address_handle_chain[4], 
// // 					"address_handle_index": address_handle_index[4]
// // 				}
// 			],
//             "transaction_data": bb
//         });
        

               
//         tempBuffer = txContents.encodeDelimited();
        tempBuffer = txContents.encode();
        
        
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
        console.log("READY");

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
//         VendorID: 0x051B,
        VendorID: 0x03EB,
        ProductID: 0x204F
            //0x6E68   
    };

    var deviceCommands = {
        ping: '23230000000000070A0548656C6C6F',
        format_storage: '2323000D000000220A204242424242424242424242424242424242424242424242424242424242424242',
        button_ack: '2323005100000000',
        button_cancel: '2323005200000000',
        pin_cancel: '2323005500000000',
        otp_cancel: '2323005800000000',

        list_wallets: '2323001000000000',

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
        raw_blink: '0080082055060800dd060800dd060800dd060800dd060800dd06080000000000000000000000000000000000df060800dd06080000000000e3060800e7060800dd060800dd060800dd060800dd060800dd060800dd060800dd060800dd060800790108000000000000000000dd060800dd060800000000000000000000000000000000008901080095010800dd06080000000000dd060800dd060800dd060800dd06080000000000dd060800dd060800dd060800dd060800dd060800dd060800dd060800000000000000000000000000dd060800dd060800dd060800dd060800cd060800dd06080000000000dd060800dd06080010b5054c237833b9044b13b10448aff300800123237010bd70040720000000006424080008b5064b1bb106480649aff300800648036813b1054b03b1984708bd00000000642408007404072064240800000000000d20012100f0f2ba08b501210d2000f01ffb4ff47a7000f0d1fa0d20002100f017fbbde808404ff47a7000f0c7ba7047014800f007bc00bf8c04072070477047014800f09bbc00bff4040720014800f095bc00bf14050720f8b53a4d00f012fa2b684ff47a72b3fbf2f35a1e364bf0215a60364a002482f8231007229c6034481a6000f0fbf901f0b1fb2f4620460021013400f0ddfa2a2cf8d12e4c2e4d4ff0ff36c4f8a0604ff440720023c5f8a0602046012100f04af90020012100f0c8fa204601214ff44062002300f03ff9204601214ff44052002300f038f9284601214ff44062002300f031f9204601210322002300f02bf901214ff440420023284600f024f9252000f067f93968134a0c23134800f077f80123114800214ff4401200f0c3f800210a460d4800f0b7f831460b4800f0cbf80a4800f0c4f8bde8f84000f04aba2c00072010e000e000ed00e0501a0e40000e0e4000100e40002d310100000c4037b5114c114d204600f0cefa082213460f4900940f48104c00f052fb284600f0c3fa204600f0c0fa1122134600950b490b4800f0b1fb122200940a4913460a4800f0aafb03b030bdac0407203405072000080e408c0407207c05072000800940f404072000c009401405072008b5094800f0b2fa08b1fff728ff074800f046fb08b1fff729ff054800f040fb08b1fff724ff08bd8c040720f4040720140507202de9f041224d90b06c4606460f4690469c460fcd0fc40fcd0fc40fcd0fc495e80f0084e80f000123336000214fea480240f202237160c6f82031c6f80411c6f81411b7fbf2f102fb117202b901394b1c5b00b7fbf3f70f4b0022b7fbf3f70cfb07fc5df82200604505d20132102af8d14ff0ff3009e07368090289b21204194302f470220a437260002010b0bde8f0811421080040420f004368d2011943d3b219434160704710b54468090622431b0701f07064224303f040531a43426010bd4ff6ff7343617047816270470ab14166704701667047426405290dd8dfe801f00d03090d0d0d036f016f0b4023ea020301e0036f1343036742607047d30741644cbf4166016612f00a0f14bf01624162930701d4130701d5c0f8801041610160704710b5029c41640cb1416600e001660bb1016500e041650ab1016300e041630161016010bd0000f7b51e464b1e05460f461446042b1fd8dfe803f003030c12120022460e4b9847f2076c644cbf6c662c6603e0214632460a4b984701200ce006f0010300937b1f5a4221465a41064cc6f38003a047f1e7002003b0f0bd00bf23040800490408006f04080003468068084004d09b6919420cbf002001207047034b4ff44412da619a6e5206fcd5704700060e402c2819d81f280e4b4ff0010208d802fa00f0996900ea010282420fd018610de0203802fa00f0d3f8081100ea0102824204d0c3f8000101e0012070470020704700060e402c2817d81f280d4b4ff0010107d801fa00f09a69024082420ed15a610ce0203801fa00f0d3f808210240824204d1c3f8042101e0012070470020704700060e40000200f47062024b42f001029a63704700060e40014b20221a60704700060e404ff40043436070471a4a4ff480631360c2f80032184b1a6ad20102d5174a1a6205e0174a1a629a6ed007fcd5f6e7996e114ac903fbd5116b21f0030141f0010111639a6e1207fcd50e490b4a91629a6e9007fcd5084a112111639a6e1107fcd5054a122111639a6e1207fcd5064a074b1a607047000a0e4000060e400908370109083700013f0d2000bd01052c000720154b164a10b593421c4601d0002301e0134b07e01349d0188842f9d2e158d1500433f7e7104a934203d2002243f8042bf8e70e490e4b21f0604201f1604122f07f02b1f5801f9a6003d29a6842f000529a60084b9847fee7642408000000072070040720700407209c0807200000080000ed00e0e507080008b5024b1b6803b1984708bdc4050720fee700f010b800f00eb808b500f009f828b900f0a1f8bde8084000f03dbf08bd704700207047fee738b5044648b100f03bff0546fff7f4ff00f036ff401ba042f8d338bd0023034a0021995401332a2bf9d17047c805072070b51c254543164e7419237b3bb3012916d002d3022908d070bda068fff7e6fe705903216268002306e0a068fff7defe7059626803210123bde87040fff790be75592369284605216268fff789feab69013304d1a068bde87040fff7e9be70bd101b08001c2273b550430f4b0e461a18117bb1b11d58546828462146fff7a2fe38b928462146324602b0bde87040fff729be012300932846214632460023fff74cfe02b070bd00bf101b08007047000008b5fff7dbfcfff7f9ff0120fff788ff064800f0a5fafff7a5fcfff7a7fc044b002bfad0fff786fdf7e700bf0806072019030800014b1860704700bf30000720024b4ff0ff321a60704700bf30000720054a08b51368591c04d0013b13600bb9024b984708bd00bf300007200100072010b500214022044601f092f8002323646364204610bd026c10b5531c446c03f03f03a3421cbf8154036410bd012070470369186c5b6cc01a00f03f00704703695a6c196c914214bf985c4ff0ff30704703695a6c196c914205d0985c013202f03f025a6470474ff0ff307047426953691b05fcd5704743695a699207fcd5d9610120704738b50446c0690d46fff71efe636940f20222c3f82021ac221a604ff400625a600c4a01211268b2fbf5f52d094ff0ff321d62da6061229a60227e50b202f01f0201fa02f20449400941f8202050221a6038bd00bf2c00072000e100e0036910b55a6c04461a64037e012259b203f01f0302fa03f34909064a203142f8213003685b699847e069bde81040fff7ffbd00bf00e100e030b5002545604ff47a758560034d41610560039d02760561c36130bd6021080038b5436904465d69ea0704d599690069c9b2fff764ff15f0600f04d063691a6842f480721a6038bd012070470369186c5b6cc01a00f03f00704703695a6c196c914214bf985c4ff0ff30704703695a6c196c914205d0985c013202f03f025a6470474ff0ff307047426953699b05fcd5704743695a699207fcd5d96101207047036910b55a6c04461a64037e012259b203f01f0302fa03f34909064a203142f8213003685b699847e069bde81040fff793bd00bf00e100e030b5002545604ff47a758560034d41610560039d02760561c36130bd9021080070b50446c0690d461646fff757fd636940f20222c3f82021ac221a600c4a5e6012680121b2fbf5f52d094ff0ff321d62da6061229a60227e50b202f01f0201fa02f20449400941f8202050221a6070bd2c00072000e100e04ff40c62fff7d0bf38b5436904465d69ea0704d599690069c9b2fff7c8fe15f0600f04d063691a6842f480721a6038bd064bd3f83021d20703d45b68d90703d4f6e70122c3f86021704700bf00c00a4038b5094b1d6872b6bff35f8f1c4600f00f000023236000f0c5fe25b101232360bff35f8f62b638bd400007202de9f8431b4b89461b6815463bb31a4bd3f8008072b6bff35f8f00f00f04002620461f461e6000f0a7fea84238bf0546ae4206d0204600f067fe09f806000136f6e71db1204600f097fe78b1b8f1000f09d001233b60bff35f8f62b603e04ff0ff30bde8f8832846bde8f883204600f08dfeebe7100607204000072007b501220df1070100f00f00fff7baff01280cbf9df807004ff0ff3003b05df804fb0000114b2de9f0411b6880460d461746b3b114468cb1b8f1000f14bf4ff400764026a64228bf2646294608f00f003246a41b00f0c4fd3544ece73846bde8f0814ff0ff30bde8f08100bf100607202de9f04115460c4f0c4a3b681268884693420bda2c46002644b108eb06012246002000f0a5fd0644241af5e73b6828462b443b60bde8f081f4050720f805072030b50123a1b0c21812f8014c5a0064b942f4407369460020adf80030fff7d0ff003018bf012021b030bd8d1a002defdd2df802400133e6e738b50c46054600f047fd00202946224600f0dcfd00f054fd204638bd03790bb900f02cbb022b01d100f0a0bb0020704713b5002302ac04f8013d204600f00afb204600f069fb9df8070002b010bd13b5002302ac04f8013d204600f005fb204600f05afb9df8070002b010bd10b5044600f0d0fd20b12046bde8104000f0e8bd10bd000010b50446054800f033fc00f037fc10b9034b01221a60204610bd00bf710d08000406072008b5054b186828b100f08efc034b00221a60012008bd00bf04060720100607200148fff7dbbf00bf080607202de9f047ad4c86b063681f0717d52368002023f07f032360236842f2320143f08003236000f092fca54b04221a604ff48053a361a34b00221a600823a3609f4b5b685e0408d5a04b02201860fff7a6fe10b19e4800f046fa984b5a68550744bf04229a605b68dc0440f1cb8100f0cafc002800f0c681002001a9082200f03cfd00f0c8fc9df80450280602d500f092fc01e000f09ffc15f0600440f09d819df8053073b99df80440acb1894b1b780020012b14bf0146012100f0f8fc0020014680e1012b0dd19df80630012b01d1814bece77f4b1c702046214600f0e7fc2046ede7032b75d19df80630012b05d1794a20462146137000f0d9fc9df8060028b9734b012201461a7000f0d0fc9df80630022b40f06e819df80430002b40f06981bdf80830190740f06481644c1b0a6269013b22f001026261226842f400622260032b00f25681dfe803f031383f02fff715fe0023c4f81833c4f8283341f23013c4f80831d4f8083143f00203c4f80831524bd3f838215203fad5da6942f00402da61554b554a9a5c03f8012f544a9342f8d14a4b1a6842f400421a600122c3f868214ff48042c3f82822fee7fff7e6fd236843f400532360fee7fff7dffd236843f480432360fee7fff7d8fd454b6361fee7052b06d100f0edfb9df8060000f0e1fc06e1062b40f0ca809df807603e4f022e9df80630bdf80a50dff808813c6029d1c8f80040fff7a9fe4ff00909824621464a4603a800f0fdfc01238df81130c0238df81330fa238df814303b6803a94b444a462046adf80e308df80c908df80d608df810a03c60c8f80050fff732fefff784fecde0222ec8f8005006d1304600f0faf9003018bf0120c1e0012e0ed1082d1e4b04bf01221a6019681c4a1d4b002914bf11461946112d73d813e0032e3ad123b918490b78ab420cd86ae0022b01d1164803e0012b40f0a68014482946fff720fe9ce0eab25be000bf00c00a40f0c10a401006072068c10a4020080720f205072000060720ffff1820ed21efdf340019207ff0077ef4050720fc0507202d220800c0210800e8210800b821080021220800f8050720062e04d1092d76d8eab23d492de0072e4ff000046cd1c8f80040fff72afe4ff00909824621464a4603a800f06ffc01238df81130c0238df81330fa238df814303b6803a94b444a462046adf80e308df80c908df80d608df810a03c60c8f80050fff7a4fdfff705fe3fe002b90a780020fff79cfd39e0072b3ad0082b04d1214b20461968c9b219e0092b12d1eb062fd11d48052100f0ecfa9df80620194b1a601a4b02221a604ff48042a3f5fc739a611be00a2b05d1164b0020197800f072fb13e00b2b11d19df80620114b1a600ce000f0ecfa0f4b00211960bdf80a200e4b01a81a60fff7acfd10b100f0effa04e000f098fb01e00249b8e706b0bde8f0873f22080010060720d4210800f8c10a400c060720f4050720f8050720f8b506460c468f180025bc4207d0336830461b6814f8011b98470544f5e72846f8bd0000044bd3f80002d3f80432c01ac0f30800704700bf14060720064bd3f80012d3f8042291421abfd3f80422985c4ff0ff30704700bf1406072013b5026802ab03f8011d546819460122a04702b010bd000038b50f4b0446d3f80012d3f80422914213d0d3f8042202209d5cd3f804220132c2f30802c3f80422fff76cfc18b1236820469b699847284638bd4ff0ff3038bd140607200320fff75bbd0000f8b5184b53e8003f164e13b1bff32f8ff8bd012346e80033002bf2d1124bd3f800421f460134c4f30804d7f804320e4d9c4214d00220fff73ffc20b90b4b4ff480421a600be00220fff78afcd5f80032c5f800420134e854c4f30804e5e700233360f8bd1c0807201406072028c20a4010b5094b0446db7903f0ff0043b10320fff780fc002805dc01236360002010bd0123636010bd00bf34000720037803490233037042220020fff792bcc2220800037803490233037042220020fff788bc8022080008b502784378a12a08d1212b4ff0000020d113490722fff779fc1ee0212a1ad1202b04d107210e48fff7acfc15e0222b11d182780a4bda711a68b2f5966f0cd1db79db0703d4fa20fff75afa05e0fff75dfa02e008bd002008bd012008bd00bf34000720044b00225a604ff47a729a60024a1a60704700bf2008072060220800036870b59b6804460e46984723680546db68204631469847e8b270bd037803490133037019220020fff730bca8230800002002496522fff729bc00bfc123080000b591b08df800000023934203f1010305d0c81810f8010c0df80300f5e769461a460420fff7ecfb11b05df804fb000002784378a12a05d1012b11d0033b584258417047212a0dd10b2b02d18278064b03e00a2b06d18278044b1a700120704718467047002070473c0007203d00072008b502200822fff7c3ff08bd872910b502d97831c9b215e00a0608d50123803903fa01f1037a1943017200210ae0184b595c49b30b0605d5037a01f07f0143f002030372837a8b4218d0c37a8b4215d0037b8b4212d0437b8b420fd0837b8b420cd0c37b8b4209d00023c218947a0cb9917203e00133062bf7d105e000f10801fff7beff012010bd01234360002010bd28230800872910b502d97831c9b216e00a0609d50123803903fa01f1037a23ea0101017200210ae00e4b595cc1b10b0605d5037a01f07f0123f002030372002329b1c218947a8c4204bf002494720133062bf5d100f10801fff78aff012010bd084610bd28230800002301468372c372037343738373c37301f8083ffff778bf034b00221a70034b5a60034a1a607047340807203808072010230800024b1a6801321a60704700bf48080720014b1868704700bf48080720014b1860704700bfc405072010b500232a4a002442f82340294a42f8234001330a2bf5d1274b28209847274b98472046264b9847264b9847264b4ff4807283f828435a60244b2046d3f8002822f08072c3f80028d3f8002842f00072c3f80028d3f8002822f08072c3f80028d3f8002822f48052c3f80028d3f8002842f48052c3f80028d3f8002842f40042c3f80028d3f8002822f48042c3f800281a6822f480521a601a6822f440621a60d3f8002842f48042c3f8002810bd00bf740807204c080720210508000d050800a5050800b905080000e100e000c00a40114b10b5196872b6bff35f8f1a46002313600e4bd3f800081c4620f48040c3f80008d4f80408094b4004fad5186820f4807018600820986121b101231360bff35f8f62b610bd00bf4000072000c00a40094b00f00f0000f1400243f8221001228240d9690a43da6103f5987353f820305b0300d4fee7704700c00a4030b501238b4214d20a4a50f8045f03f1400442f8245001249c40d5692c43d461054a1a4492001268520300d4fee70133e8e730bd00c00a404cb00210024bd3f83031db07fad5704700c00a40024bd3f830319b07fad5704700c00a40034b0122c3f86021024b00221a60704700c00a4074080720034b0222c3f86021024b00221a60704700c00a404c080720024bd3f8300100f00400704700c00a40024b0422c3f86021704700bf00c00a40f8b51546c20302f10052034602f5c012980000f1804000f52c24d4f83041e407f6d5174c3bb926682e44402e06d92568c5f1400502e0002644f8236054f8236016440022aa4203d08f5cb7540132f9e754f823202a4444f8232033b9084b1b68402b0bd1074b984708e000f52c230122c3f860214ff48042c3f820222846f8bd7408072045170800074b53f8202002ebc03202f1005202f5c012117053f82020013243f82020704774080720084a034652f8201001ebc03101f1005101f5c011087852f82310013142f82310704700bf4c08072070b50b4cc30303f1005354f8205003f5c0131d440023934203d0ee5cce540133f9e754f82020134444f8203070bd00bf4c080720034b0122da614ff40022c3f8f021704700c00a40034b4c3053f82000c0f30a50704700bf00c00a40830003f1804303f52c230222c3f860214ff48042c3f82022024b002243f82020704700bf4c080720830003f1804303f52c230122c3f860214ff48042c3f82022024b002243f82020704700bf74080720064b00f07f001a6822f07f0202431a601a6842f080021a60704700bf00c00a4070b50f4e0f4d761bb61007d0043d0024013455f8043f9847a642f9d10a4e0b4d00f06cfd761bb61008d0043d0024013455f8043f9847a642f9d170bd70bd00bf3c2408003c240800542408003c240800f0b4840743d0541e002a3ed0cdb2034603e0621e002c38d0144603f8015b9a07f7d1032c2ad9cdb245ea05250f2c45ea054515d9a4f110073f0903f1100606eb07161a46156055609560d5601032b242f8d104f00f040137032c03eb07130dd91e462246043a032a46f8045bfad8221f22f003020432134404f003042cb1c9b21c4403f8011ba342fbd1f0bc704714460346c6e7024b13b1024800f005b8704700000000391a0800014600200246034600f018b838b5094d094c641ba41018bf05eb840505d0013c55f8043d9847002cf9d1bde8384000f0fbbc00bf6024080064240800f0b5274c85b026680746d6f84841002c40d065681f2d1edd224818b94ff0ff3005b0f0bd4ff4c870039102920193aff3008003990446029a019b0028eed0d6f848510020256060600546c6f84841c4f88801c4f88c013fb96b1c00200235636044f8251005b0f0bd0126ae4004eb8500c0f88820d4f88821022f42ea0602c4f88821c0f80831e7d1d4f88c311e43c4f88c61e1e706f5a674c6f84841b9e700bf2c24080000000000000e0e40000100000b000000010000000000000004000000ffffffff000e0e40000200000b000000010000000000000004000000ffffffff00100e40000000080c000000020000000000000014000000ffffff01000e0e40002000000b000000010000000000000004000000ffffffff000e0e40001000000b000000010000000000000004000000ffffffff000e0e40000800000b000000010000000000000004000000ffffffff000e0e40000400000b000000010000000000000004000000ffffffff00100e40001000000c000000010000000000000004000000ffffffff00100e40002000000c000000010000000000000004000000ffffffff00100e40000000040c000000040000000000000004000000ffffffff000e0e40004000000b000000040000000000000004000000ffffffff000e0e40008000000b000000040000000000000004000000ffffffff000e0e40800000000b000000040000000000000004000000ffffffff00100e40000000020c000000020000000000000014000000ffffff00000e0e40000008000b000000040000000000000004000000ffffffff000e0e40000010000b000000040000000000000004000000ffffffff00100e40000020000c000000040000000000000004000000ffffffff00100e40004000000c000000040000000000000004000000ffffffff000e0e40000001000b0000000300000000000000020000000007ffff000e0e40000000010b0000000300000000000000020000000106ffff000e0e40000080000b0000000300000000000000020000000205ffff000e0e40000040000b0000000300000000000000020000000304ffff000e0e40400000000b0000000300000000000000020000000403ff05000e0e40100000000b0000000300000000000000020000000502ffff000e0e40080000000b0000000300000000000000020000000601ff03000e0e40040000000b0000000300000000000000020000000700ff0200100e40000002000c000000030000000000000002000000080affff00100e40000004000c000000030000000000000002000000090bffff00100e40000008000c0000000300000000000000020000000a0cffff00100e40000010000c0000000300000000000000020000000b0dffff00100e40008000000c0000000300000000000000020000000c10ffff00100e40000001000c0000000300000000000000020000000d11ffff000e0e40020000000b0000000100000000000000040000000effffff000e0e40010000000b0000000100000000000000020000000fffffff000e0e40000002000b000000010000000000000004000000ffffffff000e0e40000004000b000000010000000000000004000000ffffffff000e0e40000020000b000000040000000000000004000000ffffffff000e0e40000000020b000000010000000000000004000000ffffffff000e0e40000000040b000000010000000000000004000000ffffffff000e0e40000000080b000000010000000000000004000000ffffffff000e0e40000000100b000000010000000000000004000000ffffffff000e0e40000000200b000000010000000000000004000000ffffffff000e0e40000006000b000000010000000000000005000000ffffffff00100e40003000000c000000010000000000000005000000ffffffff000e0e40000300000b000000010000000000000005000000ffffffff000e0e40000c00000b000000010000000000000005000000ffffffff000e0e40003000000b000000010000000000000005000000ffffffff00100e40000c00000c000000010000000000000004000000ffffffff00100e40000020000c000000020000000000000004000000ffffffff00100e40000080000c000000020000000000000004000000ffffffff00100e40008000000c000000010000000000000004000000ffffffff00100e40004000000c000000010000000000000004000000ffffffff000e0e40030000000b000000010000000000000005000000ffffffff00100e4000c000000c000000010000000000000005000000ffffffff000000000000000000000000000000000000000000000000ffffffff0000000008000000100000001800000040000000500000006000000070000000000200004002000080020000c0020000000300004003000080030000c0030000000000000000000000000000cb0808009511080085080800a508080093080800c1080800d90808003509080081080800000000000000000000000000ff09080095110800b9090800d9090800c7090800f5090800bd0a08000d0a0800b5090800000000004c6f636b626f7800120100020000004041233e000001010200010000322000003639000066300000663100003639000004030904000000000000000000aaaaaaaaaaaaaaaaeeeeeeeeeeeeeeeefeffffffffffffffffffffff7fbfdfeff7fbfdfc7ebfdfeff7fbfd7e41726475696e6f204c4c4300120100020200004041233e000001010200010a0600020000004001000000000000000000000000000000000000000000000000f1110800c5120800b911080009120800d11108004d1208005512080000000000080b000202020100090400000102020000052400100105240101010424020605240600010705810310001009040100020a0000000705020240000007058302400000080b000202020100090400000102020000052400100105240101010424020605240600010705810310001009040100020a0000000705020200020007058302000200000000000000000000000000991308009511080055140800dd140800411508000000000000000000000000002a2b280000000000000000000000000000000000000000002c9eb4a0a1a2a434a6a7a5ae362d3738271e1f20212223242526b333b62eb7b89f8485868788898a8b8c8d8e8f909192939495969798999a9b9c9d2f3130a3ad350405060708090a0b0c0d0e0f101112131415161718191a1b1c1dafb1b0b5000904020001030000000921010100012265000705840340000105010902a1010901a10085010509190129031500250195037501810295017505810305010930093109381581257f750895038106c0c005010906a1018502050719e029e71500250175019508810295017508810395067508150025650507190029658100c000004300000048000720f8b500bff8bc08bc9e467047191a080019010800ad020800650d08007d13080059150800f8b500bff8bc08bc9e467047f500080072b6064b9a68d107fbd5054a5a609a68d207fcd5034a044b1a60fee7000a0e400c01005a050000a5001a0e4000093d00ffffffff00e100000000080001010000010000000000000000000000340307209c03072004040720000000000000000000000000000000000000000000000000000000000000000000000000282408000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000e33cdab34126de6ecde05000b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
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
        var targetlength = 40;
		var bytes;
        if (str.length <= targetlength) {
            length = str.length;
        }
		hex = Crypto.util.bytesToHex(Crypto.charenc.UTF8.stringToBytes(str));
        while (hex.length < (targetlength*2)) {
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






    ///////////////////////////////////////////////////////////////////////////////////////
    // HID functions
    ///////////////////////////////////////////////////////////////////////////////////////

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

    function hidAskFeature() {
        sendToDevice = '01';
        var txResult = device.hid_send_feature_report(sendToDevice);
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

    ///////////////////////////////////////////////////////////////////////////////////////
    // HID functions END
    ///////////////////////////////////////////////////////////////////////////////////////








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
//                     console.log("vendor: " + featuresMessage.vendor);
//                     console.log("config: " + featuresMessage.config);
//                     console.log("device name: " + featuresMessage.device_name);
// 					document.getElementById("device_name").innerHTML = featuresMessage.device_name;
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

                	var securedWallet = ''
                    $("#wallet_table").find("tr").remove();
                    var walletDataArray = "";
                    walletDataArray = walletMessage.wallet_info;
                    var index;
                    for (index = 0; index < walletDataArray.length; index++) {
                    	if(	walletMessage.wallet_info[index].version == 3)
                    	{
                    		securedWallet = ' <span class="glyphicon glyphicon-lock"></span>'
                    	}
                        var wallet_number = walletMessage.wallet_info[index].wallet_number;
                        var wallet_name = walletMessage.wallet_info[index].wallet_name.toString("utf8");
                        var row = '<tr id="wallet_' + wallet_number + '"><td class="iterator">' + wallet_number + '</td><td class="address-field" id="name_' + wallet_number + '" style="cursor:pointer">' + wallet_name + securedWallet +'</td></tr>';
                        $('#wallet_table').append(row);
                        securedWallet = '';
                    }
                    break;

                if (chain === 'receive') {
                    qrcode = ' <span class="open-qroverlay glyphicon glyphicon-qrcode" data-toggle="modal" data-target="#qroverlay" data-addr="' + childaddr + '"></span>';
                    qrcode2 = ' <span class="open-sendMsgFrom glyphicon glyphicon-envelope" data-target="#sign" data-addr="' + childaddr + '" data-index="' + index + '" data-chain="' + chain + '"></span>';
                }
                var row = '<tr id="' + childaddr + '"><td class="iterator">' + index + '</td><td class="address-field">' + childaddr + qrcode + qrcode2 + '</td><td class="balance">?</td></tr>';
                $('#' + chain + '_table').append(row);
                addresses[chain][childaddr] = childkey;






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
                    var SignatureComplete = Device.SignatureComplete.decodeHex(payload);
// 					console.log("SignatureComplete: " + SignatureComplete.signature_complete_data);
//                  console.log("number of signatures: " + SignatureComplete.signature_complete_data.length);
                    var sigIndex;
                    var unSignedTransaction = document.getElementById("output_transaction").value;
// 					console.log("unSignedTransaction pre: " + unSignedTransaction);
                    
                    for (sigIndex=0; sigIndex < SignatureComplete.signature_complete_data.length; sigIndex++){
                    
                    	var payloadSig = SignatureComplete.signature_complete_data[sigIndex].signature_data_complete.toString("hex");
                    	var payloadSigSizeHex = payloadSig.substring(0, 2);
                    	var payloadSigSizeDec = h2d(payloadSigSizeHex);
                    	var payloadSigSizeChars = 2 + (payloadSigSizeDec * 2);
// 						console.log("SignatureComplete:Data:signature_data_complete " + sigIndex + "  SIZE (HEX) " + payloadSigSizeHex + "  SIZE (DEC) " + payloadSigSizeDec);
// 						console.log("SignatureComplete:Data:signature_data_complete RAW " + sigIndex + " " + payloadSig);
						payloadSig = payloadSig.substring(0, payloadSigSizeChars);
// 						console.log("SignatureComplete:Data:signature_data_complete TRIM " + sigIndex + " " + payloadSig);
						var scriptPrefix = "19";
						var script = scriptPrefix.concat(scriptsToReplace[sigIndex]);

// 						console.log("script to replace: " + script);
// 						console.log("unSignedTransaction: " + unSignedTransaction);

						unSignedTransaction = unSignedTransaction.replace(script, payloadSig);
// 						console.log("SignatureComplete:Data:signature_data_complete part SIGNED " + sigIndex + " " + unSignedTransaction);
                    }
// 					console.log("SignatureComplete:Data:signature_data_complete SIGNED " + unSignedTransaction);
                    document.getElementById("ready_to_transmit").textContent = unSignedTransaction;
                    $("#signedtxlabel").show()

                    $("#submit_signed_transaction").removeAttr('disabled');

										
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

    function autoCannedTransactionMega(transData) {
        chunkSize = 32;
        var chunkedTData = [];
        var tempDTS = '';
        tempDTS = transData;
        console.log('Size of transData : ' + tempDTS.length);
//         var transDataRemainder = tempDTS.length % 16;
// //         console.log('Remainder : ' + transDataRemainder);
//         if(transDataRemainder==0||transDataRemainder==12||transDataRemainder==14){
// 			var prepend = '00000000';
// 			tempDTS = prepend.concat(tempDTS);
// 		}			
//         console.log('tempDTS : ' + tempDTS);
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
//         console.log('dataToSend.length: ' + dataToSend.length); 
		sendToDevice = '00' + dataToSend;
		var txResult = device.hid_write(sendToDevice);
// 		console.log('HID TX : ' + sendToDevice);
// 		console.log('HID TX size: ' + txResult);
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

    var GAP = 1; // how many extra addresses to generate

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


//     var createtx = function() {
//         var intx = "1197be06096230bf4b8e4de121607dd797c60df60545eda8d90b7f876f24694e";
//         in0 = b.derive_child(1)
//         var inaddr = getAddr(in0);
//         var outaddr0 = "n2hpygZMYkGAB2zbLEaUbBr3EJ5NK9vMHp";
//         var outaddr1 = getAddr(b.derive_child(0));
//         console.log(inaddr);
//         console.log(outaddr0);
//         console.log(outaddr1);
// 
//         o0s = createOutScript(outaddr0);
//         o1s = createOutScript(outaddr1);
//         to0 = new Bitcoin.TransactionOut({
//             value: valueFromNumber(0.01234567),
//             script: o0s
//         });
//         to1 = new Bitcoin.TransactionOut({
//             value: valueFromNumber(0.007),
//             script: o1s
//         });
// 
//         var tx = new Bitcoin.Transaction();
// 
//         tx.addOutput(to0);
//         tx.addOutput(to1);
// 
//         tin = new Bitcoin.TransactionIn({
//             outpoint: {
//                 hash: Bitcoin.Util.bytesToBase64(Bitcoin.Util.hexToBytes(intx).reverse()),
//                 index: 0
//             },
//             script: createOutScript(inaddr),
//             sequence: 4294967295
//         });
//         tx.addInput(tin);
// 
//         tx.signWithKey(in0.eckey)
// 
//         return tx;
//     }

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


	var getFulls = function(hashes) {
			$.get('https://bitcoin.toshi.io/api/v0/transactions/' + hashes[0] + '.hex')
			.done(function(data){
				fullInputTXHex[0] = data;
			})
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
// 				var scriptsToReplace = [];

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
                // add in the hooks to the + button here
                
                

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

                if (inamount > target) {
//                     var changeaddr = chains['change'].derive_child(usechange).eckey.getBitcoinAddress();
                    var changeaddr = chains['receive'].derive_child(0).eckey.getBitcoinAddress();
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
                    $("#preptxlabel").show()
                    
                    $("#submit_signed_transaction").attr('disabled', true);
                }
                $("#output_transaction").val(Bitcoin.Util.bytesToHex(tx.serialize()));
                var unsignedTransactionToBeCoded = Bitcoin.Util.bytesToHex(tx.serialize());
                var fullInputTXHex = [];
                var how_many_inputs = fullInputTXindex.length;
                var mCounter = 0;
                console.log("fullInputTXindex.length: " + how_many_inputs);

				$.each(fullInputTransactionHash, function(i, val){
					console.log("in each: " + i + " " + val);

					$.get('https://bitcoin.toshi.io/api/v0/transactions/' + val + '.hex')
						.done
						(
							function(data)
								{
									console.log("in each done: "  + data + " i:" + i);
									fullInputTXHex[i] = data;
									mCounter++;
									if(mCounter == how_many_inputs){prepForSigning(unsignedTransactionToBeCoded, fullInputTXHex, fullInputTXindex, address_handle_chain, address_handle_index)}
								}
						)
					} // end each function
				) // end each
 
  
 
                console.log("fullInputTXindex: " + fullInputTXindex);
                console.log("unsignedTransactionToBeCoded: " + unsignedTransactionToBeCoded);
				for(m=0; m < how_many_inputs; m++)
				{
                console.log("scripts to replace: " + scriptsToReplace[m]);
				}



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

        $('#generate_transaction').on('click', function() {
//         	document.getElementById('output_transaction').value = '';
//         	document.getElementById('device_signed_transaction').value = '';
//         	document.getElementById('ready_to_transmit').value = '';
        	genTransaction();
		});

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
 
        $('#feature').on('click', function() {
        var r = confirm("DESTROY DEVICE? THIS IS INSTANT & IRREVOCABLE!!!");
			if (r == true) {
				hidAskFeature();
// 				autoCannedTransactionMega(deviceCommands.raw_blink);
				console.log( "blink?" );
// 				hidWriteRawData(deviceCommands.raw_blink);
			} else {
				;
			}            
        });


        $('#initialize').on('click', function() {
            event.preventDefault();
            initialize_protobuf_encode();
        });

        $('#raw_input_button').on('click', function() {
            event.preventDefault();
            var toSendRaw = document.getElementById('raw_input').value;
            
            console.log("RAW: " + toSendRaw);
            autoCannedTransaction(toSendRaw);
        });

        $('#direct_load_wallet').on('click', function() {
            event.preventDefault();
            var walletToLoad = document.getElementById('direct_load_wallet_input').value;
            directLoadWallet(walletToLoad);
        });

        $('#ping').on('click', function() {
            constructPing();
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

        $('#txAddDest').click(txOnAddDest);
        $('#txRemoveDest').click(txOnRemoveDest);

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