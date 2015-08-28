/**
 * Created by ghost on 27/08/15.
 */
// TODO: video scanner,
// TODO: Converter to USD.
var wallets = angular.module('wallets', []);     //"checklist-model" 'ngSanitize'

wallets.controller('WalletsCtrl', function ($scope, $http) {
    $scope.tab =  1;
    $scope.qr ='';
    $scope.amount = 0;
    $scope.shQr = false;
    $scope.scan = false;


    var qrcode = new QRCode(document.getElementById("qrcode"), {
        width : 280,
        height : 280
    });

    function isNumeric(n) {
        return !isNaN(parseFloat(n)) && isFinite(n);
    }

    $scope.switchTab = function(el){ $scope.tab = el; };

    $scope.showQrPopUp = function(qr) {
        $scope.qr = qr;
        qrcode.clear();
        qrcode.makeCode(qr);
        $scope.shQr = true;
    };
    $scope.showScanPopUp = function(qr) {
        $scope.scan = true;

        $('#camplace').html5_qrcode(function(data) {
            console.log(data);
            $('#camplace').html5_qrcode_stop();
            $scope.raddrTo = data;
        },
        function(error){         //show read errors
            console.log(error);
        }, function(videoError){
            //the video stream could be opened
            console.log(videoError);
        });


    };

    $scope.closeQrPupUp = function() {
        $scope.shQr = false;
        $scope.scan = false;
        qrcode.clear();
        $('#camplace').html5_qrcode_stop();
    };

    $scope.calcUSD = function(e) {
        var inpt = e.target.value;
            if( isNumeric(inpt) ){
                $http.get('http://api.coindesk.com/v1/bpi/currentprice.json').
                    then(function(response) {
                        $scope.amount = (e.target.value * response.data.bpi.USD.rate).toFixed(2) + ' USD';
                    }, function(response) {
                        console.log('err',response);
                    });
            } else {
                $scope.amount ='';
            }
    };

});


