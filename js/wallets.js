/**
 * Created by ghost on 27/08/15.
 */
// TODO: video scanner,
// TODO: Converter to USD.
var wallets = angular.module('wallets', []);     //"checklist-model" 'ngSanitize'

wallets.controller('WalletsCtrl', function ($scope) {
    $scope.tab =  1;
    $scope.qr ='';
    $scope.amount = 0;
    $scope.shQr = false;

    var qrcode = new QRCode(document.getElementById("qrcode"), {
        width : 280,
        height : 280
    });

    $scope.switchTab = function(el){ $scope.tab = el; };

    $scope.showQrPopUp = function(qr) {
        $scope.qr = qr;

        qrcode.clear();
        qrcode.makeCode(qr);
        $scope.shQr = true;
    };

    $scope.closeQrPupUp = function() {
        $scope.shQr = false;
        qrcode.clear();
    }

    $scope.calcUSD = function() {
        alert($scope.amount);
    }

});


