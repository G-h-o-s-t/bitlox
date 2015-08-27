/**
 * Created by ghost on 27/08/15.
 */
var wallets = angular.module('wallets', []);     //"checklist-model" 'ngSanitize'

wallets.controller('WalletsCtrl', function ($scope) {
    $scope.tab =  1;
    $scope.switchTab = function(el){ $scope.tab = el; };

});


