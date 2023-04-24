const app = angular.module('app');
const window = require('window');
const cdn = window.cdn || '';

var subapp = 'clash'; 
if((navigator.userAgent).indexOf('Android') > -1 || (navigator.userAgent).indexOf('Adr') > -1) { var subapp = 'surfboard'; } 
if(/(iPhone|iPad|iPod|iOS)/i.test(navigator.userAgent)){ var subapp = 'shadowrocket'; } 

app.factory('subscribeDialog', [ '$mdDialog', '$http', ($mdDialog, $http) => {
  const publicInfo = { linkType: subapp, ip: '0', flow: '0' };
  const hide = () => {
    return $mdDialog.hide()
    .then(success => {
      dialogPromise = null;
      return;
    }).catch(err => {
      dialogPromise = null;
      return;
    });
  };
  publicInfo.hide = hide;
  const getSubscribe = () => {
    return $http.get(`/api/user/account/${ publicInfo.accountId }/subscribe`);
  };
  publicInfo.getSubscribe = getSubscribe;
  const updateSubscribe = () => {
    return $http.put(`/api/user/account/${ publicInfo.accountId }/subscribe`);
  };
  publicInfo.updateSubscribe = updateSubscribe;
  let dialogPromise = null;
  const isDialogShow = () => {
    if(dialogPromise && !dialogPromise.$$state.status) {
      return true;
    }
    return false;
  };
  const dialog = {
    templateUrl: `${ cdn }/public/views/dialog/subscribe.html`,
    escapeToClose: false,
    locals: { bind: publicInfo },
    bindToController: true,
    controller: ['$scope', '$mdMedia', '$mdDialog', 'bind', 'configManager', '$mdToast', function($scope, $mdMedia, $mdDialog, bind, configManager, $mdToast) {
      $scope.publicInfo = bind;
	    
      if((navigator.userAgent).indexOf('Android') > -1 || (navigator.userAgent).indexOf('Adr') > -1) {
          $scope.publicInfo.types = [
          'surfboard','clash',
          ];  
      } else if(/(iPhone|iPad|iPod|iOS)/i.test(navigator.userAgent)){
          $scope.publicInfo.types = [
          'shadowrocket', 'clash',
          ];		  
      } else {
          $scope.publicInfo.types = [
          'clash', 'shadowrocket',
          ];
      }

      if(String(navigator.platform).toLowerCase().indexOf("linux") > -1) {
      	if((navigator.userAgent).indexOf('Android') > -1 || (navigator.userAgent).indexOf('Adr') > -1) {
      		$scope.os = 'android';
      	} else {
      		$scope.os = 'linux';	
      	} 		  
      }
	    
      const config = configManager.getConfig();
      $scope.changeLinkType = () => {
        $scope.publicInfo.subscribeLink = `${ config.site }/api/user/account/subscribe/${ $scope.publicInfo.token }?type=${ $scope.publicInfo.linkType }&ip=${ $scope.publicInfo.ip}&flow=${ $scope.publicInfo.flow}`;
      };
      $scope.publicInfo.getSubscribe().then(success => {
        $scope.publicInfo.token = success.data.subscribe;
        $scope.publicInfo.subscribeLink = `${ config.site }/api/user/account/subscribe/${ $scope.publicInfo.token }?type=${ $scope.publicInfo.linkType }&ip=${ $scope.publicInfo.ip}&flow=${ $scope.publicInfo.flow}`;
      });
      $scope.publicInfo.updateLink = () => {
        $scope.publicInfo.updateSubscribe().then(success => {
          $scope.publicInfo.token = success.data.subscribe;
          $scope.publicInfo.subscribeLink = `${ config.site }/api/user/account/subscribe/${ $scope.publicInfo.token }?type=${ $scope.publicInfo.linkType }&ip=${ $scope.publicInfo.ip}&flow=${ $scope.publicInfo.flow}`;
        });
      };
      $scope.toast = () => {
        $mdToast.show(
          $mdToast.simple()
            .textContent('链接已复制到剪贴板')
            .position('top right')
            .hideDelay(3000)
        );
      };
    }],
    fullscreen: false,
    clickOutsideToClose: true,
  };
  const show = accountId => {
    if(isDialogShow()) {
      return dialogPromise;
    }
    publicInfo.accountId = accountId;
    dialogPromise = $mdDialog.show(dialog);
    return dialogPromise;
  };
  return {
    show,
  };
}]);
