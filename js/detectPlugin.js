/**
 * Created by ghost on 14/07/15.
 */
function pluginDetect() {
    if(typeof(navigator.plugins["hidapiBrowserPlugin"]) != "undefined" ){
        return true;
    } else {
        return false;
    }
}

if( pluginDetect() ){
    location.href="/indexOld.html"
} else {
    console.log('plugin not installed!');
}
