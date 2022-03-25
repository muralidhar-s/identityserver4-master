$('#resendotpid').click(function() {
var counter = 0;
var timeleft = 30;
var totaltime = 0;

const button = document.getElementById('resendotpid');

function convertSeconds(sec)
{
    var min = floor(sec /  60);
    var seconds = sec % 60;
    return min + ':' + seconds; 
}

var interval = setInterval(timeIt, 1000);

function timeIt(){
    totaltime = timeleft - counter;
    button.style.display = "none";
    $("#timer").html('Resend Code in ' + totaltime + ' secs');

    if(totaltime == 0)
    {
        button.style.display = "block";
        $("#timer").html('');
    }

    if(counter == timeleft)
    {        
        clearInterval(interval);
    }    
    counter++;
    }
});

//     var  latitude;
//     var  longitude;
//     $.getJSON("http://ip-api.com/json",function(data){
//          latitude=data.lat
//          longitude=data.lon
//    var lati=parseFloat(latitude);
//    var long=parseFloat(longitude);
//     });
