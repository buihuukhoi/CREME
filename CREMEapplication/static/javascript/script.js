// Send response each 1 sec

setInterval(function(){ 
    let ajaxRequest = new XMLHttpRequest();
    
    ajaxRequest.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            var myArr = JSON.parse(this.responseText);
            //processJson(myArr[0]);
            processJson(myArr[0]);
        }
    };

    my_domain = document.location.hostname;
    ajaxRequest.open("GET", "http://" + my_domain + ":8000/api/progressdata/", true);
    ajaxRequest.send();
}, 1000);

function processJson(data){
    document.getElementById("scenario").innerHTML = "Scenario: " + data.scenario;

    change("status1", data.stage_1_status);
    document.getElementById("detail1").innerHTML = data.stage_1_detail;

    document.getElementById("status2").innerHTML = data.attack_phase_1_data;
    change("status2", data.stage_2_status);
    document.getElementById("detail2").innerHTML = data.stage_2_detail;

    document.getElementById("status3").innerHTML = data.attack_phase_2_data;
    change("status3", data.stage_3_status);
    document.getElementById("detail3").innerHTML = data.stage_3_detail;

    document.getElementById("status4").innerHTML = data.attack_phase_3_data;
    change("status4", data.stage_4_status);
    document.getElementById("detail4").innerHTML = data.stage_4_detail;

    change("status5", data.stage_5_status);
    document.getElementById("detail5").innerHTML = data.stage_5_detail;

    change("status6", data.stage_6_status);
    document.getElementById("detail6").innerHTML = data.stage_6_detail;

    change("status7", data.stage_7_status);
    document.getElementById("detail7").innerHTML = data.stage_7_detail;
}

function change(id, status){
    e = document.getElementById(id);
    if(status <= '1'){
        e.classList.add("bg-dark");    
    }
    else if(status == '3'){
        e.classList.remove("bg-dark")
        e.classList.add("bg-success");
    }else{
        e.classList.remove("bg-dark");
        e.classList.remove("bg-success");
    }
}
