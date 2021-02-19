// Send response each 1 sec

setInterval(function(){ 
    let ajaxRequest = new XMLHttpRequest();
    
    ajaxRequest.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            var myArr = JSON.parse(this.responseText);
            //processJson(myArr[0]);
            processJson(myArr);
        }
    };

    ajaxRequest.open("GET", "http://localhost:8000/api/progressdata/", true);
    ajaxRequest.send();
}, 1000);

function processJson(myArr){
    for(let i=0 ; i<7 ; ++i){
        let stage = myArr[i].stage;
        change(stage, myArr[i].status);
        document.getElementById("stage" + stage).innerHTML = myArr[i].detail;
    }
}

function change(id, status){
    //reset();
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
