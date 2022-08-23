    function change() {
  
        var spans = document.getElementsByTagName('span');
        
        console.log(spans.length);
        for (var i=0;i<spans.length; i++) {
            console.log(spans);
            if (spans[i].innerText === "Active") {
                spans[i].className = "badge badge-light-success";
            } else if (spans[i].innerText === "Inactive") {
                spans[i].className = "badge badge-light-danger";
            }
        }
    }
    window.onload = change(); 
