function includeHTML() {

  console.log('call includeHTML');
  var z, i, elmnt, file, xhttp;
  z = document.getElementsByTagName("*");
  for (i = 0; i < z.length; i++) {
      elmnt = z[i];
      file = elmnt.getAttribute("data-include-path");
      if (file) {
          console.log('exist file');
          xhttp = new XMLHttpRequest();
          xhttp.onreadystatechange = function () {
              if (this.readyState == 4 && this.status == 200) {
                  console.log('good!');
                  elmnt.innerHTML = this.responseText;
                  elmnt.removeAttribute("data-include-path");
                  includeHTML();
              }
          }
          xhttp.open("GET", file, true);
          xhttp.send();
          return;
      }
  }
}